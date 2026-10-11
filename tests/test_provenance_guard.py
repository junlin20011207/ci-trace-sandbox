"""Independent adversarial suite for the runtime enforcement hypothesis."""
import hashlib
import json
import stat
import zipfile
from pathlib import Path
import pytest
from ci_trace.provenance_guard import Denied, verify_and_extract

SHA='a'*40


def _case_data(tmp_path):
    workspace=tmp_path/'workspace';workspace.mkdir()
    root=tmp_path/'staging';root.mkdir()
    zip_path=tmp_path/'artifact.zip'
    def create(members):
        with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED) as z:
            for name, value in members:z.writestr(name,value)
        return zip_path
    create([('review.json',b'{"pr_number":17}')])
    event={'repository':{'full_name':'example/demo'},'workflow_run':{
        'id':123,'event':'pull_request','head_sha':SHA,'head_branch':'dependabot/fix',
        'head_repository':{'full_name':'example/demo'},'conclusion':'success'}}
    policy={'expected_run_id':123,'repository':'example/demo','artifact_name':'review',
            'allowed_events':['pull_request'],'require_same_repo':True,'branch_prefix':'dependabot/',
            'allow_extensions':['.json','.txt']}
    art={'id':999,'name':'review','expired':False,'workflow_run':{'id':123,'head_sha':SHA},
         'digest':'sha256:'+hashlib.sha256(zip_path.read_bytes()).hexdigest()}
    def check():return verify_and_extract(zip_path,event,art,policy,root,workspace)
    return zip_path, create, event, art, policy, root, workspace, check


def test_valid_release(tmp_path):
    archive, _, event, api, policy, root, workspace, check=_case_data(tmp_path)
    got=check()
    assert got['status']=='approved' and got['run_id']==123
    assert json.loads((Path(got['release_dir'])/'review.json').read_text())=={'pr_number':17}
    assert not (workspace/'review.json').exists()
    assert Path(got['release_dir']).parent==root

@pytest.mark.parametrize('field,value,reason',[
 ('run','124','run_id_not_expected'), ('conclusion','failure','producer_not_successful'),
 ('event','push','source_event_denied'), ('head_repo','attacker/fork','foreign_head_repository'),
 ('branch','feature/sneaky','branch_not_authorized'),
 ('sha','f'*40,'artifact_head_mismatch'),
 ('art_run',124,'artifact_from_other_run'),('art_name','other','artifact_name_mismatch'),
 ('expired',True,'artifact_expired'),('digest','sha256:'+'0'*64,'artifact_digest_mismatch'),
 ('digest_missing',None,'missing_github_digest'),('repo','other/demo','consumer_repo_mismatch'),
])
def test_tampered_metadata(tmp_path,field,value,reason):
    archive,create,event,art,policy,root,workspace,check=_case_data(tmp_path)
    if field=='run':event['workflow_run']['id']=int(value)
    elif field=='conclusion':event['workflow_run']['conclusion']=value
    elif field=='event':event['workflow_run']['event']=value
    elif field=='head_repo':event['workflow_run']['head_repository']['full_name']=value
    elif field=='branch':event['workflow_run']['head_branch']=value
    elif field=='sha':art['workflow_run']['head_sha']=value
    elif field=='art_run':art['workflow_run']['id']=value
    elif field=='art_name':art['name']=value
    elif field=='expired':art['expired']=value
    elif field=='digest':art['digest']=value
    elif field=='digest_missing':del art['digest']
    elif field=='repo':event['repository']['full_name']=value
    with pytest.raises(Denied,match=reason):check()
    assert not list(root.iterdir())


def _archive_case(tmp_path,members,extensions=None,policy_extra=None):
    archive, create,event,art,policy,root,workspace,check=_case_data(tmp_path)
    create(members)
    art['digest']='sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest()
    if extensions is not None:policy['allow_extensions']=extensions
    if policy_extra:policy.update(policy_extra)
    return root,check

@pytest.mark.parametrize('name,value,reason',[
 ('../outside.json','bad','path_escape'),
 ('/etc/evil.json','bad','path_escape'),
 ('C:evil.json','bad','drive_path'),
 ('base/../../evil.json','bad','path_escape'),
 ('folder\\hack.json','bad','invalid_archive_path'),
 ('trusted.js','data','file_type_denied'),
])
def test_malicious_paths_or_types(tmp_path,name,value,reason):
    root,check=_archive_case(tmp_path,[(name,value)])
    with pytest.raises(Denied,match=reason):check()
    assert not list(root.iterdir())


def test_casefold_collision(tmp_path):
    root,check=_archive_case(tmp_path,[('Info.JSON','1'),('info.json','2')])
    with pytest.raises(Denied,match='duplicate_or_case_collision'):check()


def test_symlink_blocked(tmp_path):
    entry=zipfile.ZipInfo('pointer.json')
    entry.create_system=3
    entry.external_attr=(stat.S_IFLNK|0o777)<<16
    root,check=_archive_case(tmp_path,[(entry,'../../secrets.txt')])
    with pytest.raises(Denied,match='special_archive_entry|symlink_member'):check()


def test_enforced_data_only_blocks_module_overlay(tmp_path):
    root,check=_archive_case(tmp_path,[('.github/workflows/scripts/helper.js','exports.evil=1')])
    with pytest.raises(Denied,match='file_type_denied'):check()


def test_size_limit(tmp_path):
    root,check=_archive_case(tmp_path,[('info.json','A'*1000)],policy_extra={'max_uncompressed_bytes':500})
    with pytest.raises(Denied,match='uncompressed_limit_exceeded'):check()


def test_entry_limit(tmp_path):
    root,check=_archive_case(tmp_path,[(f'{i}.txt',str(i)) for i in range(5)],policy_extra={'max_entries':3})
    with pytest.raises(Denied,match='too_many_archive_entries'):check()


def test_zip_bomb_ratio(tmp_path):
    root,check=_archive_case(tmp_path,[('payload.txt','A'*7000)])
    with pytest.raises(Denied,match='compression_ratio_exceeded'):check()


def test_partial_extraction_cleanup(tmp_path):
    root,check=_archive_case(tmp_path,[('good.json','valid'),('good.json/more.json','impossible')])
    with pytest.raises(Denied,match='archive_unreadable_or_unsafe'):check()
    assert not list(root.iterdir())


def test_archive_oversize(tmp_path):
    root,check=_archive_case(tmp_path,[('payload.json','Hi')],policy_extra={'max_archive_bytes':20})
    with pytest.raises(Denied,match='archive_size_limit_exceeded'):check()


def test_no_workspace_overlap(tmp_path):
    a,c,event,art,p,root,ws,check=_case_data(tmp_path)
    with pytest.raises(Denied,match='extraction_root_overlaps_workspace'):
        verify_and_extract(a,event,art,p,ws,ws)


def test_untrusted_artifact_cannot_choose_branch(tmp_path):
    archive,create,event,api,policy,root,workspace,check=_case_data(tmp_path)
    create([('head-ref.txt','main'),('review.json','{}')])
    api['digest']='sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest()
    out=check()
    assert (Path(out['release_dir'])/'head-ref.txt').read_text()=='main'
    assert out['head_branch_from_event']=='dependabot/fix'


def test_deny_without_same_repo_when_required(tmp_path):
    a,c,event,art,p,root,ws,check=_case_data(tmp_path)
    event['workflow_run']['head_repository']['full_name']='fork/user'
    with pytest.raises(Denied,match='foreign_head_repository'):check()


def test_reject_corrupt_zip_despite_matching_digest(tmp_path):
    a,c,event,art,p,root,ws,check=_case_data(tmp_path)
    a.write_bytes(b'not a zip file')
    art['digest']='sha256:'+hashlib.sha256(a.read_bytes()).hexdigest()
    with pytest.raises(Denied,match='archive_unreadable_or_unsafe'):check()
