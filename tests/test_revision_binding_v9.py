"""V9 trusted revision authorization tests: inert archives only."""
import hashlib
import zipfile
from pathlib import Path
import pytest
from ci_trace.authorization_binding import (
    Denied, verify_authorized_release, require_authorized_revision
)
GOOD='a'*40
OTHER='b'*40

def setup(tmp_path):
    ws=tmp_path/'checkout';ws.mkdir()
    out=tmp_path/'isolate';out.mkdir()
    archive=tmp_path/'artifact.zip'
    with zipfile.ZipFile(archive,'w') as f:f.writestr('report.json','{"inert":true}')
    event={'repository':{'full_name':'example/demo'},'workflow_run':{
      'id':42,'event':'pull_request','conclusion':'success','head_sha':GOOD,
      'head_branch':'dependabot/example','head_repository':{'full_name':'example/demo'}}}
    art={'id':77,'name':'bundle','expired':False,
      'workflow_run':{'id':42,'head_sha':GOOD},
      'digest':'sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest()}
    policy={'repository':'example/demo','expected_run_id':42,'artifact_name':'bundle',
      'allowed_events':['pull_request'],'require_same_repo':True,'allow_extensions':['.json']}
    approval={'repository':'example/demo','run_id':42,'artifact_name':'bundle','commit_sha':GOOD}
    return archive,event,art,policy,approval,out,ws

def test_authorized_release_preserves_isolation(tmp_path):
    z,e,a,p,auth,out,ws=setup(tmp_path)
    r=verify_authorized_release(z,e,a,p,auth,out,ws)
    assert r['status']=='approved'
    assert r['authorization_status']=='exact_revision_bound'
    assert r['approval_binding']['authorized_commit_sha']==GOOD
    assert not r['safe_to_execute_or_publish']
    assert (Path(r['release_dir'])/'report.json').is_file()
    assert not (ws/'report.json').exists()

@pytest.mark.parametrize('kind,reason',[
 ('missing','missing_trusted_authorization'),
 ('incomplete','incomplete_authorization_binding'),
 ('bad_sha','invalid_authorized_sha'),
 ('upper_sha','unauthorized_sha_not_canonical'),
 ('repo','authorization_repository_mismatch'),
 ('run','authorization_run_id_mismatch'),
 ('bool_run','authorization_run_id_invalid'),
 ('name','authorization_artifact_name_mismatch'),
 ('sha_moved','approved_commit_changed'),
 ('artifact_sha','artifact_not_from_approved_commit'),
 ('artifact_run','artifact_not_from_approved_commit'),
])
def test_denial_on_bound_subject_change(tmp_path,kind,reason):
    z,e,a,p,auth,out,ws=setup(tmp_path)
    if kind=='missing':auth=None
    elif kind=='incomplete':del auth['commit_sha']
    elif kind=='bad_sha':auth['commit_sha']='invalid'
    elif kind=='upper_sha':auth['commit_sha']='A'*40
    elif kind=='repo':auth['repository']='other/thing'
    elif kind=='run':auth['run_id']=43
    elif kind=='bool_run':auth['run_id']=True
    elif kind=='name':auth['artifact_name']='unrelated'
    elif kind=='sha_moved':
        e['workflow_run']['head_sha']=OTHER
        a['workflow_run']['head_sha']=OTHER
    elif kind=='artifact_sha':a['workflow_run']['head_sha']=OTHER
    elif kind=='artifact_run':a['workflow_run']['id']=43
    with pytest.raises(Denied,match=reason):
        verify_authorized_release(z,e,a,p,auth,out,ws)
    assert not list(out.iterdir())

def test_same_second_timestamp_does_not_bind_commit(tmp_path):
    z,e,a,p,auth,out,ws=setup(tmp_path)
    authorizes_at=1800000000
    changed_at=authorizes_at
    assert not (changed_at>authorizes_at) # published vulnerable greater-than check
    e['workflow_run']['head_sha']=OTHER
    a['workflow_run']['head_sha']=OTHER
    with pytest.raises(Denied,match='approved_commit_changed'):
        verify_authorized_release(z,e,a,p,auth,out,ws)

def test_approval_is_not_accepted_from_artifact_data(tmp_path):
    z,e,a,p,auth,out,ws=setup(tmp_path)
    with zipfile.ZipFile(z,'w') as f:
        f.writestr('approval.json','{"commit_sha":"'+OTHER+'"}')
    a['digest']='sha256:'+hashlib.sha256(z.read_bytes()).hexdigest()
    e['workflow_run']['head_sha']=OTHER
    a['workflow_run']['head_sha']=OTHER
    with pytest.raises(Denied,match='approved_commit_changed'):
        verify_authorized_release(z,e,a,p,auth,out,ws)

def test_digest_tamper_still_blocks_after_commit_authorization(tmp_path):
    z,e,a,p,auth,out,ws=setup(tmp_path)
    z.write_bytes(z.read_bytes()+b'tamper')
    with pytest.raises(Denied,match='artifact_digest_mismatch'):
        verify_authorized_release(z,e,a,p,auth,out,ws)

def test_overlay_js_still_blocked_after_authorization(tmp_path):
    z,e,a,p,auth,out,ws=setup(tmp_path)
    with zipfile.ZipFile(z,'w') as f:
        f.writestr('.github/workflows/scripts/helper.js','inert')
    a['digest']='sha256:'+hashlib.sha256(z.read_bytes()).hexdigest()
    with pytest.raises(Denied,match='file_type_denied'):
        verify_authorized_release(z,e,a,p,auth,out,ws)

def test_original_marimo_toctou_source_snapshot():
    from pathlib import Path
    import re
    snapshot=(Path(__file__).resolve().parents[1]/'research_corpus/marimo_bot_toctou_vuln.yml').read_text()
    assert 'pushed_at' in snapshot and 'COMMENT_AT' in snapshot
    assert re.search(r'-gt\s+\$\(date\s+-d',snapshot) or ' -gt ' in snapshot
    assert 'head_sha' in snapshot
