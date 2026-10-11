"""Small controlled runtime enforcement evaluation; no vulnerable third-party execution."""
import hashlib
import json
import stat
import tempfile
import zipfile
from pathlib import Path
from time import perf_counter
from ci_trace.provenance_guard import verify_and_extract, Denied

SHA='a'*40
CASES=[
 ('legitimate_pr_artifact','review.json','{}',None,True),
 ('helper_module_overlay','.github/workflows/scripts/helper.js','module.exports=()=>1',None,False),
 ('path_traversal','../../pr.json','{}',None,False),
 ('repo_branch_ref_forged','head-ref.txt','main','branch_from_artifact',True),
 ('unrecognized_source_run','review.json','{}','run_mismatch',False),
 ('digest_tampering','review.json','{}','wrong_digest',False),
 ('symlink_archive','helper.json','file','symlink',False),
 ('large_compression_ratio','review.json','A'*10000,None,False),
]

def evaluate():
    records=[]
    with tempfile.TemporaryDirectory() as d:
        root=Path(d)
        workspace=root/'workspace';workspace.mkdir()
        extraction=root/'isolate';extraction.mkdir()
        for num,(name,path,content,mutation,expected) in enumerate(CASES):
            archive=root/(f'{num}.zip')
            with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
                if mutation=='symlink':
                    info=zipfile.ZipInfo(path)
                    info.create_system=3
                    info.external_attr=(stat.S_IFLNK|0o777)<<16
                    z.writestr(info,content)
                else:z.writestr(path,content)
            event={'repository':{'full_name':'owner/repo'},'workflow_run':{
                'id':19,'event':'pull_request','head_sha':SHA,
                'head_branch':'dependabot/build','conclusion':'success',
                'head_repository':{'full_name':'owner/repo'}}}
            api={'id':123,'name':'data','expired':False,
                 'digest':'sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest(),
                 'workflow_run':{'id':19,'head_sha':SHA}}
            policy={'expected_run_id':19,'repository':'owner/repo','artifact_name':'data',
                    'allowed_events':['pull_request'],'require_same_repo':True,
                    'branch_prefix':'dependabot/','allow_extensions':['.json','.txt']}
            if mutation=='run_mismatch':api['workflow_run']['id']=20
            if mutation=='wrong_digest':api['digest']='sha256:'+'0'*64
            start=perf_counter()
            try:
                result=verify_and_extract(archive,event,api,policy,extraction,workspace)
                allowed=True
            except Denied as e:
                allowed=False;result={'reason':str(e)}
            records.append({'case':name,'expected_approved':expected,'approved':allowed,
                            'match':expected==allowed,'elapsed_ms':round((perf_counter()-start)*1000,3),
                            'branch_source':result.get('head_branch_from_event'),
                            'reason':result.get('reason')})
    return records

if __name__=='__main__':
    rows=evaluate()
    print(json.dumps({'kind':'controlled synthetic enforcement tests',
         'total':len(rows),'matches':sum(r['match'] for r in rows),'cases':rows},indent=2))
    assert all(r['match'] for r in rows)
