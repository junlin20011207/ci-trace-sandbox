"""Reproducible SHA authorization counterfactuals; synthetic, not vulnerability prevalence."""
import argparse
import hashlib
import json
import random
import tempfile
import zipfile
from pathlib import Path
from ci_trace.provenance_guard import verify_and_extract, Denied
from ci_trace.authorization_binding import verify_authorized_release

SEED=20261011

def experiment(count=400):
    rng=random.Random(SEED)
    rows=[]
    with tempfile.TemporaryDirectory(prefix='ci-trace-revision-') as d:
        root=Path(d);ws=root/'ws';ws.mkdir();out=root/'out';out.mkdir()
        archive=root/'inert.zip'
        with zipfile.ZipFile(archive,'w') as z:z.writestr('report.json','{"inert":true}')
        digest='sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest()
        for i in range(count):
            scenario=i%4
            changed=scenario!=0
            same_second=scenario in (0,1,2)
            approved='a'*40
            actual=approved if not changed else format(rng.getrandbits(160),'040x')
            if changed and actual==approved:actual='b'*40
            event={'repository':{'full_name':'example/demo'},'workflow_run':{
                'id':42,'event':'pull_request','conclusion':'success',
                'head_sha':actual,'head_branch':'dependabot/fix',
                'head_repository':{'full_name':'example/demo'}}}
            art={'id':77,'name':'bundle','expired':False,'digest':digest,
                 'workflow_run':{'id':42,'head_sha':actual}}
            policy={'repository':'example/demo','expected_run_id':42,
                    'artifact_name':'bundle','allowed_events':['pull_request'],
                    'require_same_repo':True,'allow_extensions':['.json']}
            approval={'repository':'example/demo','run_id':42,'artifact_name':'bundle','commit_sha':approved}
            def allow(fn):
                try:
                    r=fn()
                    rd=Path(r['release_dir'])
                    (rd/'report.json').unlink();rd.rmdir()
                    return True
                except Denied:return False
            old=allow(lambda: verify_and_extract(archive,event,art,policy,out,ws))
            new=allow(lambda: verify_authorized_release(archive,event,art,policy,approval,out,ws))
            timestamp_allows=same_second # old strictly-greater-than timestamp check
            rows.append((changed,old,new,timestamp_allows,same_second))
    return {
      'design':'author-labeled SHA mutations; independent approval source ASSUMED trusted',
      'seed':SEED,'cases':count,
      'unchanged':sum(not x[0] for x in rows),
      'changed':sum(x[0] for x in rows),
      'v8_accepted_changed':sum(x[0] and x[1] for x in rows),
      'v9_accepted_changed':sum(x[0] and x[2] for x in rows),
      'v9_denied_unchanged':sum(not x[0] and not x[2] for x in rows),
      'same_second_timestamp_accepted_changed':sum(x[0] and x[3] and x[4] for x in rows)
    }

def main():
    p=argparse.ArgumentParser();p.add_argument('--cases',type=int,default=400)
    a=p.parse_args();result=experiment(a.cases)
    print(json.dumps(result,indent=2))
    assert result['v9_accepted_changed']==0 and result['v9_denied_unchanged']==0

if __name__=='__main__':main()
