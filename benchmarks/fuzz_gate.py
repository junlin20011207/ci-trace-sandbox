"""Deterministic path/metadata mutation experiment: not independent vulnerability ground truth."""
import hashlib
import json
import random
import tempfile
import zipfile
from pathlib import Path
from ci_trace.provenance_guard import verify_and_extract, Denied

SEED=20261011
SUSPICIOUS=['../escape.json','./escape.json','/etc/escape.json','x/../escape.json',
            'x/./escape.json','x//escape.json','C:escape.json','folder\\escape.json',
            'trusted.js','.github/workflows/scripts/runner.py']
SAFE=['payload.json','report.txt','build/notes.json','deep/nested/value.json']

def run(n=500):
    rng=random.Random(SEED)
    records=[]
    with tempfile.TemporaryDirectory() as d:
        root=Path(d);ws=root/'workspace';ws.mkdir();out=root/'safe';out.mkdir()
        archive=root/'artifact.zip'
        for i in range(n):
            invalid=i%2==1
            name=rng.choice(SUSPICIOUS if invalid else SAFE)
            with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr(name,'low trust inert text')
            event={'repository':{'full_name':'org/repo'},'workflow_run':{
                'id':22,'event':'pull_request','conclusion':'success',
                'head_sha':'b'*40,'head_branch':'dependabot/safe',
                'head_repository':{'full_name':'org/repo'}}}
            api={'id':9,'name':'data','expired':False,
                 'workflow_run':{'id':22,'head_sha':'b'*40},
                 'digest':'sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest()}
            policy={'repository':'org/repo','expected_run_id':22,'artifact_name':'data',
                    'allowed_events':['pull_request'],'require_same_repo':True,
                    'branch_prefix':'dependabot/','allow_extensions':['.txt','.json']}
            invalid_metadata=(i%5==0)
            if invalid_metadata:api['workflow_run']['id']=99
            expected=not invalid and not invalid_metadata
            try:
                verify_and_extract(archive,event,api,policy,out,ws)
                approved=True
            except Denied:
                approved=False
            records.append((expected,approved))
    return {'seed':SEED,'cases':len(records),'expected_allow':sum(a for a,b in records),
            'expected_deny':sum(not a for a,b in records),
            'false_approvals':sum(not a and b for a,b in records),
            'false_denials':sum(a and not b for a,b in records)}

if __name__=='__main__':
    result=run()
    print(json.dumps(result,indent=2))
    assert result['false_approvals']==0 and result['false_denials']==0
