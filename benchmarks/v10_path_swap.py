"""Controlled V9/V10 ZIP-path replacement experiment, not exploit prevalence."""
import argparse
import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch
from ci_trace.provenance_guard import verify_and_extract as v9, Denied
from ci_trace.snapshot_guard_v10 import verify_and_extract_snapshot as v10

SHA='a'*40

def one(version,index,attack):
    with tempfile.TemporaryDirectory(prefix='v10-replay-') as temp:
        root=Path(temp);ws=root/'ws';ws.mkdir();release=root/'release';release.mkdir()
        archive=root/'input.zip';evil=root/'alternate.zip'
        payload=str(index)
        for path,value in [(archive,'AUTHORIZED:'+payload),(evil,'REPLACED__:'+payload)]:
            with zipfile.ZipFile(path,'w') as z:z.writestr('data.json',json.dumps({'data':value}))
        digest=hashlib.sha256(archive.read_bytes()).hexdigest()
        event={'repository':{'full_name':'demo/test'},'workflow_run':{
              'id':1,'event':'pull_request','conclusion':'success','head_sha':SHA,
              'head_repository':{'full_name':'demo/test'}}}
        api={'id':9,'name':'data','expired':False,'digest':'sha256:'+digest,
             'workflow_run':{'id':1,'head_sha':SHA}}
        policy={'expected_run_id':1,'repository':'demo/test','artifact_name':'data',
                'allowed_events':['pull_request'],'require_same_repo':True,
                'allow_extensions':['.json']}
        if attack=='before':os.replace(evil,archive)
        original=zipfile.ZipFile
        swapped=[]
        def hook(file,*args,**kwargs):
            if attack=='between' and not swapped:
                os.replace(evil,archive);swapped.append(True)
            return original(file,*args,**kwargs)
        try:
            with patch.object(zipfile,'ZipFile',new=hook):
                output=version(archive,event,api,policy,release,ws)
            returned=json.loads((Path(output['release_dir'])/'data.json').read_text())['data']
            return 'wrong_content' if returned!='AUTHORIZED:'+payload else 'correct_content'
        except Denied:
            return 'denied'

def experiment(trials=40):
    assert trials>0
    rows=[]
    for label,attack in [('path_swap_between_check_and_use','between'),
                         ('no_mutation','none'),('tamper_before_check','before')]:
        before=[one(v9,i,attack) for i in range(trials)]
        after=[one(v10,i,attack) for i in range(trials)]
        rows.append({'scenario':label,'trials':trials,
                     'v9':{n:before.count(n) for n in ('correct_content','wrong_content','denied')},
                     'v10':{n:after.count(n) for n in ('correct_content','wrong_content','denied')}})
    return {'experiment':'deterministic archive pathname replacement',
            'ground_truth':'synthetic author-constructed inert JSON, not real exploit incidence',
            'records':rows}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--trials',type=int,default=40)
    a=p.parse_args()
    r=experiment(a.trials)
    print(json.dumps(r,indent=2))
    swap,normal,tamper=r['records']
    assert swap['v9']['wrong_content']==a.trials
    assert swap['v10']['wrong_content']==0
    assert swap['v10']['correct_content']==a.trials
    assert normal['v10']['correct_content']==a.trials
    assert tamper['v10']['denied']==a.trials

if __name__=='__main__':main()
