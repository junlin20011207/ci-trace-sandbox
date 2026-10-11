"""V9/V10 isolated artifact byte-release latency, not throughput/SLO proof."""
import hashlib
import json
import os
import shutil
import statistics
import tempfile
import time
import zipfile
from pathlib import Path
from ci_trace.provenance_guard import verify_and_extract as v9
from ci_trace.snapshot_guard_v10 import verify_and_extract_snapshot as v10

def measure(size=1048576,repeat=10):
    with tempfile.TemporaryDirectory(prefix='ci-trace-cost-') as d:
        root=Path(d);ws=root/'ws';ws.mkdir();out=root/'output';out.mkdir()
        arc=root/'archive.zip'
        with zipfile.ZipFile(arc,'w',zipfile.ZIP_STORED) as z:
            z.writestr('data.bin',os.urandom(size))
        digest=hashlib.sha256(arc.read_bytes()).hexdigest()
        sha='a'*40
        event={'repository':{'full_name':'owner/demo'},'workflow_run':{
                'id':1,'event':'pull_request','conclusion':'success',
                'head_sha':sha,'head_repository':{'full_name':'owner/demo'}}}
        art={'id':2,'name':'data','expired':False,'digest':'sha256:'+digest,
             'workflow_run':{'id':1,'head_sha':sha}}
        policy={'expected_run_id':1,'repository':'owner/demo','artifact_name':'data',
                'allowed_events':['pull_request'],'allow_extensions':['.bin'],
                'require_same_repo':True,'max_uncompressed_bytes':size+1024}
        results={}
        for key,fn in [('v9',v9),('v10',v10)]:
            timings=[]
            for _ in range(repeat):
                t=time.perf_counter()
                result=fn(arc,event,art,policy,out,ws)
                assert (Path(result['release_dir'])/'data.bin').stat().st_size==size
                timings.append((time.perf_counter()-t)*1000)
                shutil.rmtree(result['release_dir'])
            results[key]={'median_ms':round(statistics.median(timings),3),
                          'min_ms':round(min(timings),3),
                          'max_ms':round(max(timings),3)}
        return {'bytes':size,'trials_per_version':repeat,**results}

if __name__=='__main__':
    print(json.dumps({'design':'single runner microbenchmark; no production SLO',
        'cases':[measure(4096,10),measure(262144,10),measure(1048576,10)]},
        indent=2))
