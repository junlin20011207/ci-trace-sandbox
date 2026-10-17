"""Measured end-to-end local scenario latency, not network or production latency."""
import json,statistics,time,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from demo_engine import run_scenario,SCENARIOS

def run(n=10):
 dataset={}
 for k in SCENARIOS:
  observations=[]
  for _ in range(n):
   x=run_scenario(k)
   if not x['passed']:raise RuntimeError(k+' failed')
   observations.append(x['elapsed_ms'])
  dataset[k]={'n':n,'p50_ms':round(statistics.median(observations),2),
              'p95_ms':round(sorted(observations)[min(n-1,int(.95*n))],2),
              'mean_ms':round(statistics.mean(observations),2),
              'raw_ms':observations}
 return {'scope':'Same-host local bare Git, Linux filesystem, Python process and SQLite; NOT GitHub/Gitee network latency',
         'hardware':'sandbox; variable shared compute','samples':dataset}
if __name__=='__main__':
 r=run();p=Path(__file__).resolve().parent.parent/'results'/'latency.json';p.write_text(json.dumps(r,indent=2,ensure_ascii=False));
 print(json.dumps({k:{w:x[w] for w in ('n','p50_ms','p95_ms')} for k,x in r['samples'].items()},indent=2))
