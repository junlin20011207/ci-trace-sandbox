"""B vs C local total wall time (including temporary repository initialization).
Both are reference designs, never real commercial vendor benchmark.
Feature set and final proof guarantee differ; latency is not an apples-to-apples
same-security metric and does not include remote network RTT or human review.
"""
import json,statistics,sys
from pathlib import Path
from time import perf_counter
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from demo_engine import run_scenario
from experiments.paired_baselines import strong_baseline_case
N=10
result={}
for name in ('legitimate','wrong_recipient','payload_swap','expired','revoked','replay','concurrent','crash_recovery','branch_collision'):
 b=[];c=[]
 for i in range(N):
  t=perf_counter();strong_baseline_case(name);b.append(round(1000*(perf_counter()-t),2))
  t=perf_counter();out=run_scenario(name);c.append(round(1000*(perf_counter()-t),2))
  assert out['passed']
 result[name]={
  'B_p50_ms':round(statistics.median(b),2),'C_p50_ms':round(statistics.median(c),2),
  'B_p95_ms':sorted(b)[-1],'C_p95_ms':sorted(c)[-1],
  'B_raw_ms':b,'C_raw_ms':c}
report={'n_per_case':N,'timing_scope':'total locally constructed scenario, includes per-run ephemeral repo creation, signing, DB and Git; no network or human approval',
 'not_security_equivalent':True,'comparison_caveat':'B normal path omits remote-proof ACK and cannot auto reconcile crash; C validates resulting remote commit. Delays include unequal safety checks.', 'scenarios':result}
(Path(__file__).resolve().parent.parent/'results'/'baseline_b_latency.json').write_text(json.dumps(report,indent=2))
print(json.dumps({k:{x:v[x] for x in ('B_p50_ms','C_p50_ms','B_p95_ms','C_p95_ms')} for k,v in result.items()},indent=2))
