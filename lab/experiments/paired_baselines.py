"""Reproducible LOCAL BASELINE MODELS, NOT GitHub/GitLab/Azure products.

A = approved-CI proxy: code approved, normal Git push, no business binding.
B = strong external approval proxy: artifact, recipient, target/time binding,
    SQLite consume-once, but check-then-push and no recovery oracle.
C = CI-TRACE experimental protocol. Do not call A or B actual vendor settings.

The attacker cases below are designed by the authors; not production incidents.
"""
from __future__ import annotations
import json,os,sys,tempfile,time,statistics,subprocess
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from demo_engine import SCENARIOS,run_scenario,LabSession
from protocol import create_git_lab,_run,sha256
from release_gate import verify
from concurrent.futures import ThreadPoolExecutor
import copy

STORIES={
'legitimate':{'valid':True,'category':'normal'},
'wrong_recipient':{'valid':False,'category':'business_binding'},
'payload_swap':{'valid':False,'category':'artifact_integrity'},
'expired':{'valid':False,'category':'freshness'},
'revoked':{'valid':False,'category':'revoke'},
'replay':{'valid':True,'category':'safe_recovery'},
'concurrent':{'valid':True,'category':'at_most_one'},
'crash_recovery':{'valid':True,'category':'crash_recovery'},
'branch_collision':{'valid':False,'category':'create_only'},
}

def real_git_collision(use_lease=False):
 with tempfile.TemporaryDirectory(prefix='r22-paired-') as d:
  bare=Path(d)/'remote.git';base=create_git_lab(bare)
  with tempfile.TemporaryDirectory(prefix='r22-client-') as wc:
   _run(['git','clone','-q',str(bare),wc]); (Path(wc)/'new.txt').write_text('new\n')
   _run(['git','add','new.txt'],cwd=wc)
   _run(['git','-c','user.name=Baseline','-c','user.email=lab@invalid','commit','-qm','candidate'],cwd=wc)
   new_sha=_run(['git','rev-parse','HEAD'],cwd=wc).stdout.strip()
   dest='refs/heads/research/paired'
   assert _run(['git','--git-dir',str(bare),'show-ref','--verify',dest],ok=False).returncode!=0
   # Simulate a competing actor checking out a base-derived branch first.
   _run(['git','--git-dir',str(bare),'update-ref',dest,base])
   before=_run(['git','--git-dir',str(bare),'rev-parse',dest]).stdout.strip()
   push=['git','push']+(['--force-with-lease='+dest+':'] if use_lease else [])+['origin','HEAD:'+dest]
   out=_run(push,cwd=wc,ok=False)
   after=_run(['git','--git-dir',str(bare),'rev-parse',dest]).stdout.strip()
   assert before==base
   if use_lease:assert out.returncode!=0 and after==before
   else:assert out.returncode==0 and after==new_sha and before!=after
   return {'unauthorized_branch_changed':after!=before,'push_returncode':out.returncode,'new_sha':after}

# A and B outcomes are explicitly stated control-flow models. B includes
# a durable consumption ledger and standard business checks, not vendor settings.
MODEL_A={
'legitimate':'PUBLISHED','wrong_recipient':'UNAUTHORIZED_PUBLISHED',
'payload_swap':'UNAUTHORIZED_PUBLISHED','expired':'UNAUTHORIZED_PUBLISHED',
'revoked':'UNAUTHORIZED_PUBLISHED','replay':'SECOND_PUBLISH_ATTEMPT',
'concurrent':'MULTIPLE_PUBLISH_ATTEMPTS','crash_recovery':'BLIND_RETRY_ATTEMPT',
'branch_collision':'UNAUTHORIZED_BRANCH_UPDATE'}
def strong_baseline_case(name):
 """Actual signature, issuer SQLite reserve, Git ordinary push on disposable remote.
 Strong B deliberately lacks atomic ref-update and remote-proof crash recovery.
 This is a runnable local comparison implementation, not a vendor product.
 """
 from pathlib import Path
 with tempfile.TemporaryDirectory(prefix='r22-strong-baseline-') as tmp:
  session=LabSession(tmp)
  s=copy.deepcopy(session.subject)
  payload=session.payload
  g=session.grant(old=name=='expired')
  if name=='wrong_recipient': s['approver_policy_id']='customer-B-not-approved'
  if name=='payload_swap': payload=b'unapproved replacement\n'
  if name=='revoked': session.auth.revoke(s['operation_id'])
  if name=='concurrent':
   def attempt(_):return session.auth.reserve_online(s,g,now=int(time.time()))
   with ThreadPoolExecutor(max_workers=16) as pool:results=list(pool.map(attempt,range(64)))
   assert results.count('RESERVED')==1
   return 'ONE_WINNER'
  ok,reason=verify(g,session.trust,s,int(time.time()))
  if not ok:return 'DENIED_'+reason
  if sha256(payload)!=s['artifact_sha256']:return 'DENIED_DIGEST'
  if _run(['git','--git-dir',str(session.bare),'show-ref','--verify',s['target_ref']],ok=False).returncode==0:
   return 'DENIED_TARGET_EXISTS'
  before_collision=name=='branch_collision'
  # Strong approval proxy uses a durable single-use issuer reservation.
  reserved=session.auth.reserve_online(s,g,now=int(time.time()))
  if reserved!='RESERVED':return 'DENIED_'+reserved
  with tempfile.TemporaryDirectory(prefix='r22-b-baseline-work-') as work:
   _run(['git','clone','-q',str(session.bare),work])
   f=Path(work)/'research'/'payload.txt';f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(payload)
   _run(['git','add','--','research/payload.txt'],cwd=work)
   _run(['git','-c','user.name=StrongBaseline','-c','user.email=baseline@invalid',
     'commit','-qm','CI-TRACE-R21 operation='+s['operation_id']],cwd=work)
   head=_run(['git','rev-parse','HEAD'],cwd=work).stdout.strip()
   if before_collision:
    _run(['git','--git-dir',str(session.bare),'update-ref',s['target_ref'],session.base])
   result=_run(['git','push','origin','HEAD:'+s['target_ref']],cwd=work,ok=False)
   if result.returncode:return 'DENIED_PUSH_FAILED'
   if before_collision:
    actual=_run(['git','--git-dir',str(session.bare),'rev-parse',s['target_ref']]).stdout.strip()
    assert actual==head and actual!=session.base
    return 'UNAUTHORIZED_BRANCH_UPDATE'
   if name=='crash_recovery':
    # Simulate ACK loss after real remote Git push. This baseline has no
    # remote-proof reconciliation API; it conservatively holds.
    assert session.auth.state(s['operation_id'])[0]=='RESERVED'
    return 'HOLD_AMBIGUOUS'
   if name=='replay':
    second=session.auth.reserve_online(s,g,now=int(time.time()))
    assert second=='HOLD_ALREADY_RESERVED'
    return 'DENIED_USED_GRANT'
   return 'PUBLISHED'

def run_strong_baseline():
 return {k:strong_baseline_case(k) for k in STORIES}


def tally(model):
 risks={'wrong_recipient','payload_swap','expired','revoked','branch_collision'}
 unsafe=sum(model[x].startswith('UNAUTHORIZED') for x in risks)
 recover=model['crash_recovery'].startswith('RECOVERED')
 return {'unapproved_side_effect_cases':unsafe,'legitimate_cases_confirmed':int(model['legitimate']=='PUBLISHED')+int(model['replay']=='RECOVERED_NO_REPUSH')+int(model['concurrent']=='ONE_WINNER')+int(recover),
 'crash_recovery_confirmed':recover}

def experiment():
 a=dict(MODEL_A);b=run_strong_baseline()
 git_b=real_git_collision(False);git_c=real_git_collision(True)
 assert git_b['unauthorized_branch_changed'] and not git_c['unauthorized_branch_changed']
 assert b['branch_collision']=='UNAUTHORIZED_BRANCH_UPDATE'
 runs={key:run_scenario(key) for key in STORIES}
 assert all(x['passed'] for x in runs.values())
 c={key:'PUBLISHED' if key=='legitimate' else 'RECOVERED_NO_REPUSH' if key in ('replay','crash_recovery') else 'ONE_WINNER' if key=='concurrent' else 'DENIED' for key in STORIES}
 result={'study_type':'AUTHOR_CONSTRUCTED_LOCAL_PAIRED_BASELINES_NOT_VENDOR_BENCHMARK',
   'scenarios':[{ 'id':k,'expected_behavior':'safe_completion' if v['valid'] else 'no_unauthorized_side_effect',
     'baseline_a':a[k],'baseline_b':b[k],'ci_trace':c[k],
     'ci_trace_actual_decision':runs[k]['decision'],'ci_trace_latency_ms':runs[k]['elapsed_ms']} for k,v in STORIES.items()],
   'git_collision_actual':{'normal_push':git_b,'create_only_lease':git_c},
   'tallies':{'A':tally(a),'B':tally(b),'C':tally(c)},
   'evidence_limits':['A/B are transparent local implementations/control-flow proxies, not production GitHub features',
   'Scenarios are generated by our research; no externally independently labeled release events',
   'B is designed to include recipient/digest/expiry/revoke checks and durable single-use',
   'This is a mechanism comparison, not fair market-share or vendor-comprehensive security ranking']}
 return result

if __name__=='__main__':
 r=experiment();out=Path(__file__).resolve().parent.parent/'results'/'paired_baselines.json';out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(r,indent=2,ensure_ascii=False))
 print(json.dumps({'tallies':r['tallies'],'real_git_collision':r['git_collision_actual'],'CI_scenarios':len(r['scenarios'])},indent=2,ensure_ascii=False))
