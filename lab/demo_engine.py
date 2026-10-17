"""CI-TRACE end-to-end laboratory engine.

DO NOT use this engine as a real authority. The app owns its own ephemeral test
signing key and local Git remote; a production publisher requires an externally
administered credential, policy/issuer, protected destination, and trusted code.
"""
from __future__ import annotations
import copy,hashlib,json,os,subprocess,sys,tempfile,time,uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from protocol import Authority,CreateOnlyPublisher,create_git_lab,public_hex,sha256,_run

SCENARIOS={
 'legitimate':'授权与发布完全一致，核验真实 Git 引用',
 'wrong_recipient':'批准给客户 A 的操作被替换为客户 B',
 'payload_swap':'已批准的制品被替换成其他内容',
 'expired':'授权有效期已经结束',
 'revoked':'授权在预留之前被撤销',
 'replay':'同一个批准在发布后再次请求执行',
 'concurrent':'64 个执行进程竞争同一授权',
 'crash_recovery':'Git 更新成功后进程退出，恢复时只读核验',
 'branch_collision':'批准检查后目标分支被其他人抢先创建',
}

class LabSession:
 def __init__(self, path):
  self.root=Path(path);self.root.mkdir(parents=True,exist_ok=True)
  self.bare=self.root/'remote.git';self.base=create_git_lab(self.bare)
  self.key=Ed25519PrivateKey.generate()
  self.db=self.root/'authority.sqlite'
  self.clock=lambda:int(time.time())
  self.auth=Authority(self.db,self.key,remote_bare=self.bare,clock=self.clock)
  self.payload=b'CI-TRACE approved customer A release v2.0\n'
  self.subject={
   'repository_id':'1414105644','repository':'junlin20011207/ci-trace-sandbox',
   'source_sha':'c'*40,'source_workflow_ref':'junlin20011207/ci-trace-sandbox/.github/workflows/candidate.yml@refs/heads/research/demo',
   'artifact_sha256':sha256(self.payload),'gitee_repo':'https://gitee.com/liljunlin/test.git',
   'target_ref':'refs/heads/research/ci-trace-demo-'+uuid.uuid4().hex[:12],
   'target_base_sha':self.base,'operation_id':'release-'+uuid.uuid4().hex[:16],
   'approver_policy_id':'LAB-DEMO-ONLY'}
  self.trust={'schema_version':1,'issuers':{'LAB-R21':public_hex(self.key)},
             'policy_revision':21,'revoked_grants':[], 'max_ttl_seconds':120,'max_clock_skew_seconds':10}
  self.publisher=CreateOnlyPublisher(self.bare,self.trust)
  self.timeline=[]
 def event(self,step,details):self.timeline.append({'step':step,'details':details})
 def grant(self,old=False):
  self.auth.approve_subject(self.subject);self.event('ADMIN_APPROVE','实验管理员预批准指定客户、制品摘要和 Git 引用')
  now=int(time.time())
  g,reason=self.auth.issue(self.subject,now=now-180 if old else now,ttl=90)
  self.event('ISSUE',reason+'，Ed25519 临时实验私钥签发')
  return g
 def execute(self,scenario):
  if scenario not in SCENARIOS:raise ValueError('unknown laboratory scenario')
  start=time.perf_counter();g=self.grant(old=scenario=='expired')
  s=copy.deepcopy(self.subject);payload=self.payload
  if scenario=='wrong_recipient':
   s['approver_policy_id']='customer-B-not-approved';self.event('ATTACK','调换批准客户/策略主体')
  elif scenario=='payload_swap':
   payload=b'malicious replacement\n';self.event('ATTACK','替换已授权制品内容')
  elif scenario=='revoked':
   result=self.auth.revoke(s['operation_id']);self.event('REVOKE',result)
  elif scenario=='concurrent':
   self.event('ATTACK','64 个执行请求试图同时占用授权')
   def take(_):return self.auth.reserve_online(s,g,now=int(time.time()))
   with ThreadPoolExecutor(max_workers=16) as pool:outcomes=list(pool.map(take,range(64)))
   accepted=outcomes.count('RESERVED')
   self.event('RESERVATION',f'成功 {accepted}/64，其余 {64-accepted} 次被拒绝')
   return self.result(scenario,accepted==1,'ONE_WINNER',start,{'winners':accepted,'losers':64-accepted})
  elif scenario=='branch_collision':
   _run(['git','--git-dir',str(self.bare),'update-ref',s['target_ref'],self.base]);self.event('ATTACK','其他进程提前创建目标研究分支')
  if scenario=='crash_recovery':
   program='''import json,os,sys;sys.path.insert(0,sys.argv[1]);from protocol import Authority,CreateOnlyPublisher;p=CreateOnlyPublisher(sys.argv[2],json.loads(sys.argv[3]));a=Authority(sys.argv[4],None,remote_bare=sys.argv[2]);p.publish(a,json.loads(sys.argv[5]),json.loads(sys.argv[6]),bytes.fromhex(sys.argv[7]),now=int(sys.argv[8]),crash_after_push=True)'''
   cmd=[sys.executable,'-c',program,str(Path(__file__).resolve().parent),str(self.bare),json.dumps(self.trust),str(self.db),json.dumps(g),json.dumps(s),payload.hex(),str(int(time.time()))]
   child=subprocess.run(cmd,capture_output=True,text=True,timeout=25)
   self.event('FAILURE',f'子进程在 Git push 成功后被故障注入终止，exit={child.returncode}')
   assert child.returncode==91,child.stderr
   outcome,proof=self.publisher.publish(self.auth,g,s,payload,now=int(time.time()))
   self.event('RECOVERY',outcome+'；从远端 Git 对象核验后完成账本确认')
  else:
   outcome,proof=self.publisher.publish(self.auth,g,s,payload,now=int(time.time()))
   self.event('PUBLISH',outcome)
   if scenario=='replay':
    again,_=self.publisher.publish(self.auth,g,s,payload,now=int(time.time()))
    self.event('REPLAY',again+'，没有第二次远端更新')
  expected={'legitimate':True,'wrong_recipient':False,'payload_swap':False,'expired':False,
            'revoked':False,'replay':True,'crash_recovery':True,'branch_collision':False}
  successful=(outcome=='ACK_PUBLISHED' if scenario=='legitimate' else
     outcome.startswith('HOLD_') if scenario in ('wrong_recipient','payload_swap','expired','revoked','branch_collision') else
     outcome=='ACK_PUBLISHED' and again=='RECOVERED_ACK_IDEMPOTENT' if scenario=='replay' else
     outcome=='RECOVERED_ACK_PUBLISHED')
  return self.result(scenario,successful,outcome,start,proof)
 def result(self,scenario,pass_flag,outcome,start,receipt=None):
  row=self.auth.state(self.subject['operation_id'])
  return {'scenario':scenario,'description':SCENARIOS[scenario], 'passed':bool(pass_flag),
   'decision':outcome,'operation_id':self.subject['operation_id'],
   'authorized_recipient':'customer A','requested_recipient':'customer B' if scenario=='wrong_recipient' else 'customer A',
   'authority_state':row[0] if row else None, 'elapsed_ms':round(1000*(time.perf_counter()-start),2),
   'receipt':receipt,'timeline':self.timeline,'environment':'LOCAL_LAB_ONLY_NO_GITEE_WRITE'}

def run_scenario(name):
 with tempfile.TemporaryDirectory(prefix='ci-trace-r22-') as temp:
  return LabSession(temp).execute(name)

def run_all():
 return [run_scenario(k) for k in SCENARIOS]

if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser();parser.add_argument('--scenario',choices=list(SCENARIOS));parser.add_argument('--all',action='store_true')
 opts=parser.parse_args()
 results=run_all() if opts.all or not opts.scenario else run_scenario(opts.scenario)
 print(json.dumps(results,indent=2,ensure_ascii=False))
 if isinstance(results,list) and not all(x['passed'] for x in results):sys.exit(2)
