"""Run only as root in a disposable Linux sandbox. Secret never printed."""
import concurrent.futures,json,os,stat,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption
from protocol import create_git_lab,sha256
from ipc_lab import client

ISSUER_UID=65531
PUBLISHER_UID=65533
ATTACKER_UID=65532

class UIDLab(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  if os.geteuid()!=0:raise unittest.SkipTest('requires sandbox root to create OS-isolated users')
  cls.tmp=tempfile.TemporaryDirectory(prefix='r21-uid-')
  cls.root=Path(cls.tmp.name)
  cls.private=cls.root/'issuer-private'
  cls.private.mkdir(mode=0o700)
  cls.socketdir=cls.root/'ipc'
  cls.socketdir.mkdir(mode=0o755)
  os.chown(cls.socketdir,ISSUER_UID,ISSUER_UID)
  cls.socket=str(cls.socketdir/'authority.sock')
  os.chmod(cls.root,0o755)
  os.chown(cls.private,ISSUER_UID,ISSUER_UID)
  key=Ed25519PrivateKey.generate().private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
  priv=cls.private/'signing.key';priv.write_bytes(key)
  os.chown(priv,ISSUER_UID,ISSUER_UID);priv.chmod(0o400)
  base=create_git_lab(cls.private/'local.git')
  # test Git remote accessible to the issuer to validate published refs
  from os import chown
  for root,dirs,files in os.walk(cls.private/'local.git'):
   chown(root,ISSUER_UID,ISSUER_UID)
   for name in dirs:chown(os.path.join(root,name),ISSUER_UID,ISSUER_UID)
   for name in files:chown(os.path.join(root,name),ISSUER_UID,ISSUER_UID)
  cls.subject={
   'repository_id':'1414105644','repository':'junlin20011207/ci-trace-sandbox',
   'source_sha':'d'*40,'source_workflow_ref':'junlin20011207/ci-trace-sandbox/.github/workflows/lab.yml@refs/heads/research/x',
   'artifact_sha256':sha256(b'harmless\n'),'gitee_repo':'https://gitee.com/liljunlin/test.git',
   'target_ref':'refs/heads/research/ci-trace-uid-lab','target_base_sha':base,
   'operation_id':'operation-UID-20261012','approver_policy_id':'signed-lab-policy-21'}
  f=cls.private/'approved-subject.json';f.write_text(json.dumps(cls.subject))
  os.chown(f,ISSUER_UID,ISSUER_UID);f.chmod(0o400)
  cls.proc=subprocess.Popen(['setpriv',f'--reuid={ISSUER_UID}',f'--regid={ISSUER_UID}','--clear-groups',
      sys.executable,str(Path(__file__).parent/'ipc_lab.py'),'serve',str(cls.private),cls.socket,str(PUBLISHER_UID)],
      stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  for _ in range(100):
   if os.path.exists(cls.socket):break
   if cls.proc.poll() is not None:raise RuntimeError('issuer process exited: '+cls.proc.stderr.read())
   time.sleep(.05)
  if not os.path.exists(cls.socket):raise RuntimeError('issuer socket never appeared')
 @classmethod
 def tearDownClass(cls):
  if hasattr(cls,'proc'):
   cls.proc.terminate()
   try:cls.proc.wait(timeout=3)
   except subprocess.TimeoutExpired:cls.proc.kill()
  if hasattr(cls,'tmp'):cls.tmp.cleanup()
 @classmethod
 def call_as(cls,uid,action):
  cmd=['setpriv',f'--reuid={uid}',f'--regid={uid}','--clear-groups',sys.executable,
       str(Path(__file__).parent/'ipc_lab.py'),'client',cls.socket,json.dumps(action)]
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
  if r.returncode:raise AssertionError(r.stderr)
  return json.loads(r.stdout)
 def test_01_publisher_cannot_read_private_issuer_key(self):
  for uid in (PUBLISHER_UID,ATTACKER_UID):
   code='import pathlib,sys;pathlib.Path(sys.argv[1]).read_bytes()'
   r=subprocess.run(['setpriv',f'--reuid={uid}',f'--regid={uid}','--clear-groups',sys.executable,'-c',code,
      str(self.private/'signing.key')],capture_output=True,text=True,timeout=8)
   self.assertNotEqual(r.returncode,0)
 def test_02_unknown_linux_uid_cannot_issue(self):
  response=self.call_as(ATTACKER_UID,{'action':'issue','subject':self.subject})
  self.assertEqual(response['result'],'DENY_PEER_UID')
 def test_03_unprivileged_caller_cannot_modify_issuer_db(self):
  for uid in (PUBLISHER_UID,ATTACKER_UID):
   r=subprocess.run(['setpriv',f'--reuid={uid}',f'--regid={uid}','--clear-groups',sys.executable,
        '-c','import sqlite3,sys;sqlite3.connect(sys.argv[1]).execute("DELETE FROM operations")',
        str(self.private/'issuer.sqlite')],capture_output=True,text=True,timeout=8)
   self.assertNotEqual(r.returncode,0)
 def test_04_issuer_does_not_allow_publisher_preapproval(self):
  resp=self.call_as(PUBLISHER_UID,{'action':'approve','subject':self.subject})
  self.assertEqual(resp['result'],'DENY_ACTION_OR_ROLE')
 def test_05_issue_one_grant_then_atomic_competition(self):
  rsp=self.call_as(PUBLISHER_UID,{'action':'issue','subject':self.subject})
  self.assertEqual(rsp['result'],'ISSUED')
  grant=rsp['grant']
  def task(_):return self.call_as(PUBLISHER_UID,{'action':'reserve','subject':self.subject,'grant':grant,'now':1})['result']
  with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
   results=list(pool.map(task,range(48)))
  self.assertEqual(results.count('RESERVED'),1)
  self.assertEqual(results.count('HOLD_ALREADY_RESERVED'),47)
 def test_06_unauthorized_admin_action_denied(self):
  response=self.call_as(PUBLISHER_UID,{'action':'revoke','operation_id':self.subject['operation_id']})
  self.assertEqual(response['result'],'DENY_ACTION_OR_ROLE')
 def test_07_cannot_issue_arbitrary_other_subject(self):
  req=dict(self.subject,source_sha='e'*40,operation_id='operation-UID-other')
  res=self.call_as(PUBLISHER_UID,{'action':'issue','subject':req})
  self.assertEqual(res['result'],'DENY_UNAPPROVED_SUBJECT')

if __name__=='__main__':unittest.main(verbosity=2)
