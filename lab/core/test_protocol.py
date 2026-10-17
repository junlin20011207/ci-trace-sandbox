import os,sys,copy,time,unittest,sqlite3, tempfile,subprocess,threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from protocol import Authority,CreateOnlyPublisher,create_git_lab,sha256,public_hex,_run

NOW=int(time.time())
class ProtocolTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='r21-test-')
  self.addCleanup(self.tmp.cleanup)
  root=Path(self.tmp.name)
  self.bare=root/'remote.git'
  self.base=create_git_lab(self.bare)
  self.key=Ed25519PrivateKey.generate()
  self.db=root/'authority.sqlite'
  self.auth=Authority(self.db,self.key,remote_bare=self.bare)
  self.payload=b'approved legitimate inert research payload\n'
  self.s={
   'repository_id':'1414105644','repository':'junlin20011207/ci-trace-sandbox',
   'source_sha':'c'*40,
   'source_workflow_ref':'junlin20011207/ci-trace-sandbox/.github/workflows/candidate.yml@refs/heads/research/x',
   'artifact_sha256':sha256(self.payload),
   'gitee_repo':'https://gitee.com/liljunlin/test.git',
   'target_ref':'refs/heads/research/ci-trace-r21-lab',
   'target_base_sha':self.base,'operation_id':'operation-R21-001',
   'approver_policy_id':'lab-policy-v21'}
  self.trust={'schema_version':1,'issuers':{'LAB-R21':public_hex(self.key)},'policy_revision':21,
              'revoked_grants':[],'max_ttl_seconds':120,'max_clock_skew_seconds':10}
  self.publisher=CreateOnlyPublisher(self.bare,self.trust)
 def issue(self):
  self.auth.approve_subject(self.s)
  g,why=self.auth.issue(self.s,now=NOW,ttl=90)
  self.assertEqual(why,'ISSUED')
  return g
 def test_01_success_binds_commit_and_receipt(self):
  g=self.issue()
  status,proof=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+1)
  self.assertEqual(status,'ACK_PUBLISHED')
  self.assertEqual(self.auth.state(self.s['operation_id'])[0],'PUBLISHED')
  self.assertEqual(proof['base_sha'],self.base)
  self.assertEqual(self.publisher._ref('refs/heads/master'),self.base)
  self.assertNotEqual(self.publisher._ref(self.s['target_ref']),self.base)
 def test_02_replay_recovers_without_second_push(self):
  g=self.issue()
  status,proof=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+1)
  self.assertEqual(status,'ACK_PUBLISHED')
  again,proof2=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+2)
  self.assertEqual(again,'RECOVERED_ACK_IDEMPOTENT')
  self.assertEqual(proof,proof2)
 def test_03_preapproved_absent_does_not_sign(self):
  g,why=self.auth.issue(self.s,now=NOW)
  self.assertIsNone(g);self.assertEqual(why,'DENY_UNAPPROVED_SUBJECT')
 def test_04_subject_mismatch_does_not_sign(self):
  self.auth.approve_subject(self.s)
  corrupt=dict(self.s,source_sha='e'*40)
  g,why=self.auth.issue(corrupt,now=NOW)
  self.assertIsNone(g);self.assertEqual(why,'DENY_UNAPPROVED_SUBJECT')
 def test_05_revoke_before_issue(self):
  self.auth.approve_subject(self.s)
  self.assertEqual(self.auth.revoke(self.s['operation_id']),'REVOKED')
  g,why=self.auth.issue(self.s,now=NOW)
  self.assertIsNone(g);self.assertEqual(why,'DENY_REVOKED')
 def test_06_revoke_before_reservation(self):
  g=self.issue()
  self.assertEqual(self.auth.revoke(self.s['operation_id']),'REVOKED')
  status,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+1)
  self.assertEqual(status,'HOLD_DENY_REVOKED')
  self.assertIsNone(self.publisher._ref(self.s['target_ref']))
 def test_07_expiry_rejects_at_boundary(self):
  g=self.issue()
  status,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+90)
  self.assertIn('expired',status.lower())
  self.assertIsNone(self.publisher._ref(self.s['target_ref']))
 def test_08_mutated_destination_signed_invalid(self):
  g=self.issue();g['payload']['target_ref']='refs/heads/research/other'
  st,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+1)
  self.assertIn('HOLD_',st)
  self.assertIsNone(self.publisher._ref(self.s['target_ref']))
 def test_09_grant_substitution_refused(self):
  g=self.issue()
  g2=copy.deepcopy(g);g2['signature_hex']='0'*128
  st,_=self.publisher.publish(self.auth,g2,self.s,self.payload,now=NOW+1)
  self.assertIn('HOLD_',st)
 def test_10_payload_mismatch_refused(self):
  g=self.issue()
  st,_=self.publisher.publish(self.auth,g,self.s,b'evil\n',now=NOW+1)
  self.assertEqual(st,'HOLD_PAYLOAD_MISMATCH')
 def test_11_branch_already_created_refused(self):
  g=self.issue()
  _run(['git','--git-dir',str(self.bare),'update-ref',self.s['target_ref'],self.base])
  st,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+1)
  self.assertEqual(st,'HOLD_TARGET_EXISTS')
  self.assertEqual(self.auth.state(self.s['operation_id'])[0],'ISSUED')
 def test_12_base_drift_refused_before_reserve(self):
  g=self.issue()
  with tempfile.TemporaryDirectory() as d:
   _run(['git','clone','-q',str(self.bare),d]);p=Path(d,'drift');p.write_text('drift')
   _run(['git','add','drift'],cwd=d)
   _run(['git','-c','user.name=Lab','-c','user.email=lab@invalid','commit','-qm','unrelated'],cwd=d)
   _run(['git','push','-q','origin','HEAD:master'],cwd=d)
  st,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+1)
  self.assertEqual(st,'HOLD_BASE_DRIFT')
 def test_13_different_pinned_public_key_refused(self):
  g=self.issue();wrong=dict(self.trust,issuers={'LAB-R21':public_hex(Ed25519PrivateKey.generate())})
  st,_=CreateOnlyPublisher(self.bare,wrong).publish(self.auth,g,self.s,self.payload,now=NOW+1)
  self.assertIn('HOLD_',st)
 def test_14_key_and_grant_both_corrupt_but_pub_pinned(self):
  g=self.issue();forged=Ed25519PrivateKey.generate()
  bad=dict(self.trust,issuers={'LAB-R21':public_hex(forged)})
  # Deny if publisher retains the original trust root.
  import release_gate as gate
  g['signature_hex']=forged.sign(gate.DOMAIN+gate.canon(g['payload'])).hex()
  st,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+1)
  self.assertIn('HOLD_',st)
  # It is a critical *counterexample* if publisher's trusted root is editable.
  self.assertTrue(gate.verify(g,bad,self.s,NOW+1)[0])
 def test_15_authority_db_unavailable_fail_closed(self):
  g=self.issue()
  self.auth.db=str(Path(self.tmp.name)/'no-such-dir'/'missing.sqlite')
  st,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+1)
  self.assertIn('HOLD_EXCEPTION_',st)
 def test_16_late_revocation_not_cancellation(self):
  g=self.issue()
  self.assertEqual(self.auth.reserve_online(self.s,g,now=NOW+1),'RESERVED')
  self.assertEqual(self.auth.revoke(self.s['operation_id']),'TOO_LATE_ALREADY_IN_FLIGHT')
  self.assertEqual(self.auth.state(self.s['operation_id'])[0],'RESERVED')
 def test_17_reserve_replay_contention_64(self):
  g=self.issue()
  def reserve(_):return self.auth.reserve_online(self.s,g,now=NOW+1)
  with ThreadPoolExecutor(max_workers=24) as pool:
   results=list(pool.map(reserve,range(64)))
  self.assertEqual(results.count('RESERVED'),1)
  self.assertEqual(results.count('HOLD_ALREADY_RESERVED'),63)
 def test_18_revoke_vs_reserve_is_serialized(self):
  g=self.issue()
  with ThreadPoolExecutor(max_workers=2) as pool:
   a=pool.submit(self.auth.revoke,self.s['operation_id']);b=pool.submit(self.auth.reserve_online,self.s,g,now=NOW+1)
   results={a.result(),b.result()}
  self.assertTrue(results=={'REVOKED','DENY_REVOKED'} or results=={'TOO_LATE_ALREADY_IN_FLIGHT','RESERVED'},results)
 def test_19_crash_after_push_recovery(self):
  g=self.issue()
  code='''import json,sys,os;sys.path.insert(0,sys.argv[1]);from protocol import *;s=json.loads(sys.argv[4]);g=json.loads(sys.argv[5]);trust=json.loads(sys.argv[6]);a=Authority(sys.argv[3],None);p=CreateOnlyPublisher(sys.argv[2],trust);p.publish(a,g,s,bytes.fromhex(sys.argv[7]),now=int(sys.argv[8]),crash_after_push=True)'''
  p=subprocess.run([sys.executable,'-c',code,str(Path(__file__).parent),str(self.bare),str(self.db),json_dumps(self.s),json_dumps(g),json_dumps(self.trust),self.payload.hex(),str(NOW+1)],capture_output=True,text=True,timeout=20)
  self.assertEqual(p.returncode,91,p.stderr)
  self.assertEqual(self.auth.state(self.s['operation_id'])[0],'RESERVED')
  st,proof=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+2)
  self.assertEqual(st,'RECOVERED_ACK_PUBLISHED')
  self.assertEqual(self.auth.state(self.s['operation_id'])[0],'PUBLISHED')
  self.assertIsNotNone(proof)
 def test_20_ambiguous_changed_remote_stays_hold(self):
  g=self.issue()
  self.assertEqual(self.auth.reserve_online(self.s,g,now=NOW+1),'RESERVED')
  _run(['git','--git-dir',str(self.bare),'update-ref',self.s['target_ref'],self.base])
  st,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+2)
  self.assertEqual(st,'HOLD_AMBIGUOUS')
 def test_21_reissued_ticket_not_possible(self):
  g=self.issue();g2,msg=self.auth.issue(self.s,now=NOW+1)
  self.assertIsNone(g2);self.assertEqual(msg,'DENY_ALREADY_ISSUED')
 def test_22_same_target_after_publish_checked(self):
  g=self.issue();self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+1)
  _run(['git','--git-dir',str(self.bare),'update-ref',self.s['target_ref'],self.base])
  st,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+2)
  self.assertEqual(st,'HOLD_AMBIGUOUS')
 def test_23_tamper_grant_unsigned_authority_rejects_online(self):
  g=self.issue();tampered=copy.deepcopy(g);tampered['payload']['issued_at']=NOW-2
  self.assertEqual(self.auth.reserve_online(self.s,tampered,now=NOW+1),'DENY_GRANT_MISMATCH')
 def test_25_forged_ack_cannot_publish(self):
  g=self.issue()
  self.assertEqual(self.auth.reserve_online(self.s,g,now=NOW+1),'RESERVED')
  fake={'operation_id':self.s['operation_id'],'target_ref':self.s['target_ref'],
        'published_sha':self.base,'base_sha':self.base,
        'content_sha256':self.s['artifact_sha256']}
  st=self.auth.ack(self.s['operation_id'],self.base,fake)
  self.assertEqual(st,'HOLD_INVALID_REMOTE_PROOF')
  self.assertEqual(self.auth.state(self.s['operation_id'])[0],'RESERVED')
 def test_26_reconcile_exact_remote_after_grant_expired(self):
  g=self.issue()
  code='import json,sys,os;sys.path.insert(0,sys.argv[1]);from protocol import *;s=json.loads(sys.argv[4]);g=json.loads(sys.argv[5]);t=json.loads(sys.argv[6]);a=Authority(sys.argv[3],None);p=CreateOnlyPublisher(sys.argv[2],t);p.publish(a,g,s,bytes.fromhex(sys.argv[7]),now=int(sys.argv[8]),crash_after_push=True)'
  import json
  p=subprocess.run([sys.executable,'-c',code,str(Path(__file__).parent),str(self.bare),str(self.db),json.dumps(self.s),json.dumps(g),json.dumps(self.trust),self.payload.hex(),str(NOW+1)],capture_output=True,text=True,timeout=20)
  self.assertEqual(p.returncode,91,p.stderr)
  self.assertEqual(self.auth.state(self.s['operation_id'])[0],'RESERVED')
  st,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+150)
  self.assertEqual(st,'RECOVERED_ACK_PUBLISHED')
 def test_27_caller_clock_cannot_resurrect_expired_grant(self):
  self.auth.approve_subject(self.s)
  g,msg=self.auth.issue(self.s,now=NOW-250,ttl=90)
  self.assertEqual(msg,'ISSUED')
  # Attack: caller lies that the clock is 249 seconds earlier.
  st=self.auth.reserve_online(self.s,g,now=NOW-249)
  self.assertEqual(st,'DENY_EXPIRED')
  self.assertEqual(self.auth.state(self.s['operation_id'])[0],'ISSUED')
 def test_28_extra_unapproved_files_in_remote_tree_denied(self):
  g=self.issue()
  self.assertEqual(self.auth.reserve_online(self.s,g,now=NOW+1),'RESERVED')
  with tempfile.TemporaryDirectory() as d:
   _run(['git','clone','-q',str(self.bare),d])
   f=Path(d,'research','payload.txt');f.parent.mkdir(exist_ok=True);f.write_bytes(self.payload)
   Path(d,'unauthorized_file.txt').write_text('malicious unrelated change\n')
   _run(['git','add','.'],cwd=d)
   _run(['git','-c','user.name=Lab','-c','user.email=lab@example.invalid',
          'commit','-qm','CI-TRACE-R21 operation='+self.s['operation_id']],cwd=d)
   sha=_run(['git','rev-parse','HEAD'],cwd=d).stdout.strip()
   _run(['git','push','origin','HEAD:'+self.s['target_ref']],cwd=d)
  # ACK proof must represent the full intended change-set, not just one hashed file.
  forged={'operation_id':self.s['operation_id'],'target_ref':self.s['target_ref'],
        'published_sha':sha,'base_sha':self.base,
        'content_sha256':self.s['artifact_sha256']}
  self.assertEqual(self.auth.ack(self.s['operation_id'],sha,forged),'HOLD_INVALID_REMOTE_PROOF')
 def test_29_malicious_base_research_symlink_must_not_write_outside(self):
  external=Path(self.tmp.name,'victim');external.mkdir()
  with tempfile.TemporaryDirectory() as d:
   _run(['git','clone','-q',str(self.bare),d])
   Path(d,'research').symlink_to(external,target_is_directory=True)
   _run(['git','add','research'],cwd=d)
   _run(['git','-c','user.name=Lab','-c','user.email=lab@example.invalid','commit','-qm','add symlink'],cwd=d)
   _run(['git','push','origin','HEAD:master'],cwd=d)
  self.s['target_base_sha']=_run(['git','--git-dir',str(self.bare),'rev-parse','refs/heads/master']).stdout.strip()
  g=self.issue()
  st,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+1)
  self.assertFalse((external/'payload.txt').exists(),'unsafe write through Git-tracked symlink')
  self.assertNotEqual(st,'ACK_PUBLISHED')
 def test_30_binary_payload_rejected_before_push(self):
  self.payload=b'\xff\xfe invalid text'
  self.s['artifact_sha256']=sha256(self.payload)
  g=self.issue()
  st,_=self.publisher.publish(self.auth,g,self.s,self.payload,now=NOW+1)
  self.assertEqual(st,'HOLD_PAYLOAD_NOT_UTF8')
  self.assertIsNone(self.publisher._ref(self.s['target_ref']))
 def test_24_collision_other_operation_denied(self):
  self.auth.approve_subject(self.s)
  with self.assertRaises(sqlite3.IntegrityError):self.auth.approve_subject(self.s)

def json_dumps(x):
 import json
 return json.dumps(x,separators=(',',':'))
if __name__=='__main__':unittest.main(verbosity=2)
