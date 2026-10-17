"""Integration tests: real SSL sockets, issuer subprocess, Git object updates, SM2/SM3.
IMPORTANT: All Git repos and keypairs are temporary laboratory fixtures.
"""
import base64,copy,json,multiprocessing,os,socket,ssl,tempfile,time,unittest,urllib.error,sqlite3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from .crypto_sm import keypair,sm3,sign,verify,strict_json,canonical
from .authority_server import State,serve,git
from .lab_setup import certificates,local_git_repo
from .client import MTLSClient,fresh_subject,publish,push_local_create_only

class NativeLab(unittest.TestCase):
 def setUp(self):
    self.tmp=tempfile.TemporaryDirectory(prefix='r23-cn-testing-');self.root=Path(self.tmp.name)
    self.tls=certificates(self.root/'certs')
    self.remote=str(self.root/'remote.git');self.base=local_git_repo(self.remote)
    self.payload=b'GB-T safe release payload for customer A\n'
    self.sub=fresh_subject(self.base,self.payload,'release-'+os.urandom(8).hex(),platform=getattr(self,'platform','CODEARTS'))
    self.state=State(self.root/'issuer.sqlite',self.tls['sm_private'],self.tls['sm_public'],self.remote,self.sub)
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));self.port=s.getsockname()[1]
    self.proc=multiprocessing.Process(target=serve,args=(self.state,self.tls['ca'],self.tls['server_cert'],self.tls['server_key'],self.port),daemon=True)
    self.proc.start()
    self.client=MTLSClient('https://localhost:'+str(self.port),self.tls['ca'],self.tls['publisher_cert'],self.tls['publisher_key'])
    for i in range(80):
        try:
            self.client.call('state',{'operation_id':self.sub['operation_id']});break
        except (OSError,urllib.error.URLError,ssl.SSLError):time.sleep(.04)
    else:raise RuntimeError('issuer HTTPS endpoint did not start')
 def tearDown(self):
    self.proc.terminate();self.proc.join(timeout=4);self.tmp.cleanup()
 def issue(self):
    a=self.client.call('issue',{'operation_id':self.sub['operation_id'],'subject':self.sub})
    self.assertTrue(a['ok'],a);return a['grant']
 def reserve(self,grant):
    return self.client.call('reserve',{'operation_id':self.sub['operation_id'],'grant':grant})
 def test_01_valid_sm2_offline_signature(self):
    grant=self.issue();self.assertTrue(verify(grant,self.tls['sm_public'],'grant'))
 def test_02_no_tls_client_certificate(self):
    import urllib.request
    ctx=ssl.create_default_context(cafile=self.tls['ca'])
    req=urllib.request.Request('https://localhost:'+str(self.port)+'/state',canonical({'operation_id':self.sub['operation_id']}),{'Content-Type':'application/json'},method='POST')
    with self.assertRaises((ssl.SSLError,urllib.error.URLError,ConnectionError,TimeoutError)):
        urllib.request.urlopen(req,context=ctx,timeout=2)
 def test_03_wrong_certificate_cn(self):
    attacker=MTLSClient('https://localhost:'+str(self.port),self.tls['ca'],self.tls['attacker_cert'],self.tls['attacker_key'])
    with self.assertRaises(urllib.error.HTTPError) as err:attacker.call('state',{'operation_id':self.sub['operation_id']})
    self.assertEqual(err.exception.code,403)
 def test_04_valid_publish_with_actual_git_proof(self):
    v=publish(self.client,self.tls['sm_public'],self.sub,self.payload,self.remote)
    self.assertTrue(v.get('ok'),v)
    self.assertEqual(v['decision'],'PUBLISHED_VERIFIED');self.assertTrue(verify(v['receipt'],self.tls['sm_public'],'receipt'))
    self.assertEqual(v['receipt']['body']['payload']['artifact_sm3'],sm3(self.payload))
 def test_05_wrong_recipient_cannot_approve(self):
    wrong=copy.deepcopy(self.sub);wrong['recipient']='customer-B'
    r=self.client.call('issue',{'operation_id':self.sub['operation_id'],'subject':wrong})
    self.assertFalse(r['ok']);self.assertEqual(r['reason'],'SUBJECT_MISMATCH')
 def test_06_swapped_payload_rejected_before_push(self):
    r=publish(self.client,self.tls['sm_public'],self.sub,b'another payload',self.remote)
    self.assertFalse(r['ok']);self.assertEqual(r['reason'],'ARTIFACT_OR_SUBJECT_MISMATCH')
 def test_07_revoke_before_reserve(self):
    g=self.issue();denied=self.client.call('revoke',{'operation_id':self.sub['operation_id']});self.assertFalse(denied['ok'])
    self.assertEqual(denied['reason'],'ADMIN_ONLY_REVOKE')
    # Simulate offline administrator, NOT publisher, revoking issuer-owned record.
    with sqlite3.connect(self.root/'issuer.sqlite') as db:
        db.execute('UPDATE ops SET state=? WHERE id=?',('REVOKED',self.sub['operation_id']))
    self.assertEqual(self.reserve(g)['reason'],'RESERVE_STATE_REVOKED')
 def test_08_32_concurrent_reservations_one_winner(self):
    g=self.issue()
    def f(_):return self.reserve(g)
    with ThreadPoolExecutor(max_workers=12) as pool:out=list(pool.map(f,range(32)))
    self.assertEqual(sum(x.get('ok',False) for x in out),1)
 def test_09_git_create_only_ref_collision(self):
    g=self.issue();self.assertTrue(self.reserve(g)['ok'])
    label,sha=push_local_create_only(self.remote,self.sub,self.payload,force_collision=True)
    self.assertEqual(label,'CREATE_ONLY_REJECTED');self.assertIsNone(sha)
    self.assertEqual(git('--git-dir',self.remote,'rev-parse',self.sub['target_ref']).decode().strip(),self.base)
 def test_10_verified_crash_recovery(self):
    g=self.issue();self.assertTrue(self.reserve(g)['ok'])
    result,sha=push_local_create_only(self.remote,self.sub,self.payload,crash_after_push=True)
    self.assertEqual(result,'CRASH_AFTER_PUSH')
    rec=self.client.call('confirm',{'operation_id':self.sub['operation_id'],'actual_sha':sha})
    self.assertTrue(rec['ok'],rec);self.assertTrue(verify(rec['receipt'],self.tls['sm_public'],'receipt'))
    twice=self.client.call('confirm',{'operation_id':self.sub['operation_id'],'actual_sha':sha})
    self.assertEqual(twice['decision'],'IDEMPOTENT_VERIFIED')
 def test_11_false_ack_denied(self):
    g=self.issue();self.assertTrue(self.reserve(g)['ok'])
    r=self.client.call('confirm',{'operation_id':self.sub['operation_id'],'actual_sha':self.base})
    self.assertFalse(r['ok']);self.assertEqual(r['reason'],'NO_VERIFIED_REMOTE_PROOF')
 def test_12_sm2_receipt_tamper_denied(self):
    x=publish(self.client,self.tls['sm_public'],self.sub,self.payload,self.remote)
    self.assertTrue(x['ok']);tamper=copy.deepcopy(x['receipt']);tamper['body']['payload']['recipient']='customer-B'
    self.assertFalse(verify(tamper,self.tls['sm_public'],'receipt'))
 def test_13_signature_algorithm_substitution_denied(self):
    g=self.issue();g['algorithm']='ED25519';self.assertFalse(verify(g,self.tls['sm_public'],'grant'))
 def test_14_sm2_wrong_key_denied(self):
    g=self.issue();p,q=keypair(self.root/'other');self.assertFalse(verify(g,q,'grant'))
 def test_15_offline_receipt_after_ref_tamper_no_online_reconfirm(self):
    v=publish(self.client,self.tls['sm_public'],self.sub,self.payload,self.remote);self.assertTrue(v['ok'])
    git('--git-dir',self.remote,'update-ref',self.sub['target_ref'],self.base)
    confirm=self.client.call('confirm',{'operation_id':self.sub['operation_id'],'actual_sha':self.base})
    self.assertFalse(confirm['ok']);self.assertEqual(confirm['reason'],'REMOTE_CHANGED_AFTER_CONFIRM')
    # Pure offline cryptographic verification can't infer mutable Git refs changed afterward.
    self.assertTrue(verify(v['receipt'],self.tls['sm_public'],'receipt'))
 def test_16_strict_json_duplicate_keys(self):
    with self.assertRaises(ValueError):strict_json(b'{"operation_id":"a","operation_id":"b"}')
 def test_17_unapproved_operation_cannot_issue(self):
    new=fresh_subject(self.base,self.payload,'release-'+os.urandom(8).hex())
    response=self.client.call('issue',{'operation_id':new['operation_id'],'subject':new})
    self.assertFalse(response['ok'])
 def test_19_remote_push_disabled_without_lab_marker(self):
    with self.assertRaises(ValueError):
        push_local_create_only('https://gitee.com/liljunlin/test.git',self.sub,self.payload)
 def test_18_grant_forgery_payload_changes_denied(self):
    g=self.issue();g['body']['payload']['subject']['recipient']='customer-B'
    self.assertFalse(verify(g,self.tls['sm_public'],'grant'))

class NativeGiteeGoLab(NativeLab):
 def setUp(self):
    self.platform='GITEE_GO'
    super().setUp()

if __name__=='__main__':unittest.main(verbosity=2)
