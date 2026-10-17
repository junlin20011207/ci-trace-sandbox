import copy,hashlib,hmac,time,unittest,tempfile,os
from .crypto_sm import canonical
from .request_adapter import verify_bridge_input,NonceStore
class AdapterContract(unittest.TestCase):
 def setUp(self):
    self.secret=b'CI-TRACE-R23-ONLY-LOCAL-CONTRACT' # 33 bytes lab key
    self.subject={'platform':'CODEARTS','operation_id':'release-12345678','source_commit_sha':'c'*40,
        'workflow_identity':'demo','artifact_sm3':'d'*64,'recipient':'customer-A',
        'target_repo':'gitee.com/liljunlin/test','target_ref':'refs/heads/research/native-cn-r23-12345678',
        'created_at':int(time.time()),'nonce':'nonce-'+('a'*24)}
 def sig(self,v=None):return hmac.new(self.secret,canonical(v or self.subject),'sha256').hexdigest()
 def test_valid_codearts_bridge_request_is_not_business_approval(self):
    x=verify_bridge_input(self.subject,self.secret,self.sig());self.assertTrue(x['accepted']);self.assertTrue(x['requires_independent_policy'])
 def test_valid_gitee_go_bridge_request_is_not_business_approval(self):
    x=dict(self.subject,platform='GITEE_GO');self.assertTrue(verify_bridge_input(x,self.secret,self.sig(x))['accepted'])
 def test_nonce_replay_rejected(self):
    with tempfile.TemporaryDirectory() as d:
      store=NonceStore(os.path.join(d,'nonce.sqlite'))
      self.assertTrue(verify_bridge_input(self.subject,self.secret,self.sig(),nonce_store=store)['accepted'])
      self.assertEqual(verify_bridge_input(self.subject,self.secret,self.sig(),nonce_store=store)['reason'],'REPLAYED_BRIDGE_NONCE')
 def test_wrong_client_secret(self):self.assertFalse(verify_bridge_input(self.subject,b'q'*32,self.sig())['accepted'])
 def test_modified_recipient(self):
    x=dict(self.subject,recipient='customer-B');self.assertEqual(verify_bridge_input(x,self.secret,self.sig())['reason'],'HMAC_MISMATCH')
 def test_stale_event(self):
    x=dict(self.subject,created_at=1);self.assertEqual(verify_bridge_input(x,self.secret,self.sig(x))['reason'],'STALE_EVENT')
 def test_unsupported_platform(self):
    x=dict(self.subject,platform='MALICIOUS');self.assertFalse(verify_bridge_input(x,self.secret,self.sig(x))['accepted'])
 def test_unknown_extra_field(self):
    x=dict(self.subject,admin_approved=True);self.assertEqual(verify_bridge_input(x,self.secret,self.sig(x))['reason'],'FIELDS')
if __name__=='__main__':unittest.main()
