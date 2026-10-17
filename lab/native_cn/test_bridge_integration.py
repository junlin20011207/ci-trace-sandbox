"""Developer-authored adapter -> preapproved subject -> mTLS issuer -> local Git.
No claim that CodeArts/Gitee Go official cloud pipelines were run.
"""
import hmac,os,time,unittest
from . import test_native as labtests
from .request_adapter import verify_bridge_input,candidate_matches_preapproval
from .crypto_sm import canonical
from .client import publish

class BridgeIntegration(unittest.TestCase):
 def run_full(self,kind):
    cls=labtests.NativeLab if kind=='CODEARTS' else labtests.NativeGiteeGoLab
    lab=cls('test_04_valid_publish_with_actual_git_proof');lab.setUp()
    try:
        subject=lab.sub;key=os.urandom(32)
        event={'platform':kind,'operation_id':subject['operation_id'],
               'source_commit_sha':subject['source_commit_sha'],
               'workflow_identity':subject['workflow_identity'],
               'artifact_sm3':subject['artifact_sm3'],
               'recipient':subject['recipient'],
               'target_repo':subject['target_repo'],'target_ref':subject['target_ref'],
               'created_at':int(time.time()),'nonce':os.urandom(12).hex()}
        from hashlib import sha256
        sig=hmac.new(key,canonical(event),'sha256').hexdigest()
        candidate=verify_bridge_input(event,key,sig)
        self.assertTrue(candidate['accepted']);self.assertTrue(candidate_matches_preapproval(candidate,subject))
        denied=dict(event,recipient='customer-B');deny_sig=hmac.new(key,canonical(denied),'sha256').hexdigest()
        denied_req=verify_bridge_input(denied,key,deny_sig)
        self.assertTrue(denied_req['accepted']);self.assertFalse(candidate_matches_preapproval(denied_req,subject))
        result=publish(lab.client,lab.tls['sm_public'],subject,lab.payload,lab.remote)
        self.assertTrue(result['ok'],result)
        return result
    finally:lab.tearDown()
 def test_codearts_contract_to_mtls_issuer_to_git(self):self.run_full('CODEARTS')
 def test_gitee_go_contract_to_mtls_issuer_to_git(self):self.run_full('GITEE_GO')
if __name__=='__main__':unittest.main()
