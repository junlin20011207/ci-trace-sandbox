"""V15 hosted regression: signed receipt, crash, issuer isolation, revoke race."""
import concurrent.futures,hashlib,json,os,socket,subprocess,sys,threading,time
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ci_trace.approval_v14 import ApprovalLedger,ProtectedIssuer
from ci_trace.effect_v15 import ReceiptSink
from ci_trace.revocation_v15 import AtomicRevocationLedger
from ci_trace.issuer_agent_v15 import listener,serve_one,request_signature
from ci_trace.provenance_guard import Denied

PAYLOAD=b'inert research business receipt'
SUBJECT={'repository':'research/demo','run_id':42,'artifact_id':2,
   'commit_sha':'a'*40,'content_sha256':hashlib.sha256(PAYLOAD).hexdigest(),
   'recipient':'spiffe://research.test/consumer'}

def setup(tmp_path,cls=ApprovalLedger):
    issuer_dir=tmp_path/'issuer';issuer_dir.mkdir(mode=0o700)
    sink_dir=tmp_path/'sink';sink_dir.mkdir(mode=0o700)
    ledger=cls(issuer_dir/'grants.sqlite');sink=ReceiptSink(sink_dir/'receipts.sqlite')
    key=Ed25519PrivateKey.generate()
    pub={'key':key.public_key().public_bytes(
      serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()}
    signer=ProtectedIssuer(ledger,key,'key',[SUBJECT])
    now=time.time();token=signer.issue(SUBJECT,ttl=300,now=now)
    return ledger,sink,pub,token,now,signer

def test_ack_loss_and_100_retries_produce_one_receipt(tmp_path):
    ledger,sink,pub,token,now,_=setup(tmp_path)
    ledger.reserve(token,pub,SUBJECT['recipient'],now=now)
    with pytest.raises(ConnectionError):
        sink.apply(token,pub,SUBJECT['recipient'],PAYLOAD,ledger,now=now,
           after_commit_hook=lambda:(_ for _ in ()).throw(ConnectionError('ack lost')))
    def attempt(_):
        return sink.apply(token,pub,SUBJECT['recipient'],PAYLOAD,ledger,now=now)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as workers:
        results=list(workers.map(attempt,range(100)))
    assert all(r['replayed'] for r in results) and sink.count()==1

def test_revoke_before_grant_use_and_invalid_content(tmp_path):
    ledger,sink,pub,token,now,_=setup(tmp_path)
    with pytest.raises(Denied,match='effect_grant_not_reserved'):
        sink.apply(token,pub,SUBJECT['recipient'],PAYLOAD,ledger,now=now)
    ledger.reserve(token,pub,SUBJECT['recipient'],now=now)
    with pytest.raises(Denied,match='effect_artifact_digest_mismatch'):
        sink.apply(token,pub,SUBJECT['recipient'],b'FAKE',ledger,now=now)
    assert sink.count()==0

def test_v14_key_revocation_between_check_and_update_is_bypassed(tmp_path):
    ledger,_,pub,token,now,_=setup(tmp_path)
    original=ledger._key_revoked
    def revoke_in_gap(k):
        assert not original(k)
        ledger.revoke_key(k)
        return False
    ledger._key_revoked=revoke_in_gap
    assert ledger.reserve(token,pub,SUBJECT['recipient'],now=now)['status']=='uncertain_delivery'
    assert original('key')

def test_v15_revoked_key_rejected_in_same_database_transaction(tmp_path):
    ledger,_,pub,token,now,_=setup(tmp_path,AtomicRevocationLedger)
    ledger.revoke_key('key')
    with pytest.raises(Denied,match='approval_key_revoked'):
        ledger.reserve(token,pub,SUBJECT['recipient'],now=now)
    assert ledger.state(token['record']['grant_id'])=='granted'

def test_v15_issuer_denies_wrong_client_kernel_uid(tmp_path):
    ledger,_,pub,token,now,signer=setup(tmp_path)
    endpoint=tmp_path/'issuer.sock';server=listener(endpoint)
    errors=[]
    def service():
        try:serve_one(server,signer,permitted_approver_uid=os.getuid()+1)
        except Denied as e:errors.append(str(e))
    worker=threading.Thread(target=service,daemon=True);worker.start()
    with pytest.raises(Denied,match='issuer_did_not_approve'):
        request_signature(endpoint,SUBJECT)
    worker.join(timeout=6);server.close()
    assert errors==['issuer_principal_denied']

def test_v15_process_crash_after_atomic_business_commit(tmp_path):
    ledger,sink,pub,token,now,_=setup(tmp_path)
    ledger.reserve(token,pub,SUBJECT['recipient'],now=now)
    config=tmp_path/'config.json'
    config.write_text(json.dumps({'issuer':str(ledger.path),'sink':str(sink.path),
                                  'grant':token,'pub':pub,'now':now}))
    program=StringCode = '''import json,os,sys
from ci_trace.approval_v14 import ApprovalLedger
from ci_trace.effect_v15 import ReceiptSink
x=json.load(open(sys.argv[1]))
ReceiptSink(x['sink']).apply(x['grant'],x['pub'],'spiffe://research.test/consumer',
 b'inert research business receipt',ApprovalLedger(x['issuer']),now=x['now'],
 after_commit_hook=lambda:os.kill(os.getpid(),9))
'''
    proc=subprocess.run([sys.executable,'-c',program,str(config)],
         cwd=str(Path(__file__).resolve().parents[1]),capture_output=True)
    assert proc.returncode==-9,proc.stderr
    assert ReceiptSink(sink.path).count()==1
    assert sink.apply(token,pub,SUBJECT['recipient'],PAYLOAD,ledger,now=now)['replayed']
    assert sink.count()==1
