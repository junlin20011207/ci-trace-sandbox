"""Author-designed receipt-retry benchmark. No arbitrary external side effect."""
import concurrent.futures,hashlib,json,tempfile,time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ci_trace.approval_v14 import ApprovalLedger,ProtectedIssuer
from ci_trace.effect_v15 import ReceiptSink
DATA=b'inert invoice acknowledgement payload'
SUBJECT={'repository':'example/repo','run_id':42,'artifact_id':71,
         'commit_sha':'c'*40,'content_sha256':hashlib.sha256(DATA).hexdigest(),
         'recipient':'spiffe://ci-trace.local/consumer'}
def experiment(grants=12,retries=100):
    with tempfile.TemporaryDirectory(prefix='ci-v15-effects-') as temp:
        top=Path(temp)
        (top/'issuer').mkdir(mode=0o700);(top/'sink').mkdir(mode=0o700)
        ledger=ApprovalLedger(top/'issuer'/'grants.sqlite')
        sink=ReceiptSink(top/'sink'/'receipts.sqlite')
        sk=Ed25519PrivateKey.generate()
        pub={'test':sk.public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()}
        issuer=ProtectedIssuer(ledger,sk,'test',[SUBJECT]);now=time.time()
        batches=[]
        for i in range(grants):
            grant=issuer.issue(SUBJECT,ttl=600,now=now)
            ledger.reserve(grant,pub,SUBJECT['recipient'],now=now)
            def call(_):
                return sink.apply(grant,pub,SUBJECT['recipient'],DATA,ledger,now=now)
            start=time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
                outputs=list(executor.map(call,range(retries)))
            assert sum(not x['replayed'] for x in outputs)==1
            batches.append((time.perf_counter()-start)*1000)
        assert sink.count()==grants
        return {'scenario':'synthetic SQLite transactional inert receipts',
                'grant_count':grants,'attempts':grants*retries,
                'durable_effects':sink.count(),'deduplicated':grants*(retries-1),
                'median_batch_ms':round(sorted(batches)[len(batches)//2],3),
                'external_business_services_tested':False}
if __name__=='__main__':
    print(json.dumps(experiment(),indent=2))
