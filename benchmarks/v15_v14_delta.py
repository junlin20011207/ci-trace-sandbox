"""Compare V14 uncertain at-most-once grant to V15 local DB idempotent effect."""
import base64
import json
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ci_trace.approval_v14 import ApprovalLedger,issue_signed_grant
from ci_trace.quorum_effect_v15 import AtomicEffectSink,ROLES,canonical
from ci_trace.provenance_guard import Denied

def compare():
    with tempfile.TemporaryDirectory(prefix='ci-v15-comparator-') as td:
        root=Path(td)/'protected';root.mkdir(mode=0o700)
        old=ApprovalLedger(root/'old.db')
        key=Ed25519PrivateKey.generate()
        pub={'test':key.public_key().public_bytes(serialization.Encoding.Raw,
                serialization.PublicFormat.Raw).hex()}
        base={'repository':'demo/safe','run_id':12,'artifact_id':13,
              'commit_sha':'a'*40,'content_sha256':'b'*64,
              'recipient':'spiffe://ci-trace.test/consumer'}
        token=issue_signed_grant(old,key,'test',base,ttl=60)
        old.reserve(token,pub,base['recipient'])
        state=old.state(token['record']['grant_id'])
        try:
            old.reserve(token,pub,base['recipient'])
            old_result='accepted_twice'
        except Denied:old_result='denied_to_avoid_duplicate'
        new=AtomicEffectSink(root/'new.db')
        signers={role:Ed25519PrivateKey.generate() for role in ROLES}
        trust={role:{'key_id':role,'public_hex':signers[role].public_key().public_bytes(
               serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()}
               for role in ROLES}
        subject={**base,'operation_id':'f'*64,'effect_name':'increment_inert_counter',
                 'effect_value':1,'epoch':0}
        proof={'subject':subject,'signatures':{role:{'key_id':role,
               'signature':base64.b64encode(signers[role].sign(canonical(subject))).decode()}
               for role in ROLES}}
        try:new.execute(proof,trust,subject,interrupt='after_commit')
        except Denied:pass
        outcome=new.execute(proof,trust,subject)
        assert new.inspect()['effects']==new.inspect()['value']==1
        return {'V14_unknown_state':state,'V14_retry':old_result,
                'V15_rediscovered_effect_receipt':outcome['status'],
                'V15_actual_effects':new.inspect()['effects'],
                'scope':'single transactional SQLite effect; not arbitrary external side effects'}
if __name__=='__main__':print(json.dumps(compare(),indent=2))
