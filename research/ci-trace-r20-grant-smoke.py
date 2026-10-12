#!/usr/bin/env python3
"""R20 GitHub-hosted cryptographic smoke test. LAB-ONLY EPHEMERAL KEYS.
This code does not issue real approvals or hold any Gitee credentials.
The complete prototype and adversarial suite are delivered separately.
"""
import json,time,copy,hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
DOMAIN=b'CI-TRACE:R20:RELEASE-GRANT:V1\x00'
BOUND=('repository_id','repository','source_sha','source_workflow_ref',
       'artifact_sha256','gitee_repo','target_ref','target_base_sha',
       'operation_id','approver_policy_id')
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def is_allowed(bundle,trust,expected,now):
    try:
        p=bundle['payload']
        if set(bundle)!={'payload','signature_hex'}:return False
        if set(p)!=set(BOUND)|{'schema_version','issuer_key_id','policy_revision','issued_at','expires_at','grant_id'}:return False
        if any(p[k]!=expected[k] for k in BOUND):return False
        if p['schema_version']!=1 or p['policy_revision']!=trust['policy_revision']:return False
        if p['grant_id'] in trust['revoked_grants']:return False
        if type(p['issued_at'])!=int or type(p['expires_at'])!=int:return False
        if not 0<p['expires_at']-p['issued_at']<=180:return False
        if now<p['issued_at']-10 or now>=p['expires_at']:return False
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub=trust['issuers'][p['issuer_key_id']]
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
            bytes.fromhex(bundle['signature_hex']),DOMAIN+canon(p))
        return True
    except (KeyError,TypeError,ValueError,InvalidSignature):return False
key=Ed25519PrivateKey.generate()
pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
now=int(time.time())
expected=dict(repository_id='1414105644',repository='junlin20011207/ci-trace-sandbox',
 source_sha='a'*40,source_workflow_ref='lab-workflow',artifact_sha256=hashlib.sha256(b'fixture').hexdigest(),
 gitee_repo='https://gitee.com/liljunlin/test.git',target_ref='refs/heads/research/ci-trace-lab',
 target_base_sha='b'*40,operation_id='operation-00001',approver_policy_id='policy-lab-only')
trust={'issuers':{'LAB-ONLY':pub},'policy_revision':3,'revoked_grants':[]}
payload=dict(expected,schema_version=1,issuer_key_id='LAB-ONLY',policy_revision=3,
 issued_at=now-1,expires_at=now+100,grant_id='lab-grant-0001')
signed={'payload':payload,'signature_hex':key.sign(DOMAIN+canon(payload)).hex()}
assert is_allowed(signed,trust,expected,now)
print('EPHEMERAL_ED25519_GRANT_VALID=yes')
tampered=copy.deepcopy(signed);tampered['payload']['target_ref']='refs/heads/main'
assert not is_allowed(tampered,trust,expected,now)
print('MODIFIED_DESTINATION_DENIED=yes')
assert not is_allowed(signed,trust,expected,now+110)
print('EXPIRED_GRANT_DENIED=yes')
revoked=copy.deepcopy(trust);revoked['revoked_grants']=[payload['grant_id']]
assert not is_allowed(signed,revoked,expected,now)
print('REVOKED_GRANT_DENIED=yes')
wrong=Ed25519PrivateKey.generate()
wrongpub=wrong.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
faket=copy.deepcopy(trust);faket['issuers']['LAB-ONLY']=wrongpub
assert not is_allowed(signed,faket,expected,now)
print('UNTRUSTED_SIGNING_KEY_DENIED=yes')
print('REAL_INDEPENDENT_APPROVER_PRESENT=no')
