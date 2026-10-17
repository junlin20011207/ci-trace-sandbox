"""CI-TRACE R20 proof-of-concept signed release gate (NO deployment credentials).

This verifier is not a trusted root by itself. The verifier, trust policy and
Git credentials MUST reside in a separate immutable trust domain from the
repository/workflow that proposes the release. Offline revocations cannot be
immediate without an independently fresh trust epoch or online checking.
"""
from __future__ import annotations
import hashlib
import math
import json
import re
import time
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b"CI-TRACE:R20:RELEASE-GRANT:V1\0"
EXPECTED_FIELDS = frozenset({
    'repository_id', 'repository', 'source_sha', 'source_workflow_ref',
    'artifact_sha256', 'gitee_repo', 'target_ref', 'target_base_sha',
    'operation_id', 'approver_policy_id'
})
PAYLOAD_FIELDS = EXPECTED_FIELDS | frozenset({
    'schema_version', 'issuer_key_id', 'policy_revision', 'issued_at',
    'expires_at', 'grant_id'
})
HEX40 = re.compile(r'^[0-9a-f]{40}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
OP_ID = re.compile(r'^[a-zA-Z0-9_.:-]{8,100}$')
REF = re.compile(r'^refs/heads/research/[a-zA-Z0-9._/-]{1,120}$')


def _pairs_unique(pairs):
    obj = {}
    for k,v in pairs:
        if k in obj:
            raise ValueError('duplicate JSON key')
        obj[k] = v
    return obj


def _finite_float(raw):
    value=float(raw)
    if not math.isfinite(value):
        raise ValueError('non-finite float')
    return value


def parse_json_strict(raw: bytes) -> dict:
    if len(raw) > 32768:
        raise ValueError('oversized JSON')
    o = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs_unique,
                   parse_constant=lambda x: (_ for _ in ()).throw(ValueError('non-finite number')),
                   parse_float=lambda x: _finite_float(x))
    if not isinstance(o, dict):
        raise ValueError('non-object JSON')
    return o


def canon(x: Any) -> bytes:
    return json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def check_expected(expected: dict):
    if not isinstance(expected, dict) or set(expected) != EXPECTED_FIELDS:
        raise ValueError('expected-field mismatch')
    if not all(isinstance(x, str) and x for x in expected.values()):
        raise ValueError('invalid expected string')
    if not re.fullmatch(r'[0-9]{1,20}', expected['repository_id']):
        raise ValueError('invalid repository id')
    if not HEX40.fullmatch(expected['source_sha']):
        raise ValueError('invalid SHA-1 commit id')
    if not HEX40.fullmatch(expected['target_base_sha']):
        raise ValueError('invalid SHA-1 base id')
    if not HEX64.fullmatch(expected['artifact_sha256']):
        raise ValueError('invalid artifact SHA-256')
    if not REF.fullmatch(expected['target_ref']) or '..' in expected['target_ref'] or '//' in expected['target_ref'] or '/.' in expected['target_ref'] or expected['target_ref'].endswith('.lock') or expected['target_ref'].endswith('/'):
        raise ValueError('invalid research ref')
    if not OP_ID.fullmatch(expected['operation_id']):
        raise ValueError('invalid operation ID')
    if expected['gitee_repo'] != 'https://gitee.com/liljunlin/test.git':
        raise ValueError('unexpected Gitee repo')
    if not expected['source_workflow_ref'].startswith(expected['repository'] + '/.github/workflows/'):
        raise ValueError('mismatched workflow provenance')


def verify(grant: dict, trust: dict, expected: dict, now: int | None = None) -> tuple[bool, str]:
    """No external side effects. The caller must not publish on any denial."""
    try:
        check_expected(expected)
        if not isinstance(grant, dict) or set(grant) != {'payload','signature_hex'}:
            return False, 'grant_shape'
        payload=grant['payload']
        if not isinstance(payload, dict) or set(payload) != PAYLOAD_FIELDS:
            return False, 'payload_shape'
        if not isinstance(trust, dict) or set(trust) != {'schema_version','issuers','policy_revision','revoked_grants','max_ttl_seconds','max_clock_skew_seconds'}:
            return False, 'trust_shape'
        if type(trust['schema_version']) is not int or trust['schema_version'] != 1:
            return False, 'trust_schema'
        if type(payload['schema_version']) is not int or payload['schema_version'] != 1:
            return False, 'grant_schema'
        if type(trust['policy_revision']) is not int or type(payload['policy_revision']) is not int or trust['policy_revision'] != payload['policy_revision']:
            return False, 'policy_revision'
        if any(payload.get(f) != expected[f] for f in EXPECTED_FIELDS):
            return False, 'bound_subject_mismatch'
        if any(type(payload[f]) is not str for f in EXPECTED_FIELDS):
            return False, 'bad_field_type'
        if not isinstance(payload['grant_id'], str) or not OP_ID.fullmatch(payload['grant_id']):
            return False, 'grant_id'
        if not isinstance(trust['revoked_grants'], list) or any(not isinstance(x,str) for x in trust['revoked_grants']):
            return False,'revocation_shape'
        if payload['grant_id'] in trust['revoked_grants']:
            return False, 'revoked'
        if type(payload['issued_at']) is not int or type(payload['expires_at']) is not int:
            return False, 'time_shape'
        if type(trust['max_ttl_seconds']) is not int or type(trust['max_clock_skew_seconds']) is not int:
            return False,'time_policy_shape'
        ttl=payload['expires_at']-payload['issued_at']
        if not 0 < ttl <= min(trust['max_ttl_seconds'], 300):
            return False, 'ttl_invalid'
        if not 0 <= trust['max_clock_skew_seconds'] <= 15:
            return False,'clock_policy'
        t=int(time.time()) if now is None else now
        if type(t) is not int:
            return False, 'clock_invalid'
        if t < payload['issued_at']-trust['max_clock_skew_seconds']:
            return False, 'not_yet_valid'
        if t >= payload['expires_at']:
            return False, 'expired'
        if not isinstance(trust['issuers'], dict):
            return False,'issuer_map'
        key_id=payload['issuer_key_id']
        pub_hex=trust['issuers'].get(key_id) if isinstance(key_id,str) else None
        if not isinstance(pub_hex,str) or not HEX64.fullmatch(pub_hex):
            return False,'untrusted_issuer'
        sighex=grant['signature_hex']
        if not isinstance(sighex,str) or not re.fullmatch(r'[0-9a-f]{128}',sighex):
            return False,'invalid_signature_format'
        pub=Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(bytes.fromhex(sighex), DOMAIN+canon(payload))
        return True,'VALID'
    except (InvalidSignature,ValueError,KeyError,TypeError,OverflowError) as e:
        return False,'invalid_signature_or_schema'
    except Exception:
        return False,'internal_fail_closed'


def make_grant_for_test_only(private_key, subject: dict, *, issue_time: int, expiration: int, grant_id='labgrant-0001', key_id='LAB-TEST-ONLY', revision=3):
    check_expected(subject)
    payload=dict(subject, schema_version=1, issuer_key_id=key_id, policy_revision=revision,
                 issued_at=issue_time, expires_at=expiration, grant_id=grant_id)
    return {'payload':payload,'signature_hex':private_key.sign(DOMAIN+canon(payload)).hex()}


def artifact_sha256(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

if __name__=='__main__':
    # Not a signing CLI. Only permits verification against explicitly supplied trusted file.
    import argparse, pathlib,sys
    p=argparse.ArgumentParser()
    p.add_argument('--grant',required=True)
    p.add_argument('--trust',required=True)
    p.add_argument('--expected',required=True)
    args=p.parse_args()
    try:
        grant=parse_json_strict(pathlib.Path(args.grant).read_bytes())
        trust=parse_json_strict(pathlib.Path(args.trust).read_bytes())
        expected=parse_json_strict(pathlib.Path(args.expected).read_bytes())
        yes, reason=verify(grant,trust,expected)
    except Exception:
        yes,reason=False,'invalid_input'
    print(json.dumps({'allow':yes,'reason':reason},sort_keys=True))
    sys.exit(0 if yes else 2)
