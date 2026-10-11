"""Ed25519-verified authorization package for GitHub Artifact release.

Trusted public keys MUST be pinned in protected, reviewed configuration outside
untrusted artifacts. This module does not authenticate the signer role itself.
"""
import base64
import binascii
import json
from datetime import datetime, timezone, timedelta
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .provenance_guard import Denied, _require
from .authorization_binding import verify_authorized_release

DOMAIN=b'CI-TRACE:APPROVAL:V1\n'
FIELDS=frozenset({'repository','run_id','artifact_name','commit_sha','purpose','issued_at','expires_at'})

def payload_bytes(record):
    _require(isinstance(record,dict), 'invalid_approval_record')
    _require(set(record)==FIELDS, 'unexpected_approval_fields')
    return DOMAIN+json.dumps(record,sort_keys=True,separators=(',',':'),
                             ensure_ascii=True,allow_nan=False).encode('ascii')

def parse_time(value):
    _require(isinstance(value,str), 'invalid_approval_time')
    try:
        when=datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError as exc:
        raise Denied('invalid_approval_time') from exc
    _require(when.tzinfo is not None, 'unqualified_approval_time')
    return when.astimezone(timezone.utc)

def verify_approval_package(package,trusted_keys,now=None):
    _require(isinstance(package,dict) and set(package)=={'key_id','record','signature'},
             'malformed_signed_approval')
    _require(isinstance(trusted_keys,dict), 'untrusted_key_source')
    key_id=package.get('key_id')
    _require(isinstance(key_id,str) and key_id in trusted_keys,'unknown_approval_key')
    key=trusted_keys[key_id]
    _require(isinstance(key,str),'invalid_trusted_key')
    try:
        pub=Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
        signature=base64.b64decode(package['signature'],validate=True)
        pub.verify(signature,payload_bytes(package['record']))
    except (TypeError,ValueError,binascii.Error,InvalidSignature) as exc:
        raise Denied('approval_signature_invalid') from exc
    record=package['record']
    _require(record['purpose']=='artifact_release','approval_purpose_mismatch')
    issued=parse_time(record['issued_at'])
    expires=parse_time(record['expires_at'])
    now=datetime.now(timezone.utc) if now is None else now
    _require(isinstance(now,datetime) and now.tzinfo is not None,'invalid_verifier_clock')
    now=now.astimezone(timezone.utc)
    _require(issued<=now<=expires,'approval_outside_validity')
    _require(issued<expires and expires-issued<=timedelta(days=7),
             'approval_validity_too_long')
    return record

def verify_signed_release(archive_path,event,artifact_api,policy,package,
                          trusted_keys,output_root,workspace,now=None):
    approval=verify_approval_package(package,trusted_keys,now=now)
    outcome=verify_authorized_release(archive_path,event,artifact_api,policy,
                                      approval,output_root,workspace)
    outcome['approval_signature']={'verified':True,'key_id':package['key_id'],
                                   'purpose':approval['purpose']}
    return outcome
