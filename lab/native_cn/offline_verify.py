"""Standalone offline SM2/SM3 receipt verification.
Pinned fingerprint is an OUT-OF-BAND trust anchor; without it a replaced public
key+receipt could pass. The signed historical receipt does NOT assert that a
mutable remote Git ref still points to the same commit today.
"""
import argparse,hashlib,json,re,sys
from pathlib import Path
from .crypto_sm import canonical,verify,sm3,strict_json

def validate(grant,receipt,subject,pub_path,expected_public_sha256):
    try:
        pem=Path(pub_path).read_bytes()
        fingerprint=hashlib.sha256(pem).hexdigest()
        if not re.fullmatch(r'[0-9a-f]{64}',expected_public_sha256) or fingerprint!=expected_public_sha256:
            return False,'TRUST_ANCHOR_MISMATCH'
        if not verify(grant,pub_path,'grant') or not verify(receipt,pub_path,'receipt'):
            return False,'SIGNATURE_INVALID'
        grant_payload=grant['body']['payload'];receipt_payload=receipt['body']['payload']
        if grant_payload['subject']!=subject:return False,'SUBJECT_NOT_APPROVED'
        if set(receipt_payload)!={'operation_id','recipient','platform','target_platform','target_ref',
            'base_sha','actual_commit_sha','artifact_sm3','source_commit_sha','workflow_identity',
            'execution_backend','business_authority',
            'confirmed_at','grant_sm3'}:return False,'RECEIPT_SCHEMA'
        for key in ('operation_id','recipient','target_ref','base_sha','artifact_sm3','source_commit_sha','workflow_identity'):
            if receipt_payload[key]!=subject[key]:return False,'RECEIPT_SUBJECT_MISMATCH'
        if receipt_payload['grant_sm3']!=sm3(canonical(grant)):
            return False,'RECEIPT_NOT_BOUND_TO_GRANT'
        if receipt_payload['execution_backend']!='ISOLATED_LOCAL_GIT_FIXTURE':
            return False,'UNEXPECTED_BACKEND'
        if receipt_payload['business_authority']!='EPHEMERAL_LAB_ISSUER_NOT_REAL_COMPANY':
            return False,'UNEXPECTED_AUTHORITY'
        return True,'VALID_HISTORICAL_LAB_RECEIPT_NOT_CURRENT_REMOTE_STATE'
    except (OSError,ValueError,KeyError,TypeError,UnicodeError):
        return False,'INVALID_DOCUMENT'

def main():
    p=argparse.ArgumentParser();p.add_argument('--grant',required=True);p.add_argument('--receipt',required=True)
    p.add_argument('--subject',required=True);p.add_argument('--issuer-public',required=True)
    p.add_argument('--trusted-sha256',required=True)
    args=p.parse_args()
    try:
        grant=strict_json(Path(args.grant).read_bytes());receipt=strict_json(Path(args.receipt).read_bytes());subject=strict_json(Path(args.subject).read_bytes())
        allowed,reason=validate(grant,receipt,subject,args.issuer_public,args.trusted_sha256)
    except (OSError,ValueError,TypeError):allowed,reason=False,'INVALID_DOCUMENT'
    print(json.dumps({'valid':allowed,'reason':reason},ensure_ascii=False,sort_keys=True))
    return 0 if allowed else 2
if __name__=='__main__':sys.exit(main())
