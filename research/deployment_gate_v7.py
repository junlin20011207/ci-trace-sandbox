#!/usr/bin/env python3
"""Prevent publication of trust-cut patches unless protected-main assumption is verified.

The gate is not a GitHub authorization substitute. The snapshot must be fetched
via an authenticated trustworthy channel and checked against current repo state;
caller-supplied JSON can be forged. It intentionally refuses when metadata is
unavailable, branch is unprotected or inherited rulesets remain unresolved.
"""
import argparse, json
from pathlib import Path

EXPECTED_REPO='junlin20011207/ci-trace-sandbox'

def assess(snapshot, repo=EXPECTED_REPO):
    # Only proofs with explicit, trusted API provenance are even considered.
    if snapshot.get('full_name') != repo or snapshot.get('default_branch') != 'main':
        return {'status':'REFUSED','reason':'repository or default-branch identity mismatch'}
    if snapshot.get('branch_api_status')!='verified' or snapshot.get('rulesets_api_status')!='verified':
        return {'status':'UNKNOWN','reason':'incomplete GitHub policy state; branch may be governed by hidden/inherited settings'}
    if snapshot.get('branch_protected') is not True:
        return {'status':'REFUSED','reason':'main not protected; protected-main publication obligation unverified'}
    if snapshot.get('actor_can_push_unreviewed') is not False:
        return {'status':'UNKNOWN','reason':'not proven that unreviewed actors cannot push main'}
    if snapshot.get('allow_untrusted_payloads') is not False:
        return {'status':'UNKNOWN','reason':'untrusted payloads have not been excluded from release producer'}
    return {'status':'PRECONDITIONS_ASSERTED','reason':'input assertions meet modeled assumptions; re-check authoritatively before deployment', 'warning':'Not a cryptographic proof of repository administration settings.'}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('snapshot');a=p.parse_args()
    r=assess(json.loads(Path(a.snapshot).read_text()));print(json.dumps(r,indent=2,ensure_ascii=False))
    raise SystemExit(0 if r['status']=='PRECONDITIONS_ASSERTED' else 2)
