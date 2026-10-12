"""Cross-GitHub-hosted-runner V15 quorum smoke test, NOT trusted production signers.

Each signer job uses a separate ephemeral GitHub-hosted runner and creates a
test key; its public key travels with the signature, so this verifies runner
separation/transfer and protocol mechanics, NOT identity-independent approval.
"""
import argparse
import base64
import hashlib
import json
import os
import socket
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ci_trace.quorum_effect_v15 import canonical,verify_quorum,AtomicEffectSink,ROLES

def subject():
    commit=os.environ.get('GITHUB_SHA','a'*40)
    if len(commit)!=40:commit='a'*40
    return {'operation_id':hashlib.sha256(b'v15-pair-test-'+commit.encode()).hexdigest(),
      'repository':os.environ.get('GITHUB_REPOSITORY','junlin20011207/ci-trace-sandbox'),
      'run_id':41,'artifact_id':42,'commit_sha':commit,
      'content_sha256':hashlib.sha256(b'inert-cross-runner-proof').hexdigest(),
      'recipient':'spiffe://ci-trace.test/receiver',
      'effect_name':'increment_inert_counter','effect_value':1,'epoch':0}

def attestation(role):
    assert role in ROLES
    sk=Ed25519PrivateKey.generate()
    pb=sk.public_key().public_bytes(serialization.Encoding.Raw,
        serialization.PublicFormat.Raw).hex()
    record=subject()
    return {'role':role,'subject':record,
       'runner_hostname':socket.gethostname(),'runner_name':os.environ.get('RUNNER_NAME',''),
       'key_id':role+'-ephemeral-only','public_hex':pb,
       'signature':base64.b64encode(sk.sign(canonical(record))).decode()}

def sign(role,out):
    p=Path(out);p.mkdir(parents=True,exist_ok=True)
    (p/(role+'.json')).write_text(json.dumps(attestation(role),sort_keys=True))
    print(json.dumps({'role':role,'runner':socket.gethostname(),'ephemeral_only':True}))

def verify(folder):
    directory=Path(folder)
    assertions=[json.loads((directory/(role+'.json')).read_text()) for role in ROLES]
    expected=subject()
    assert all(p['subject']==expected for p in assertions)
    hosts=[p['runner_hostname'] for p in assertions]
    me=socket.gethostname()
    assert len(set(hosts+[me]))==3, 'GitHub runner hosts not independent'
    trust={p['role']:{'key_id':p['key_id'],'public_hex':p['public_hex']} for p in assertions}
    proof={'subject':expected,'signatures':{p['role']:{
          'key_id':p['key_id'],'signature':p['signature']} for p in assertions}}
    verify_quorum(proof,trust,expected)
    with tempfile.TemporaryDirectory(prefix='ci-trace-v15-runner-') as d:
        secure=Path(d)/'db';secure.mkdir(mode=0o700)
        sink=AtomicEffectSink(secure/'effect.db')
        for _ in range(30):sink.execute(proof,trust,expected)
        assert sink.inspect()['value']==sink.inspect()['effects']==1
    print(json.dumps({'security_runner':hosts[0],'release_runner':hosts[1],
       'verification_runner':me,'three_distinct_runner_hosts':True,
       'two_ephemeral_signatures_verified':True,
       'effect_count_after_30_retries':1,
       'not_a_production_authority':True},sort_keys=True))

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('action',choices=['sign','verify'])
    parser.add_argument('--role',choices=ROLES)
    parser.add_argument('--directory',required=True)
    args=parser.parse_args()
    if args.action=='sign':sign(args.role,args.directory)
    else:verify(args.directory)
