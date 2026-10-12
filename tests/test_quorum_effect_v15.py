"""Real signed quorum, fault injection and exactly-once database-effect tests."""
import base64
import concurrent.futures
import json
import os
import subprocess
import sys
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ci_trace.quorum_effect_v15 import (
    AtomicEffectSink,ROLES,canonical,load_protected_policy)
from ci_trace.provenance_guard import Denied

def sample(tmp_path):
    folder=tmp_path/'sink-only';folder.mkdir(mode=0o700)
    sink=AtomicEffectSink(folder/'effects.db')
    keys={role:Ed25519PrivateKey.generate() for role in ROLES}
    roots={role:{'key_id':role+'-key',
        'public_hex':keys[role].public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()}
        for role in ROLES}
    subject={'operation_id':'a'*64,'repository':'example/demo','run_id':12,
       'artifact_id':13,'commit_sha':'b'*40,'content_sha256':'c'*64,
       'recipient':'spiffe://ci-trace.test/sink',
       'effect_name':'increment_inert_counter','effect_value':1,'epoch':0}
    proof={'subject':subject,'signatures':{
        role:{'key_id':roots[role]['key_id'],
        'signature':base64.b64encode(keys[role].sign(canonical(subject))).decode()}
        for role in ROLES}}
    return sink,keys,roots,proof

def test_exactly_once_after_lost_ack(tmp_path):
    sink,keys,roots,proof=sample(tmp_path)
    with pytest.raises(Denied,match='simulated_lost_ack_after_commit'):
        sink.execute(proof,roots,proof['subject'],interrupt='after_commit')
    receipt=sink.execute(proof,roots,proof['subject'])
    assert receipt==sink.execute(proof,roots,proof['subject'])
    assert sink.inspect()['value']==sink.inspect()['effects']==1

def test_before_commit_rollback(tmp_path):
    sink,keys,roots,proof=sample(tmp_path)
    with pytest.raises(Denied,match='simulated_before_commit'):
        sink.execute(proof,roots,proof['subject'],interrupt='before_effect')
    assert sink.inspect()['value']==0
    assert sink.execute(proof,roots,proof['subject'])['value_after']==1

@pytest.mark.parametrize('field,value',[
   ('repository','other/repo'),('run_id',99),('artifact_id',99),
   ('commit_sha','d'*40),('content_sha256','e'*64),
   ('recipient','spiffe://ci-trace.test/other')])
def test_modified_approved_subject_denied(tmp_path,field,value):
    sink,keys,roots,proof=sample(tmp_path)
    modified=dict(proof['subject']);modified[field]=value
    with pytest.raises(Denied,match='approved_subject_mismatch'):
        sink.execute(proof,roots,modified)
    assert sink.inspect()['value']==0

def test_one_stolen_signing_key_insufficient(tmp_path):
    sink,keys,roots,proof=sample(tmp_path)
    modified=proof.copy()
    modified={'subject':dict(proof['subject']),
              'signatures':{k:dict(v) for k,v in proof['signatures'].items()}}
    modified['subject']['content_sha256']='f'*64
    modified['signatures']['security_approver']['signature']=base64.b64encode(
        keys['security_approver'].sign(canonical(modified['subject']))).decode()
    with pytest.raises(Denied,match='approver_signature_invalid'):
        sink.execute(modified,roots,modified['subject'])

def test_missing_signature_or_duplicate_key_rejected(tmp_path):
    sink,keys,roots,proof=sample(tmp_path)
    del proof['signatures']['release_approver']
    with pytest.raises(Denied,match='approval_quorum_missing'):
        sink.execute(proof,roots,proof['subject'])
    roots['release_approver']['public_hex']=roots['security_approver']['public_hex']
    with pytest.raises(Denied,match='independent_approvers_required'):
        sink.execute(proof,roots,proof['subject'])

def test_100_duplicate_claims_return_same_business_receipt(tmp_path):
    sink,keys,roots,proof=sample(tmp_path)
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        result=list(executor.map(lambda i:sink.execute(proof,roots,proof['subject']),range(100)))
    assert len({json.dumps(r,sort_keys=True) for r in result})==1
    assert sink.inspect()['value']==1

def test_revoke_uncommitted_but_reconcile_committed(tmp_path):
    sink,keys,roots,proof=sample(tmp_path)
    sink.revoke_outstanding()
    with pytest.raises(Denied,match='approval_epoch_revoked'):
        sink.execute(proof,roots,proof['subject'])
    assert sink.inspect()['value']==0

def test_protected_trust_roots_reject_checkout(tmp_path):
    sink,keys,roots,proof=sample(tmp_path)
    checkout=tmp_path/'checkout';checkout.mkdir()
    config=checkout/'policy.json'
    config.write_text(json.dumps({'trust':roots,'expected_subject':proof['subject']}))
    config.chmod(0o600)
    with pytest.raises(Denied,match='untrusted_policy_in_checkout'):
        load_protected_policy(config,checkout)
    protected=tmp_path/'roots';protected.mkdir(mode=0o700)
    proper=protected/'policy.json';proper.write_text(config.read_text());proper.chmod(0o600)
    assert load_protected_policy(proper,checkout)['trust']==roots

def test_child_crash_after_commit_then_retry_same_effect(tmp_path):
    sink,keys,roots,proof=sample(tmp_path)
    import pickle
    payload=tmp_path/'case.pkl'
    with payload.open('wb') as f:pickle.dump((proof,roots),f)
    code="""import os,pickle,sys
from ci_trace.quorum_effect_v15 import AtomicEffectSink
with open(sys.argv[2],'rb') as file: proof,roots=pickle.load(file)
sink=AtomicEffectSink(sys.argv[1])
try:sink.execute(proof,roots,proof['subject'],interrupt='after_commit')
finally:os._exit(137)
"""
    worker=subprocess.run([sys.executable,'-c',code,str(sink.path),str(payload)],
                          capture_output=True,text=True,timeout=10)
    assert worker.returncode==137,worker.stderr
    assert AtomicEffectSink(sink.path).execute(proof,roots,proof['subject'])['value_after']==1
    assert sink.inspect()['effects']==1

def test_peer_cannot_override_protected_verifier_roots(tmp_path):
    from ci_trace.quorum_effect_v15 import execute_with_protected_roots
    sink,keys,roots,proof=sample(tmp_path)
    checkout=tmp_path/'checkout';checkout.mkdir()
    protected=tmp_path/'pin';protected.mkdir(mode=0o700)
    file=protected/'policy.json'
    file.write_text(json.dumps({'trust':roots,'expected_subject':proof['subject']}))
    file.chmod(0o600)
    assert execute_with_protected_roots(sink,proof,file,checkout)['value_after']==1
    forged={'subject':proof['subject'],'signatures':{
       role:{'key_id':role+'-not-pinned','signature':'AA=='}
       for role in ROLES}}
    with pytest.raises(Denied,match='approval_role_key_mismatch'):
        execute_with_protected_roots(sink,forged,file,checkout)
