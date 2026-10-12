"""V15 fault injection: exactly-once SQLite effect, NOT network delivery."""
import argparse
import base64
import hashlib
import json
import statistics
import tempfile
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ci_trace.quorum_effect_v15 import AtomicEffectSink,ROLES,canonical
from ci_trace.provenance_guard import Denied

def measure(cases=300):
    assert cases>0 and cases%3==0
    keys={r:Ed25519PrivateKey.generate() for r in ROLES}
    trust={r:{'key_id':r+'-key','public_hex':keys[r].public_key().public_bytes(
          serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()} for r in ROLES}
    metrics={'initial_before_commit_faults':0,'initial_after_commit_ack_losses':0,
             'normal_requests':0,'retry_receipts_returned':0}
    times=[]
    with tempfile.TemporaryDirectory(prefix='ci-v15-faults-') as td:
        directory=Path(td)/'protected';directory.mkdir(mode=0o700)
        sink=AtomicEffectSink(directory/'effects.db')
        for i in range(cases):
            subject={'operation_id':hashlib.sha256(('case-%d'%i).encode()).hexdigest(),
              'repository':'example/demo','run_id':4,'artifact_id':5,
              'commit_sha':'a'*40,'content_sha256':'b'*64,
              'recipient':'spiffe://ci-trace.test/inert-sink',
              'effect_name':'increment_inert_counter','effect_value':1,'epoch':0}
            proof={'subject':subject,'signatures':{r:{'key_id':r+'-key',
              'signature':base64.b64encode(keys[r].sign(canonical(subject))).decode()}
              for r in ROLES}}
            fault='before_effect' if i%3==0 else 'after_commit' if i%3==1 else None
            t=time.perf_counter_ns()
            if fault:
                try:
                    sink.execute(proof,trust,subject,interrupt=fault)
                    raise AssertionError('fault not observed')
                except Denied as exc:
                    assert str(exc).startswith('simulated_')
                if fault=='before_effect':metrics['initial_before_commit_faults']+=1
                else:metrics['initial_after_commit_ack_losses']+=1
            else:metrics['normal_requests']+=1
            receipt=sink.execute(proof,trust,subject)
            assert sink.execute(proof,trust,subject)==receipt
            metrics['retry_receipts_returned']+=1
            times.append((time.perf_counter_ns()-t)/1e6)
        snap=sink.inspect()
        assert snap['value']==cases and snap['effects']==cases
    metrics.update({'cases':cases,'database_effects':snap['effects'],
      'duplicate_database_effects':0,
      'median_case_ms':round(statistics.median(times),3),
      'p95_case_ms':round(sorted(times)[int(.95*(len(times)-1))],3)})
    return metrics
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--cases',type=int,default=300)
    a=p.parse_args()
    print(json.dumps({'design':'author-labeled benign single SQLite resource, not exploit incidence',
                      'metrics':measure(a.cases)},indent=2))
