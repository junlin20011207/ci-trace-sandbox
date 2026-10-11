"""Compare V10 raw-path MISUSE, correct V10 reader, and kernel-sealed V11 handle."""
import hashlib
import json
import os
import tempfile
from pathlib import Path
from ci_trace.provenance_guard import Denied
from ci_trace.sealed_handoff_v11 import seal_bytes, consume_sealed_fd
from ci_trace.verified_reader_v10 import read_verified_member

def compare(rounds=30):
    assert 1 <= rounds <= 1000
    result={'rounds':rounds,'v10_raw_path_misuse_wrong':0,
            'v10_manifest_reader_denied':0,'v11_fd_correct':0,
            'v11_mutation_denied':0}
    for i in range(rounds):
        with tempfile.TemporaryDirectory(prefix='sealed-handoff-') as d:
            folder=Path(d); release=folder/'release'; release.mkdir()
            path=release/'record.json'
            good=json.dumps({'value':'VALID','case':i},sort_keys=True).encode()
            bad=json.dumps({'value':'EVILL','case':i},sort_keys=True).encode()
            path.write_bytes(good)
            report={'status':'approved','snapshot_type':'immutable_bytes',
                    'release_dir':str(release), 'file_manifest':[{'path':'record.json',
                     'bytes':len(good),'sha256':hashlib.sha256(good).hexdigest()}]}
            sealed,proof=seal_bytes(read_verified_member(report,'record.json'))
            try:
                path.write_bytes(bad)
                if path.read_bytes()==bad:result['v10_raw_path_misuse_wrong']+=1
                try:read_verified_member(report,'record.json')
                except Denied:result['v10_manifest_reader_denied']+=1
                if consume_sealed_fd(sealed,proof)==good:result['v11_fd_correct']+=1
                try:os.pwrite(sealed,bad,0)
                except OSError:result['v11_mutation_denied']+=1
            finally:os.close(sealed)
    return result

if __name__=='__main__':
    r=compare()
    print(json.dumps({'kind':'deterministic path misuse vs compliant V10 reader vs V11 sealed FD',
                      'metrics':r},indent=2))
    assert all(v==r['rounds'] for k,v in r.items() if k!='rounds')
