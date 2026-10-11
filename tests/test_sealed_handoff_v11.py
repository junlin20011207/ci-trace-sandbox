import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path
import pytest
from ci_trace.provenance_guard import Denied
from ci_trace.snapshot_guard_v10 import verify_and_extract_snapshot
from ci_trace.sealed_handoff_v11 import (seal_bytes, seal_verified_member,
    consume_sealed_fd, REQUIRED_SEALS)
from test_snapshot_v10 import fixture

def test_v11_sealing_prevents_mutations():
    fd, proof = seal_bytes(b'VALID')
    try:
        assert consume_sealed_fd(fd, proof) == b'VALID'
        assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & REQUIRED_SEALS == REQUIRED_SEALS
        for fn in [lambda: os.pwrite(fd,b'EVIL!',0),
                   lambda: os.ftruncate(fd, 0),
                   lambda: os.ftruncate(fd, 100)]:
            with pytest.raises(OSError):
                fn()
        assert consume_sealed_fd(fd, proof) == b'VALID'
    finally:
        os.close(fd)

def test_v11_immutable_cross_process_fd_transfer():
    fd, proof = seal_bytes(b'VALID')
    try:
        child = '''import os,sys,json,fcntl
from ci_trace.sealed_handoff_v11 import consume_sealed_fd
fd=int(sys.argv[1]); proof=json.loads(sys.argv[2]); data=consume_sealed_fd(fd,proof)
try: os.pwrite(fd,b"EVIL!",0); code="WRITABLE"
except OSError: code="SEALED"
print(json.dumps({"payload":data.decode(),"seal":code}))
'''
        result = subprocess.run([sys.executable,'-c',child,str(fd),json.dumps(proof)],
            pass_fds=(fd,),check=True,text=True,capture_output=True)
        assert json.loads(result.stdout) == {'payload':'VALID','seal':'SEALED'}
    finally:os.close(fd)

def test_v10_file_path_can_change_but_v11_fd_stays_trusted(tmp_path):
    arc, alt, event, api, policy, root, ws = fixture(tmp_path)[:7]
    record = verify_and_extract_snapshot(arc,event,api,policy,root,ws)
    fd, proof = seal_verified_member(record,'report.json')
    try:
        source=Path(record['release_dir'])/'report.json'
        assert json.loads(source.read_text()) == {'payload':'VALID'}
        source.write_text('{"payload": "EVILL"}')
        assert json.loads(source.read_text()) == {'payload':'EVILL'}
        assert json.loads(consume_sealed_fd(fd,proof)) == {'payload':'VALID'}
    finally:os.close(fd)

def test_oversize_rejected_without_fd_leak():
    with pytest.raises(Denied,match='handoff_size_exceeded'):
        seal_bytes(b'0123456789',limit=5)

def test_bad_proof_rejected():
    fd,proof=seal_bytes(b'DATA')
    try:
        proof['sha256']='0'*64
        with pytest.raises(Denied,match='handoff_digest_mismatch'):
            consume_sealed_fd(fd,proof)
    finally:os.close(fd)

def test_regular_unsealed_file_fd_rejected(tmp_path):
    target=tmp_path/'file.txt';target.write_bytes(b'VALID')
    with target.open('rb') as inp:
        with pytest.raises(Denied,match='handoff_read_failed|handoff_not_sealed'):
            consume_sealed_fd(inp.fileno(), {'sha256':'x','length':5})

def test_nonexec_memfd():
    fd,proof=seal_bytes(b'not executable')
    try:
        assert not (os.fstat(fd).st_mode & 0o111)
    finally:os.close(fd)


def test_forged_selfconsistent_sealed_fd_needs_trust_anchor():
    from ci_trace.sealed_handoff_v11 import consume_authorized_sealed_fd
    goodfd, goodproof = seal_bytes(b'ORIGINAL')
    forgedfd, forgedproof = seal_bytes(b'FORGERY!')
    try:
        # The original API established consistency, NOT authorization.
        assert consume_sealed_fd(forgedfd, forgedproof) == b'FORGERY!'
        with pytest.raises(Denied, match='handoff_not_authorized'):
            consume_authorized_sealed_fd(forgedfd,forgedproof,
                                         trusted_expected_sha256=goodproof['sha256'])
        assert consume_authorized_sealed_fd(goodfd, goodproof,
                trusted_expected_sha256=goodproof['sha256']) == b'ORIGINAL'
    finally:
        os.close(goodfd)
        os.close(forgedfd)

def test_invalid_trusted_digest_rejected():
    from ci_trace.sealed_handoff_v11 import consume_authorized_sealed_fd
    fd,proof=seal_bytes(b'INERT')
    try:
        with pytest.raises(Denied,match='invalid_trusted_digest'):
            consume_authorized_sealed_fd(fd,proof,trusted_expected_sha256='garbage')
    finally:os.close(fd)
