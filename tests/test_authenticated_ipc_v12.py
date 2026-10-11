"""Adversarial AF_UNIX/SCM_RIGHTS protocol tests on real Linux sockets."""
import array
import hashlib
import json
import os
import socket
import subprocess
import sys
import textwrap
import threading
import pytest
from ci_trace.provenance_guard import Denied
from ci_trace.sealed_handoff_v11 import seal_bytes
from ci_trace.authenticated_ipc_v12 import receive_authorized,send_sealed

GOOD=b'authenticated inert test data'
GOOD_SHA=hashlib.sha256(GOOD).hexdigest()

def pair(mode='good',contents=GOOD):
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    left.settimeout(4);right.settimeout(4)
    errors=[]
    def sender():
        fd,proof=seal_bytes(contents)
        try:
            if mode in ('replay','duplicate','extra_fd','bad_version','oversize'):
                nonce=right.recv(33)
                header={'version':1,'challenge':nonce.hex(),
                        'sha256':proof['sha256'],'length':proof['length']}
                if mode=='replay':header['challenge']='00'*32
                if mode=='bad_version':header['version']=2
                raw=json.dumps(header).encode()
                if mode=='duplicate':
                    raw=raw.replace(b'"length"',b'"sha256":"'+
                       proof['sha256'].encode()+b'","length"')
                if mode=='oversize':raw=b'X'*2000
                fds=[fd,fd] if mode=='extra_fd' else [fd]
                right.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
                                      array.array('i',fds))])
            else:
                send_sealed(right,fd,proof,allowed_receiver_uid=os.getuid())
        except Exception as e:errors.append(e)
        finally:os.close(fd);right.close()
    thread=threading.Thread(target=sender,daemon=True)
    thread.start()
    return left,thread,errors

def test_authorized_connected_data():
    sock,thread,errors=pair()
    try:
        data,peer=receive_authorized(sock,trusted_expected_sha256=GOOD_SHA,
                                      allowed_uid=os.getuid())
        assert data==GOOD and peer['uid']==os.getuid()
    finally:sock.close();thread.join(timeout=5)
    assert not errors

def test_forged_selfconsistent_content_denied():
    sock,thread,errors=pair(contents=b'forged unrelated bytes')
    try:
        with pytest.raises(Denied,match='handoff_not_authorized'):
            receive_authorized(sock,trusted_expected_sha256=GOOD_SHA,
                               allowed_uid=os.getuid())
    finally:sock.close();thread.join(timeout=5)
    assert not errors

@pytest.mark.parametrize('mode,reason',[
 ('replay','ipc_challenge_mismatch'),
 ('duplicate','ipc_duplicate_key'),
 ('extra_fd','ipc_expected_single_fd'),
 ('bad_version','ipc_protocol_version_mismatch'),
 ('oversize','ipc_truncated_message'),
])
def test_message_falsifications(mode,reason):
    sock,thread,errors=pair(mode)
    try:
        with pytest.raises(Denied,match=reason):
            receive_authorized(sock,trusted_expected_sha256=GOOD_SHA,
                               allowed_uid=os.getuid())
    finally:sock.close();thread.join(timeout=5)
    assert not errors

def test_wrong_uid_denied_before_challenge():
    sock,thread,errors=pair()
    try:
        with pytest.raises(Denied,match='ipc_peer_uid_denied'):
            receive_authorized(sock,trusted_expected_sha256=GOOD_SHA,
                               allowed_uid=os.getuid()+1)
    finally:sock.close();thread.join(timeout=5)

def test_wrong_pid_denied_before_challenge():
    sock,thread,errors=pair()
    try:
        with pytest.raises(Denied,match='ipc_peer_pid_denied'):
            receive_authorized(sock,trusted_expected_sha256=GOOD_SHA,
                               allowed_uid=os.getuid(),allowed_pid=99999999)
    finally:sock.close();thread.join(timeout=5)

def test_sender_rejects_wrong_receiver_uid():
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    left.settimeout(4);right.settimeout(4)
    fd,proof=seal_bytes(b'INERT')
    try:
        with pytest.raises(Denied,match='ipc_receiver_uid_denied'):
            send_sealed(right,fd,proof,allowed_receiver_uid=os.getuid()+1)
    finally:left.close();right.close();os.close(fd)

def test_sender_rejects_wrong_receiver_pid():
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    left.settimeout(4);right.settimeout(4)
    fd,proof=seal_bytes(b'INERT')
    try:
        with pytest.raises(Denied,match='ipc_receiver_pid_denied'):
            send_sealed(right,fd,proof,allowed_receiver_uid=os.getuid(),
                        allowed_receiver_pid=99999999)
    finally:left.close();right.close();os.close(fd)

def test_finite_timeout_required():
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        with pytest.raises(Denied,match='ipc_timeout_required'):
            receive_authorized(left,trusted_expected_sha256=GOOD_SHA,
                               allowed_uid=os.getuid())
    finally:left.close();right.close()

def test_real_peer_pid_from_separate_process(tmp_path):
    path=str(tmp_path/'test.sock')
    server=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    server.bind(path);server.listen(1);server.settimeout(5)
    program=textwrap.dedent("""
        import socket,os,sys
        from ci_trace.sealed_handoff_v11 import seal_bytes
        from ci_trace.authenticated_ipc_v12 import send_sealed
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        sock.settimeout(5);sock.connect(sys.argv[1])
        fd,proof=seal_bytes(b'authenticated inert test data')
        try:send_sealed(sock,fd,proof,allowed_receiver_uid=os.getuid())
        finally:os.close(fd);sock.close()
    """)
    child=subprocess.Popen([sys.executable,'-c',program,path],
                           stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        conn,_=server.accept()
        with conn:
            conn.settimeout(5)
            data,peer=receive_authorized(conn,trusted_expected_sha256=GOOD_SHA,
                allowed_uid=os.getuid(),allowed_pid=child.pid)
        assert data==GOOD and peer['pid']==child.pid
        stdout,stderr=child.communicate(timeout=6)
        assert child.returncode==0,stderr
    finally:
        if child.poll() is None:child.kill();child.communicate()
        server.close()
