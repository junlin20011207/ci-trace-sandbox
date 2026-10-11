"""Real Linux UID-separation and delegated nonce experiments; skip if unprivileged."""
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
import pytest
from ci_trace.provenance_guard import Denied
from ci_trace.redeem_v13 import RedemptionLedger
from ci_trace.issuer_broker_v13 import (
    bind_broker_listener,new_grant,service_once,claim_once)
from ci_trace.sealed_handoff_v11 import seal_bytes

DATA=b'authorized-data-only'
SHA=hashlib.sha256(DATA).hexdigest()

def issuer():
    td=tempfile.TemporaryDirectory(prefix='ci-v13-',dir='/tmp')
    top=Path(td.name);os.chmod(top,0o755)
    private=top/'private';private.mkdir(mode=0o700)
    db=private/'grants.sqlite'
    ledger=RedemptionLedger(db)
    path=top/'issuer.sock'
    listener=bind_broker_listener(path,backlog=4)
    os.chmod(path,0o666)
    return td,db,ledger,path,listener

def start_client(path,grant,uid,db):
    code='''import json,os,socket,sys
from ci_trace.issuer_broker_v13 import claim_once
path,grant,digest,db=sys.argv[1:5]
try:
    try:open(db,'rb').read(1);protected=False
    except (PermissionError,OSError):protected=True
    s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(5)
    s.connect(path)
    data,peer=claim_once(s,grant,trusted_expected_sha256=digest,allowed_broker_uid=0)
    print(json.dumps({'status':'accepted','data':data.decode(),
        'db_protected':protected,'broker_uid':peer['uid']}))
except Exception as e:
    print(json.dumps({'status':'denied','reason':str(e)}))
'''
    def drop():
        os.setgid(uid)
        os.setuid(uid)
    return subprocess.Popen([sys.executable,'-c',code,str(path),grant,SHA,str(db)],
        preexec_fn=drop,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1])})

def serve_once(server,client,ledger,fd,proof):
    conn,_=server.accept();conn.settimeout(5)
    with conn:
        try:result=service_once(conn,ledger,fd,proof,
                                trusted_expected_sha256=SHA)
        except Denied as exc:result={'status':'denied','reason':str(exc)}
    stdout,stderr=client.communicate(timeout=7)
    assert client.returncode==0,stderr
    return result,json.loads(stdout)

@pytest.mark.skipif(os.geteuid()!=0,reason='requires root for real distinct UIDs')
def test_real_different_uid_and_one_use():
    td,db,ledger,path,server=issuer()
    fd,proof=seal_bytes(DATA)
    try:
        grant=new_grant(ledger,SHA,65534)
        first=start_client(path,grant,65534,db)
        broker,client=serve_once(server,first,ledger,fd,proof)
        assert broker['status']=='released'
        assert client=={'status':'accepted','data':DATA.decode(),
                        'db_protected':True,'broker_uid':0}
        replay=start_client(path,grant,65534,db)
        broker2,client2=serve_once(server,replay,ledger,fd,proof)
        assert broker2['reason']=='grant_not_redeemable'
        assert client2['status']=='denied'
    finally:os.close(fd);server.close();td.cleanup()

@pytest.mark.skipif(os.geteuid()!=0,reason='requires root for real distinct UIDs')
def test_wrong_uid_cannot_burn_grant():
    td,db,ledger,path,server=issuer()
    fd,proof=seal_bytes(DATA)
    try:
        grant=new_grant(ledger,SHA,65534)
        unauthorized=start_client(path,grant,1,db)
        failed,client=serve_once(server,unauthorized,ledger,fd,proof)
        assert failed['reason']=='grant_not_redeemable'
        assert client['status']=='denied'
        real=start_client(path,grant,65534,db)
        valid,c=serve_once(server,real,ledger,fd,proof)
        assert valid['status']=='released' and c['status']=='accepted'
    finally:os.close(fd);server.close();td.cleanup()

def test_delegated_nonce_after_valid_request_rejected():
    td,db,ledger,path,server=issuer()
    fd,proof=seal_bytes(DATA)
    delegate='''import socket,sys
from ci_trace.authenticated_ipc_v12 import receive_authorized
sock=socket.socket(fileno=int(sys.argv[1]));sock.settimeout(4)
try:receive_authorized(sock,trusted_expected_sha256=sys.argv[2],allowed_uid=0)
except Exception:pass
finally:sock.close()
'''
    owner='''import json,socket,subprocess,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(5)
s.connect(sys.argv[1])
s.sendall(json.dumps({'grant_id':sys.argv[2],'version':1}).encode())
subprocess.run([sys.executable,'-c',sys.argv[3],str(s.fileno()),sys.argv[4]],
    pass_fds=(s.fileno(),),timeout=6,check=True)
s.close()
'''
    try:
        grant=new_grant(ledger,SHA,os.getuid())
        child=subprocess.Popen([sys.executable,'-c',owner,str(path),grant,delegate,SHA],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        conn,_=server.accept();conn.settimeout(5)
        with conn:
            with pytest.raises(Denied,match='ipc_challenge_sender_mismatch'):
                service_once(conn,ledger,fd,proof,trusted_expected_sha256=SHA)
        stdout,stderr=child.communicate(timeout=7)
        assert child.returncode==0,stderr
        with pytest.raises(Denied,match='grant_not_redeemable'):
            ledger.redeem(grant,SHA,os.getuid())
    finally:os.close(fd);server.close();td.cleanup()
