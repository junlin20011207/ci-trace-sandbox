"""Linux experimental isolated key agent.

Issuer is a separate OS principal; authorized requests use kernel UID/PID,
not human identity. No real production HSM or approval governance claimed.
"""
import json,os,socket,struct
from .provenance_guard import Denied,_require

MAX_REQUEST=4096
def listener(path):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        s.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        s.bind(str(path))
        os.chmod(path,0o666)
        s.listen(8);s.settimeout(5)
        return s
    except BaseException:
        s.close();raise

def serve_one(sock,issuer,*,permitted_approver_uid):
    _require(type(permitted_approver_uid) is int and permitted_approver_uid>=0,
             'invalid_approver_uid')
    conn,_=sock.accept()
    try:
        conn.settimeout(5)
        peer=struct.unpack('3i',conn.getsockopt(
            socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
        data,anc,flags,_=conn.recvmsg(MAX_REQUEST,
            socket.CMSG_SPACE(struct.calcsize('3i')),socket.MSG_CMSG_CLOEXEC)
        _require(not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC),
                 'issuer_message_truncated')
        actual=[struct.unpack('3i',v[:struct.calcsize('3i')]) for l,k,v in anc
                if l==socket.SOL_SOCKET and k==socket.SCM_CREDENTIALS]
        _require(len(actual)==1 and actual[0]==peer,'issuer_sender_mismatch')
        _require(peer[1]==permitted_approver_uid,'issuer_principal_denied')
        try:request=json.loads(data)
        except (ValueError,UnicodeError) as exc:raise Denied('issuer_request_invalid') from exc
        _require(type(request) is dict and set(request)=={'subject'},
                 'issuer_request_schema')
        grant=issuer.issue(request['subject'],ttl=120)
        blob=json.dumps(grant,sort_keys=True,separators=(',',':')).encode()
        _require(len(blob)<=MAX_REQUEST,'issuer_response_too_large')
        conn.sendall(blob)
        return {'issued':True,'caller_uid':peer[1],'caller_pid':peer[0],
                'grant_id':grant['record']['grant_id']}
    finally:conn.close()

def request_signature(path,subject):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        s.settimeout(5);s.connect(str(path))
        s.sendall(json.dumps({'subject':subject}).encode())
        received=s.recv(MAX_REQUEST)
        _require(bool(received),'issuer_did_not_approve')
        return json.loads(received)
    finally:s.close()
