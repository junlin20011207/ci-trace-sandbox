"""V13 issuer-side once-only sealed data broker, with kernel-credentialed request AND challenge.

SO_PASSCRED must be enabled on the listening socket before connections can
queue messages. At-most-once delivery: a crash after redemption burns grant.
Data-only API; no privileged execution or release authorization.
"""
import array
import json
import secrets
import socket
import struct
import time
from .provenance_guard import Denied, _require
from .authenticated_ipc_v12 import (
    kernel_peer,receive_authorized,NONCE_LEN,PROTOCOL,HEADER_MAX)

MAX_REQUEST=512

def bind_broker_listener(path,*,backlog=8):
    conn=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        conn.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        conn.bind(str(path))
        conn.listen(backlog)
        conn.settimeout(8)
        return conn
    except BaseException:
        conn.close()
        raise

def new_grant(ledger,expected_sha,client_uid,*,lifetime=30):
    _require(type(lifetime) in (int,float) and 0<lifetime<=3600,
             'invalid_grant_lifetime')
    grant_id=secrets.token_hex(32)
    ledger.issue(grant_id,expected_sha,client_uid,time.time()+lifetime)
    return grant_id

def _send_after_credentialed_challenge(conn,fd,proof,expected_peer):
    """Reject delegated socket nonce even AFTER a correctly-authenticated request."""
    nonce,controls,flags,_=conn.recvmsg(NONCE_LEN+1,
        socket.CMSG_SPACE(struct.calcsize('3i')),socket.MSG_CMSG_CLOEXEC)
    _require(not flags & (socket.MSG_TRUNC|socket.MSG_CTRUNC),
             'ipc_challenge_truncated')
    identities=[]
    for level,kind,item in controls:
        _require(level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS,
                 'ipc_challenge_ancillary_invalid')
        _require(len(item)>=struct.calcsize('3i'),'ipc_challenge_credential_invalid')
        pid,uid,gid=struct.unpack('3i',item[:struct.calcsize('3i')])
        identities.append({'pid':pid,'uid':uid,'gid':gid})
    _require(len(identities)==1 and identities[0]==expected_peer,
             'ipc_challenge_sender_mismatch')
    _require(len(nonce)==NONCE_LEN,'ipc_challenge_invalid')
    msg=json.dumps({'version':PROTOCOL,'challenge':nonce.hex(),
        'sha256':proof['sha256'],'length':proof['length']},
        separators=(',',':'),sort_keys=True).encode('ascii')
    _require(len(msg)<=HEADER_MAX,'ipc_header_too_large')
    sent=conn.sendmsg([msg],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,
        array.array('i',[fd]))])
    _require(sent==len(msg),'ipc_short_send')

def service_once(conn,ledger,fd,proof,*,trusted_expected_sha256):
    _require(conn.family==socket.AF_UNIX and
             conn.type & 0xf==socket.SOCK_SEQPACKET,
             'ipc_transport_must_be_seqpacket')
    _require(conn.gettimeout() is not None,'ipc_timeout_required')
    peer=kernel_peer(conn)
    _require(conn.getsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED)==1,
             'ipc_passcred_must_precede_connection')
    data,controls,flags,_=conn.recvmsg(MAX_REQUEST,
        socket.CMSG_SPACE(struct.calcsize('3i'))+socket.CMSG_SPACE(16),
        socket.MSG_CMSG_CLOEXEC)
    creds=[]
    try:
        _require(not(flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC)),
                 'ipc_request_truncated')
        for level,kind,item in controls:
            _require(level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS,
                     'ipc_request_ancillary_invalid')
            _require(len(item)>=struct.calcsize('3i'),
                     'ipc_request_credential_invalid')
            pid,uid,gid=struct.unpack('3i',item[:struct.calcsize('3i')])
            creds.append({'pid':pid,'uid':uid,'gid':gid})
        _require(len(creds)==1 and creds[0]==peer,
                 'ipc_request_sender_mismatch')
        def unique_pairs(pairs):
            obj={}
            for k,v in pairs:
                _require(k not in obj,'ipc_duplicate_key')
                obj[k]=v
            return obj
        try:
            req=json.loads(data.decode('utf8'),object_pairs_hook=unique_pairs)
        except (UnicodeError,json.JSONDecodeError) as exc:
            raise Denied('ipc_invalid_request') from exc
        _require(isinstance(req,dict) and set(req)=={'grant_id','version'}
                 and type(req['version']) is int and req['version']==1,
                 'ipc_request_schema_invalid')
        _require(isinstance(proof,dict) and
                 proof.get('sha256')==trusted_expected_sha256,
                 'broker_untrusted_proof')
        # SQL BEGIN IMMEDIATE linearizes competing claims before FD handoff.
        ledger.redeem(req['grant_id'],trusted_expected_sha256,peer['uid'])
        _send_after_credentialed_challenge(conn,fd,proof,peer)
        return {'status':'released','client_uid':peer['uid'],
                'client_pid':peer['pid'],'grant_id':req['grant_id']}
    except OSError as exc:
        raise Denied('ipc_request_failed') from exc

def claim_once(conn,grant_id,*,trusted_expected_sha256,
               allowed_broker_uid,allowed_broker_pid=None,max_bytes=1024*1024):
    _require(isinstance(grant_id,str) and len(grant_id)==64 and
             all(c in '0123456789abcdef' for c in grant_id),
             'invalid_grant_id')
    request=json.dumps({'grant_id':grant_id,'version':1},
        separators=(',',':')).encode()
    try:conn.sendall(request)
    except OSError as exc:raise Denied('ipc_request_send_failed') from exc
    return receive_authorized(conn,trusted_expected_sha256=trusted_expected_sha256,
        allowed_uid=allowed_broker_uid,allowed_pid=allowed_broker_pid,
        max_bytes=max_bytes)
