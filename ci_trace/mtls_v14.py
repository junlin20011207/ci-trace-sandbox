"""V14 experimental TCP/TLS1.3 mTLS data-only transfer with one-use grant.

SAN URI service identities are checked separately from the TLS CA. This is
not a SPIFFE workload API implementation, cross-host deployment or HSM.
"""
import hashlib
import json
import socket
import ssl
import struct
from cryptography import x509
from .approval_v14 import verify_signed_grant
from .provenance_guard import Denied,_require
MAX_FRAME=2*1024*1024

def identity_from_peer(cert):
    _require(cert,'peer_certificate_required')
    obj=x509.load_der_x509_certificate(cert)
    try:
        uris=obj.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value.get_values_for_type(
            x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound as e:
        raise Denied('peer_spiffe_identity_missing') from e
    _require(len(uris)==1 and uris[0].startswith('spiffe://'),
             'peer_spiffe_identity_invalid')
    return uris[0]

def send_frame(conn,payload):
    data=(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
          if isinstance(payload,dict) else payload)
    _require(type(data) is bytes and len(data)<=MAX_FRAME,'frame_too_large')
    conn.sendall(struct.pack('!I',len(data))+data)

def _exact(conn,count):
    data=bytearray()
    while len(data)<count:
        part=conn.recv(count-len(data))
        if not part:raise Denied('tls_connection_ended')
        data.extend(part)
    return bytes(data)

def receive_frame(conn):
    size=struct.unpack('!I',_exact(conn,4))[0]
    _require(size<=MAX_FRAME,'frame_too_large')
    return _exact(conn,size)

def parse_json(payload):
    def unique(pairs):
        result={}
        for k,v in pairs:
            _require(k not in result,'duplicate_protocol_key')
            result[k]=v
        return result
    try:result=json.loads(payload.decode(),object_pairs_hook=unique)
    except (UnicodeError,json.JSONDecodeError) as e:
        raise Denied('invalid_protocol_json') from e
    _require(type(result) is dict,'protocol_mapping_required')
    return result

def serve_authenticated_client(conn,ledger,trust,trusted_bytes,
                               *,fail_after_reserve=False,now=None):
    conn.settimeout(5)
    identity=identity_from_peer(conn.getpeercert(binary_form=True))
    packet=parse_json(receive_frame(conn))
    _require(set(packet)=={'grant'},'invalid_grant_request')
    token=packet['grant']
    rec=verify_signed_grant(token,trust,now=now)
    _require(rec['recipient']==identity,'recipient_not_authorized')
    _require(type(trusted_bytes) is bytes and len(trusted_bytes)<=MAX_FRAME and
             hashlib.sha256(trusted_bytes).hexdigest()==rec['content_sha256'],
             'issuer_data_digest_mismatch')
    ledger.reserve(token,trust,identity,now=now)
    if fail_after_reserve:
        return {'status':'crash_injected_after_reservation','state':'uncertain'}
    send_frame(conn,{'status':'data','grant_id':rec['grant_id'],'length':len(trusted_bytes)})
    send_frame(conn,trusted_bytes)
    try:
        ack=parse_json(receive_frame(conn))
        _require(ack=={'ack':rec['grant_id']},'ack_invalid')
        ledger.acknowledge(rec['grant_id'],identity)
    except (Denied,OSError,ssl.SSLError):
        return {'status':'delivery_uncertain','state':ledger.state(rec['grant_id'])}
    return {'status':'acknowledged','state':ledger.state(rec['grant_id'])}

def receive_from_authority(conn,grant,trust,expected_issuer_identity,
                           *,expected_digest=None,send_ack=True,now=None):
    conn.settimeout(5)
    peer=identity_from_peer(conn.getpeercert(binary_form=True))
    _require(peer==expected_issuer_identity,'untrusted_issuer_identity')
    rec=verify_signed_grant(grant,trust,now=now)
    if expected_digest is not None:
        _require(rec['content_sha256']==expected_digest,'unexpected_approval_digest')
    send_frame(conn,{'grant':grant})
    response=parse_json(receive_frame(conn))
    _require(set(response)=={'status','grant_id','length'} and
             response['status']=='data' and
             response['grant_id']==rec['grant_id'] and
             type(response['length']) is int and 0<=response['length']<=MAX_FRAME,
             'invalid_data_response')
    data=receive_frame(conn)
    _require(len(data)==response['length'] and
             hashlib.sha256(data).hexdigest()==rec['content_sha256'],
             'received_data_digest_mismatch')
    if send_ack:send_frame(conn,{'ack':rec['grant_id']})
    return data
