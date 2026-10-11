"""V14 hosted experimental checks; no production approval authority."""
import hashlib
import os
import concurrent.futures
import ssl
import socket
import threading
import json
from datetime import datetime,timedelta,timezone
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ci_trace.approval_v14 import ApprovalLedger,issue_signed_grant,ProtectedIssuer
from ci_trace.mtls_v14 import serve_authenticated_client,receive_from_authority
from ci_trace.provenance_guard import Denied

DATA=b'inert real TLS data'
SHA=hashlib.sha256(DATA).hexdigest()
A='spiffe://ci-trace.local/service-A'
B='spiffe://ci-trace.local/service-B'

def kit(tmp_path):
    folder=tmp_path/'protected';folder.mkdir(mode=0o700)
    ledger=ApprovalLedger(folder/'auth.sqlite')
    key=Ed25519PrivateKey.generate()
    pub={'issuer-v1':key.public_key().public_bytes(
        serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()}
    subject={'repository':'example/demo','run_id':12,'artifact_id':5,
             'commit_sha':'a'*40,'content_sha256':SHA,'recipient':A}
    issuer=ProtectedIssuer(ledger,key,'issuer-v1',[subject])
    token=issuer.issue(subject,ttl=120)
    return ledger,issuer,pub,token

def test_v14_signed_subject_recipient_and_revocation(tmp_path):
    ledger,issuer,pub,token=kit(tmp_path)
    with pytest.raises(Denied,match='recipient_not_authorized'):
        ledger.reserve(token,pub,B)
    for name,value in [('repository','other/repo'),('commit_sha','b'*40),
                       ('recipient',B),('run_id',999),('artifact_id',999),
                       ('content_sha256','f'*64)]:
        with pytest.raises(Denied,match='issuer_policy_denied'):
            issuer.issue({**token['record'],name:value})
    ledger.revoke_key('issuer-v1')
    with pytest.raises(Denied,match='approval_key_revoked'):
        ledger.reserve(token,pub,A)
    assert ledger.state(token['record']['grant_id'])=='granted'

def test_v14_one_hundred_claims_and_restart(tmp_path):
    ledger,issuer,pub,token=kit(tmp_path)
    def attempt(_):
        try:ledger.reserve(token,pub,A);return True
        except Denied:return False
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        assert sum(pool.map(attempt,range(100)))==1
    reopened=ApprovalLedger(ledger.path)
    assert reopened.state(token['record']['grant_id'])=='uncertain'
    with pytest.raises(Denied,match='grant_not_redeemable'):
        reopened.reserve(token,pub,A)

def certkit(tmp_path):
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    now=datetime.now(timezone.utc)
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Research CA')])
    root=x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
    root=root.public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
    root=root.not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=2))
    root=root.add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
    root=root.sign(ca_key,hashes.SHA256())
    (tmp_path/'ca.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
    certs={}
    for name,identity in [('server','spiffe://ci-trace.local/issuer'),('A',A),('B',B)]:
        priv=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)])
        builder=x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name)
        builder=builder.public_key(priv.public_key()).serial_number(x509.random_serial_number())
        builder=builder.not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
        uris=[x509.UniformResourceIdentifier(identity)]
        if name=='server':uris.append(x509.DNSName('localhost'))
        builder=builder.add_extension(x509.SubjectAlternativeName(uris),critical=False)
        eku=(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH if name=='server' else
             x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)
        builder=builder.add_extension(x509.ExtendedKeyUsage([eku]),critical=False)
        cert=builder.sign(ca_key,hashes.SHA256())
        cp=tmp_path/(name+'.pem');kp=tmp_path/(name+'.key')
        cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        kp.write_bytes(priv.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()))
        kp.chmod(0o600)
        certs[name]=(str(cp),str(kp))
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version=ssl.TLSVersion.TLSv1_3
    server.load_cert_chain(*certs['server'])
    server.verify_mode=ssl.CERT_REQUIRED
    server.load_verify_locations(cafile=str(tmp_path/'ca.pem'))
    clients={}
    for name in ['A','B']:
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        ctx.load_verify_locations(cafile=str(tmp_path/'ca.pem'))
        ctx.load_cert_chain(*certs[name])
        clients[name]=ctx
    return server,clients,certs

@pytest.mark.parametrize('client,expected', [('A',True),('B',False)])
def test_v14_actual_tls13_same_uid_distinct_identity(tmp_path,client,expected):
    ledger,issuer,pub,token=kit(tmp_path)
    server_ctx,clients,certs=certkit(tmp_path)
    listener=socket.socket()
    listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(5)
    outcome={}
    def server_job():
        try:
            raw,_=listener.accept()
            raw.settimeout(5)
            with raw:
                with server_ctx.wrap_socket(raw,server_side=True) as tls:
                    outcome['result']=serve_authenticated_client(tls,ledger,pub,DATA)
        except Exception as exc:outcome['error']=str(exc)
        finally:listener.close()
    thread=threading.Thread(target=server_job,daemon=True)
    thread.start()
    try:
        with socket.create_connection(listener.getsockname(),timeout=5) as raw:
            with clients[client].wrap_socket(raw,server_hostname='localhost') as tls:
                try:got=receive_from_authority(tls,token,pub,'spiffe://ci-trace.local/issuer')
                except (Denied,ssl.SSLError,OSError):got=None
    finally:thread.join(timeout=7)
    assert not thread.is_alive()
    if expected:
        assert got==DATA
        assert outcome['result']['status']=='acknowledged'
    else:
        assert got is None
        assert 'recipient_not_authorized' in outcome['error']
        assert ledger.state(token['record']['grant_id'])=='granted'

def test_v14_same_uid_plain_private_key_is_readable_counterexample(tmp_path):
    server,clients,certs=certkit(tmp_path)
    victim_key=certs['A'][1]
    assert os.stat(victim_key).st_uid == os.geteuid()
    assert b'PRIVATE KEY' in open(victim_key,'rb').read()
