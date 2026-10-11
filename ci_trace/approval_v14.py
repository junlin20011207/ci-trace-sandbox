"""V14 experimental independent signed grant + persisted at-most-once state.

Test-only keys, not a real organization approval service. Grant reservation is
durable before delivery, so a crash prevents replay but may lose availability.
"""
import base64
import binascii
import hashlib
import json
import re
import secrets
import sqlite3
import time
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .provenance_guard import Denied, _require

DOMAIN=b'CI-TRACE-V14:INDEPENDENT-APPROVAL\n'
FIELDS=frozenset(('grant_id','repository','run_id','artifact_id','commit_sha',
                  'content_sha256','recipient','purpose','issued_at','expires_at'))
HEX64=re.compile(r'[a-f0-9]{64}\Z')
HEX40=re.compile(r'[a-f0-9]{40}\Z')

def encode(record):
    _require(type(record) is dict and set(record)==FIELDS,'approval_schema_invalid')
    return DOMAIN+json.dumps(record,sort_keys=True,separators=(',',':'),
                    allow_nan=False,ensure_ascii=True).encode('ascii')

def verify_signed_grant(envelope,trust,*,now=None,revoked_keys=()):
    _require(type(envelope) is dict and set(envelope)=={'record','key_id','signature'},
             'approval_envelope_invalid')
    key_id=envelope['key_id']
    _require(type(key_id) is str and key_id in trust,'approval_key_unknown')
    _require(key_id not in revoked_keys,'approval_key_revoked')
    rec=envelope['record']
    raw=encode(rec)
    try:
        pub=Ed25519PublicKey.from_public_bytes(bytes.fromhex(trust[key_id]))
        pub.verify(base64.b64decode(envelope['signature'],validate=True),raw)
    except (ValueError,TypeError,InvalidSignature,binascii.Error) as exc:
        raise Denied('approval_signature_invalid') from exc
    t=time.time() if now is None else now
    _require(type(rec['issued_at']) in (int,float) and
             type(rec['expires_at']) in (int,float) and
             rec['issued_at']<=t<rec['expires_at'] and
             0<rec['expires_at']-rec['issued_at']<=3600,
             'approval_expired_or_invalid')
    _require(type(rec['grant_id']) is str and HEX64.fullmatch(rec['grant_id']) and
             type(rec['commit_sha']) is str and HEX40.fullmatch(rec['commit_sha']) and
             type(rec['content_sha256']) is str and HEX64.fullmatch(rec['content_sha256']),
             'approval_digest_invalid')
    _require(type(rec['run_id']) is int and rec['run_id']>0 and
             type(rec['artifact_id']) is int and rec['artifact_id']>0 and
             type(rec['repository']) is str and '/' in rec['repository'] and
             rec['purpose']=='read-inert-data' and type(rec['recipient']) is str and
             rec['recipient'].startswith('spiffe://'),'approval_subject_invalid')
    return rec

class ApprovalLedger:
    def __init__(self,path):
        self.path=Path(path)
        parent=self.path.parent
        _require(parent.is_dir() and not parent.is_symlink() and
                 parent.stat().st_mode & 0o077 == 0,'approval_ledger_directory_unprotected')
        if self.path.exists():
            _require(self.path.is_file() and not self.path.is_symlink() and
                     self.path.stat().st_mode & 0o077==0,'approval_ledger_file_unprotected')
        with self.connect() as db:
            self.path.chmod(0o600)
            db.execute('CREATE TABLE IF NOT EXISTS grants (grant_id TEXT PRIMARY KEY,'
              ' record_sha TEXT NOT NULL, recipient TEXT NOT NULL,'
              ' state TEXT NOT NULL, expires REAL NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS revoked_keys ('
              'key_id TEXT PRIMARY KEY, at_time REAL NOT NULL)')

    def connect(self):
        return sqlite3.connect(self.path,timeout=10,isolation_level=None)

    def issue(self,rec):
        sha=hashlib.sha256(encode(rec)).hexdigest()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute('INSERT INTO grants VALUES (?,?,?,?,?)',(
                    rec['grant_id'],sha,rec['recipient'],'granted',rec['expires_at']))
                db.commit()
            except sqlite3.IntegrityError as exc:
                db.rollback()
                raise Denied('approval_grant_duplicate') from exc

    def revoke_grant(self,grant_id):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            n=db.execute("UPDATE grants SET state='revoked' WHERE grant_id=?"
                         " AND state='granted'",(grant_id,)).rowcount
            db.commit()
            _require(n==1,'grant_not_revocable')

    def revoke_key(self,key_id,*,now=None):
        with self.connect() as db:
            db.execute('INSERT OR IGNORE INTO revoked_keys VALUES (?,?)',(
                key_id,time.time() if now is None else now))

    def _key_revoked(self,key_id):
        with self.connect() as db:
            return db.execute('SELECT 1 FROM revoked_keys WHERE key_id=?',
                              (key_id,)).fetchone() is not None

    def reserve(self,envelope,trust,recipient,*,now=None):
        _require(type(recipient) is str,'unauthenticated_recipient')
        key_id=envelope.get('key_id') if isinstance(envelope,dict) else None
        _require(not self._key_revoked(key_id),'approval_key_revoked')
        rec=verify_signed_grant(envelope,trust,now=now)
        _require(rec['recipient']==recipient,'recipient_not_authorized')
        sha=hashlib.sha256(encode(rec)).hexdigest()
        t=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            n=db.execute("UPDATE grants SET state='uncertain' WHERE grant_id=?"
                " AND record_sha=? AND recipient=? AND state='granted' AND expires>?",
                (rec['grant_id'],sha,recipient,t)).rowcount
            db.commit()
            _require(n==1,'grant_not_redeemable')
        return {'status':'uncertain_delivery','grant_id':rec['grant_id'],
                'sha256':rec['content_sha256'],'recipient':recipient}

    def acknowledge(self,grant_id,recipient):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            n=db.execute("UPDATE grants SET state='acknowledged' WHERE grant_id=?"
               " AND recipient=? AND state='uncertain'",(grant_id,recipient)).rowcount
            db.commit()
            _require(n==1,'grant_not_acknowledgeable')

    def state(self,grant_id):
        with self.connect() as db:
            row=db.execute('SELECT state FROM grants WHERE grant_id=?',(grant_id,)).fetchone()
            return row[0] if row else None

def issue_signed_grant(ledger,key,key_id,subject,*,ttl=60,now=None):
    _require(isinstance(key,Ed25519PrivateKey),'private_signer_required')
    _require(type(ttl) in (int,float) and 0<ttl<=3600,'approval_ttl_invalid')
    t=time.time() if now is None else now
    rec={**subject,'grant_id':secrets.token_hex(32),
         'issued_at':t,'expires_at':t+ttl,'purpose':'read-inert-data'}
    encode(rec)
    ledger.issue(rec)
    return {'key_id':key_id,'record':rec,
            'signature':base64.b64encode(key.sign(encode(rec))).decode()}

class ProtectedIssuer:
    def __init__(self,ledger,key,key_id,allowlist):
        _require(isinstance(key,Ed25519PrivateKey),'private_signer_required')
        _require(bool(allowlist),'issuer_policy_required')
        self.ledger,self.key,self.key_id=ledger,key,key_id
        fields=('repository','run_id','artifact_id','commit_sha','content_sha256','recipient')
        self.fields=fields
        self.allowed=frozenset(tuple(x[k] for k in fields) for x in allowlist)
    def issue(self,subject,*,ttl=60,now=None):
        _require(tuple(subject.get(k) for k in self.fields) in self.allowed,
                 'issuer_policy_denied')
        return issue_signed_grant(self.ledger,self.key,self.key_id,subject,ttl=ttl,now=now)
