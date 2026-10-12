"""V15 research: independently signed two-role grant + atomic exactly-once DB effect.

Not exactly-once network delivery. Roots, issuer policy and database must be
managed by a distinct trusted service outside PR-controlled checkout.
"""
import base64
import hashlib
import json
import re
import sqlite3
import stat
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .provenance_guard import Denied,_require

DOMAIN=b'CI-TRACE-V15:INERT-EFFECT-QUORUM:1\n'
ROLES=('security_approver','release_approver')
FIELDS=('operation_id','repository','run_id','artifact_id','commit_sha',
        'content_sha256','recipient','effect_name','effect_value','epoch')
HEX64=re.compile(r'[a-f0-9]{64}\Z')
HEX40=re.compile(r'[a-f0-9]{40}\Z')

def canonical(s):
    _require(type(s) is dict and set(s)==set(FIELDS),'subject_schema_invalid')
    _require(type(s['operation_id']) is str and HEX64.fullmatch(s['operation_id']),
             'invalid_operation_id')
    _require(type(s['content_sha256']) is str and HEX64.fullmatch(s['content_sha256'])
             and type(s['commit_sha']) is str and HEX40.fullmatch(s['commit_sha']),
             'invalid_subject_digest')
    _require(type(s['run_id']) is int and s['run_id']>0 and
             type(s['artifact_id']) is int and s['artifact_id']>0 and
             type(s['epoch']) is int and s['epoch']>=0 and
             type(s['repository']) is str and '/' in s['repository'] and
             type(s['recipient']) is str and s['recipient'].startswith('spiffe://')
             and s['effect_name']=='increment_inert_counter' and
             type(s['effect_value']) is int and s['effect_value']==1,
             'unsafe_or_invalid_subject')
    return DOMAIN+json.dumps(s,sort_keys=True,separators=(',',':'),
                             ensure_ascii=True,allow_nan=False).encode('ascii')

def verify_quorum(proof,trust,expected):
    _require(type(proof) is dict and set(proof)=={'subject','signatures'},
             'quorum_envelope_invalid')
    data=canonical(proof['subject'])
    _require(type(expected) is dict and canonical(expected)==data,
             'approved_subject_mismatch')
    _require(type(trust) is dict and set(trust)==set(ROLES)
             and all(type(v) is dict and set(v)=={'key_id','public_hex'}
                     for v in trust.values())
             and len({v['key_id'] for v in trust.values()})==2
             and len({v['public_hex'] for v in trust.values()})==2,
             'independent_approvers_required')
    signatures=proof['signatures']
    _require(type(signatures) is dict and set(signatures)==set(ROLES),
             'approval_quorum_missing')
    for role in ROLES:
        entry=signatures[role]
        _require(type(entry) is dict and set(entry)=={'key_id','signature'}
                 and entry['key_id']==trust[role]['key_id'],
                 'approval_role_key_mismatch')
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(
                trust[role]['public_hex'])).verify(
                base64.b64decode(entry['signature'],validate=True),data)
        except (ValueError,TypeError,InvalidSignature) as exc:
            raise Denied('approver_signature_invalid') from exc
    return hashlib.sha256(data).hexdigest()

class AtomicEffectSink:
    """Commit inert business effect and receipt in the SAME SQL transaction."""
    def __init__(self,path):
        self.path=Path(path)
        parent=self.path.parent
        _require(parent.is_dir() and not parent.is_symlink()
                 and stat.S_IMODE(parent.stat().st_mode)&0o077==0,
                 'sink_directory_unprotected')
        if self.path.exists():
            _require(self.path.is_file() and not self.path.is_symlink()
                     and stat.S_IMODE(self.path.stat().st_mode)&0o077==0,
                     'sink_database_unprotected')
        with self._db() as db:
            self.path.chmod(0o600)
            db.execute('CREATE TABLE IF NOT EXISTS state (id INT PRIMARY KEY,value INT NOT NULL)')
            db.execute('INSERT OR IGNORE INTO state VALUES(1,0)')
            db.execute('CREATE TABLE IF NOT EXISTS effects ('
                'operation_id TEXT PRIMARY KEY,subject_sha TEXT NOT NULL,'
                'value_after INT NOT NULL,receipt TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS policy_epoch '
                       '(id INT PRIMARY KEY,epoch INT NOT NULL)')
            db.execute('INSERT OR IGNORE INTO policy_epoch VALUES(1,0)')
    def _db(self):
        return sqlite3.connect(self.path,timeout=15,isolation_level=None)
    def revoke_outstanding(self):
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE policy_epoch SET epoch=epoch+1 WHERE id=1')
            db.commit()
    def execute(self,proof,trust,expected_subject,*,interrupt=None):
        subject_sha=verify_quorum(proof,trust,expected_subject)
        operation=proof['subject']['operation_id']
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT subject_sha,receipt FROM effects WHERE operation_id=?',
                           (operation,)).fetchone()
            if row is not None:
                _require(row[0]==subject_sha,'operation_id_rebound')
                db.commit()
                return json.loads(row[1])
            epoch=db.execute('SELECT epoch FROM policy_epoch WHERE id=1').fetchone()[0]
            _require(epoch==proof['subject']['epoch'],'approval_epoch_revoked')
            if interrupt=='before_effect':
                raise Denied('simulated_before_commit')
            db.execute('UPDATE state SET value=value+1 WHERE id=1')
            current=db.execute('SELECT value FROM state WHERE id=1').fetchone()[0]
            receipt={'operation_id':operation,'subject_sha':subject_sha,
                     'status':'committed','value_after':current}
            db.execute('INSERT INTO effects VALUES(?,?,?,?)',
                       (operation,subject_sha,current,json.dumps(receipt,sort_keys=True)))
            db.commit()
            if interrupt=='after_commit':
                raise Denied('simulated_lost_ack_after_commit')
            return receipt
    def inspect(self):
        with self._db() as db:
            return {'value':db.execute('SELECT value FROM state').fetchone()[0],
                    'effects':db.execute('SELECT COUNT(*) FROM effects').fetchone()[0],
                    'epoch':db.execute('SELECT epoch FROM policy_epoch').fetchone()[0]}

def load_protected_policy(path,workspace):
    file=Path(path).resolve(strict=True)
    root=Path(workspace).resolve(strict=True)
    _require(file.is_file() and file!=root and root not in file.parents,
             'untrusted_policy_in_checkout')
    _require(stat.S_IMODE(file.stat().st_mode)&0o077==0,
             'unprotected_policy_file')
    _require(stat.S_IMODE(file.parent.stat().st_mode)&0o077==0,
             'unprotected_policy_parent')
    def unique(pairs):
        result={}
        for k,v in pairs:
            _require(k not in result,'duplicate_policy_field')
            result[k]=v
        return result
    config=json.loads(file.read_text(),object_pairs_hook=unique)
    _require(type(config) is dict and set(config)=={'trust','expected_subject'},
             'protected_policy_schema_invalid')
    canonical(config['expected_subject'])
    return config


def execute_with_protected_roots(sink,proof,pinned_policy_file,untrusted_workspace):
    """Trusted service chooses protected roots; no peer-provided trust or subject."""
    policy=load_protected_policy(pinned_policy_file,untrusted_workspace)
    return sink.execute(proof,policy['trust'],policy['expected_subject'])
