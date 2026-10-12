"""Idempotent durable INERT receipt, not arbitrary external exactly-once effects.

One grant => one SQLite-transactional receipt+counter, even if the ACK is lost.
Consumers must independently verify signed grant and protected issuer state.
"""
import hashlib
import json
import sqlite3
from pathlib import Path
from .approval_v14 import verify_signed_grant,encode
from .provenance_guard import Denied,_require

class ReceiptSink:
    def __init__(self,path):
        self.path=Path(path)
        parent=self.path.parent
        _require(parent.is_dir() and not parent.is_symlink() and
                 parent.stat().st_mode & 0o077 == 0,'sink_dir_unprotected')
        if self.path.exists():
            _require(self.path.is_file() and not self.path.is_symlink() and
                     self.path.stat().st_mode & 0o077 == 0,'sink_file_unprotected')
        with self.connect() as db:
            self.path.chmod(0o600)
            db.execute('CREATE TABLE IF NOT EXISTS receipts ('
                'grant_id TEXT PRIMARY KEY,signed_record_sha TEXT NOT NULL,'
                'recipient TEXT NOT NULL,artifact_digest TEXT NOT NULL,'
                'effect_name TEXT NOT NULL,response TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS metrics ('
                'name TEXT PRIMARY KEY,value INTEGER NOT NULL)')
            db.execute("INSERT OR IGNORE INTO metrics VALUES('durable_receipts',0)")

    def connect(self):
        return sqlite3.connect(self.path,isolation_level=None,timeout=10)

    def count(self):
        with self.connect() as db:
            return db.execute("SELECT value FROM metrics WHERE name='durable_receipts'").fetchone()[0]

    def apply(self,signed_grant,trusted_pubkeys,actual_recipient,
              exact_bytes,issuer_ledger,*,now=None,after_commit_hook=None):
        _require(type(exact_bytes) is bytes and len(exact_bytes)<=1024*1024,
                 'payload_not_bounded_bytes')
        rec=verify_signed_grant(signed_grant,trusted_pubkeys,now=now)
        _require(actual_recipient==rec['recipient'],'effect_recipient_mismatch')
        _require(hashlib.sha256(exact_bytes).hexdigest()==rec['content_sha256'],
                 'effect_artifact_digest_mismatch')
        _require(issuer_ledger.state(rec['grant_id']) in ('uncertain','acknowledged'),
                 'effect_grant_not_reserved')
        signed_sha=hashlib.sha256(encode(rec)).hexdigest()
        effect='durable_data_receipt'
        result={'grant_id':rec['grant_id'],'recipient':rec['recipient'],
                'data_sha256':rec['content_sha256'],'effect':effect}
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT signed_record_sha,recipient,artifact_digest,effect_name,response'
                           ' FROM receipts WHERE grant_id=?',(rec['grant_id'],)).fetchone()
            if old:
                _require(old[:4]==(signed_sha,rec['recipient'],rec['content_sha256'],effect),
                         'effect_conflicting_replay')
                db.commit()
                return {**json.loads(old[4]),'replayed':True}
            response=json.dumps(result,sort_keys=True,separators=(',',':'))
            db.execute('INSERT INTO receipts VALUES(?,?,?,?,?,?)',(
                rec['grant_id'],signed_sha,rec['recipient'],rec['content_sha256'],
                effect,response))
            db.execute("UPDATE metrics SET value=value+1 WHERE name='durable_receipts'")
            db.commit()
        if after_commit_hook is not None:after_commit_hook()
        return {**result,'replayed':False}
