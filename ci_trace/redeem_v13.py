"""Trusted, persistent, one-use artifact capability ledger.

Only the protected issuer/server can access the SQLite file. Each redemption
is an immediate, atomic transaction. Delivery is at-most-once: server crash
after redemption can lose availability, but does not allow another release.
"""
import os
import re
import sqlite3
import stat
import time
from pathlib import Path
from .provenance_guard import Denied, _require

HEX64=re.compile(r'[a-f0-9]{64}\Z')

class RedemptionLedger:
    def __init__(self,db_path):
        self.path=Path(db_path).absolute()
        folder=self.path.parent
        _require(folder.is_dir() and not folder.is_symlink(),
                 'ledger_parent_invalid')
        _require(stat.S_IMODE(folder.stat().st_mode)&0o077==0,
                 'ledger_parent_permissive')
        if self.path.exists():
            info=self.path.lstat()
            _require(stat.S_ISREG(info.st_mode) and
                     stat.S_IMODE(info.st_mode)&0o077==0,'ledger_file_insecure')
        self._init()

    def _connect(self):
        db=sqlite3.connect(self.path,timeout=10,isolation_level=None)
        db.execute('PRAGMA busy_timeout=10000')
        return db

    def _init(self):
        with self._connect() as db:
            os.chmod(self.path,0o600)
            db.execute('CREATE TABLE IF NOT EXISTS grants ('
                'grant_id TEXT PRIMARY KEY, sha256 TEXT NOT NULL,'
                'recipient_uid INTEGER NOT NULL, expires REAL NOT NULL,'
                'redeemed_at REAL)')

    def issue(self,grant_id,digest,recipient_uid,expires_at,*,now=None):
        _require(isinstance(grant_id,str) and HEX64.fullmatch(grant_id),
                 'invalid_grant_id')
        _require(isinstance(digest,str) and HEX64.fullmatch(digest),
                 'invalid_grant_digest')
        _require(type(recipient_uid) is int and recipient_uid>=0,
                 'invalid_recipient_uid')
        now=time.time() if now is None else now
        _require(type(expires_at) in (int,float) and
                 now<expires_at<=now+3600,'invalid_grant_expiration')
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute('INSERT INTO grants(grant_id,sha256,recipient_uid,expires)'
                           ' VALUES(?,?,?,?)',
                           (grant_id,digest,recipient_uid,expires_at))
                db.commit()
            except sqlite3.IntegrityError as exc:
                db.rollback()
                raise Denied('grant_id_already_issued') from exc

    def redeem(self,grant_id,trusted_sha,recipient_uid,*,now=None):
        _require(isinstance(grant_id,str) and HEX64.fullmatch(grant_id),
                 'invalid_grant_id')
        _require(isinstance(trusted_sha,str) and HEX64.fullmatch(trusted_sha),
                 'invalid_grant_digest')
        _require(type(recipient_uid) is int and recipient_uid>=0,
                 'invalid_recipient_uid')
        now=time.time() if now is None else now
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            cursor=db.execute('UPDATE grants SET redeemed_at=? WHERE grant_id=?'
                  ' AND sha256=? AND recipient_uid=? AND redeemed_at IS NULL'
                  ' AND expires>?',(now,grant_id,trusted_sha,recipient_uid,now))
            db.commit()
            _require(cursor.rowcount==1,'grant_not_redeemable')
            return {'grant_id':grant_id,'sha256':trusted_sha,
                    'recipient_uid':recipient_uid,'redeemed_at':now}
