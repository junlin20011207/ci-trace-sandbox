"""CI-TRACE R21 local trust-domain experiment. NEVER use with real Gitee secrets.

Authoritative policy decisions are pre-registered in an issuer-owned SQLite DB.
Online reserve is serialized against revoke (first-commit-wins linearization).
The publisher performs create-only Git ref update and verifies the published ref.
This is an OS/Git experimental oracle, NOT an independently-owned organization.
"""
from __future__ import annotations
import hashlib, json, os, sqlite3, subprocess, tempfile, time
from contextlib import closing
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from release_gate import (check_expected, canon, make_grant_for_test_only,
                          verify, DOMAIN)

SCHEMA = '''
CREATE TABLE IF NOT EXISTS operations(
  operation_id TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  grant_id TEXT UNIQUE,
  grant_blob TEXT,
  status TEXT NOT NULL CHECK (status IN ('PREAPPROVED','ISSUED','RESERVED','PUBLISHED','REVOKED')),
  remote_sha TEXT,
  receipt_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,
  operation_id TEXT NOT NULL,event TEXT NOT NULL,detail TEXT NOT NULL);
'''

def _run(args, *, cwd=None, ok=True):
    p=subprocess.run(args,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=12,
                     env={**os.environ,'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1'})
    if ok and p.returncode:
        raise RuntimeError(f"{args[0]} failed ({p.returncode}): {p.stderr[-250:]}")
    return p

def public_hex(key):
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    return key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()

def sha256(b:bytes)->str:
    return hashlib.sha256(b).hexdigest()

def verified_remote_proof(remote, subject, gitsha):
    """Use independently observed *remote* Git object, not client-supplied ACK fields."""
    if not gitsha or len(gitsha)!=40 or any(c not in '0123456789abcdef' for c in gitsha):
        return None
    ref=subject['target_ref']
    current=_run(['git','--git-dir',str(remote),'rev-parse','--verify',ref],ok=False)
    if current.returncode or current.stdout.strip()!=gitsha:return None
    parents=_run(['git','--git-dir',str(remote),'rev-list','--parents','-n','1',gitsha],ok=False)
    if parents.returncode or parents.stdout.split()!=[gitsha,subject['target_base_sha']]:return None
    message=_run(['git','--git-dir',str(remote),'log','-1','--format=%B',gitsha],ok=False)
    if message.returncode or message.stdout.strip()!=('CI-TRACE-R21 operation='+subject['operation_id']):return None
    delta=_run(['git','--git-dir',str(remote),'diff-tree','--no-commit-id','--name-only','-r',gitsha],ok=False)
    if delta.returncode or delta.stdout.splitlines()!=['research/payload.txt']:return None
    entry=_run(['git','--git-dir',str(remote),'ls-tree',gitsha,'--','research/payload.txt'],ok=False)
    if entry.returncode or not entry.stdout.startswith('100644 blob '):return None
    content=_run(['git','--git-dir',str(remote),'show',gitsha+':research/payload.txt'],ok=False)
    if content.returncode or sha256(content.stdout.encode())!=subject['artifact_sha256']:return None
    return {'operation_id':subject['operation_id'],'target_ref':ref,'published_sha':gitsha,
            'base_sha':subject['target_base_sha'],'content_sha256':subject['artifact_sha256']}

class Authority:
    """Issuer admin and publisher MUST run in distinct real trust domains in production.
    We use a laboratory local DB to test serializable decisions, not institutional control.
    """
    def __init__(self, db, issuer_key, *, issuer_key_id='LAB-R21', revision=21, remote_bare=None, clock=None):
        # The clock belongs to this authority process. Never accept time from callers.
        self.clock=clock if clock is not None else lambda: int(time.time())
        self.remote_bare=str(remote_bare) if remote_bare is not None else None
        self.db=str(db)
        self.key=issuer_key
        self.key_id=issuer_key_id
        self.revision=revision
        with closing(sqlite3.connect(self.db)) as c:
            c.executescript(SCHEMA)
    def _connect(self):
        c=sqlite3.connect(self.db,timeout=15,isolation_level=None)
        c.execute('PRAGMA busy_timeout=15000')
        return c
    def approve_subject(self, subject):
        # This is the ADMIN API. The untrusted publisher must never have this capability.
        check_expected(subject)
        with closing(self._connect()) as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                c.execute('INSERT INTO operations(operation_id,subject,status) VALUES (?, ?, ?)',
                          (subject['operation_id'],canon(subject).decode(),'PREAPPROVED'))
                c.execute('INSERT INTO audit(operation_id,event,detail) VALUES(?,?,?)',
                          (subject['operation_id'],'ADMIN_PREAPPROVED','explicit test policy'))
                c.commit()
            except BaseException:
                c.rollback()
                raise
    def issue(self, subject, *, now, ttl=90):
        check_expected(subject)
        with closing(self._connect()) as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                row=c.execute('SELECT subject,grant_blob,status FROM operations WHERE operation_id=?',
                              (subject['operation_id'],)).fetchone()
                if row is None or row[0]!=canon(subject).decode():
                    c.rollback();return None,'DENY_UNAPPROVED_SUBJECT'
                if row[2]=='REVOKED':
                    c.rollback();return None,'DENY_REVOKED'
                if row[2]!='PREAPPROVED':
                    c.rollback();return None,'DENY_ALREADY_ISSUED'
                if type(now)!=int or type(ttl)!=int or not 0<ttl<=120:
                    c.rollback();return None,'DENY_INVALID_TIME'
                grantid=sha256((subject['operation_id']+'|'+str(now)).encode())[:24]
                grant=make_grant_for_test_only(self.key,subject,issue_time=now,expiration=now+ttl,
                        grant_id=grantid,key_id=self.key_id,revision=self.revision)
                c.execute('UPDATE operations SET grant_id=?,grant_blob=?,status=? WHERE operation_id=?',
                          (grantid,canon(grant).decode(),'ISSUED',subject['operation_id']))
                c.execute('INSERT INTO audit(operation_id,event,detail) VALUES(?,?,?)',
                          (subject['operation_id'],'ISSUED',grantid))
                c.commit()
                return grant,'ISSUED'
            except BaseException:
                c.rollback()
                raise
    def revoke(self, operation_id):
        with closing(self._connect()) as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                row=c.execute('SELECT status FROM operations WHERE operation_id=?',(operation_id,)).fetchone()
                if row is None: c.rollback();return 'UNKNOWN'
                if row[0] in ('RESERVED','PUBLISHED'):
                    # Semantics: a publication already reserved cannot be retroactively cancelled.
                    c.rollback();return 'TOO_LATE_ALREADY_IN_FLIGHT'
                if row[0]=='REVOKED':c.rollback();return 'ALREADY_REVOKED'
                c.execute('UPDATE operations SET status=? WHERE operation_id=?',('REVOKED',operation_id))
                c.execute('INSERT INTO audit(operation_id,event,detail) VALUES(?,?,?)',
                          (operation_id,'REVOKED','before reservation'))
                c.commit();return 'REVOKED'
            except BaseException:
                c.rollback();raise
    def reserve_online(self, subject, grant, *, now):
        # A live API is necessary. Deny on any transport/DB exception, not stale cache.
        check_expected(subject)
        with closing(self._connect()) as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                row=c.execute('SELECT subject,grant_blob,status FROM operations WHERE operation_id=?',
                              (subject['operation_id'],)).fetchone()
                if row is None or row[0]!=canon(subject).decode():
                    c.rollback();return 'DENY_UNKNOWN_OPERATION'
                if row[2]=='REVOKED':c.rollback();return 'DENY_REVOKED'
                if row[2]!='ISSUED':c.rollback();return 'HOLD_ALREADY_RESERVED'
                if row[1]!=canon(grant).decode():c.rollback();return 'DENY_GRANT_MISMATCH'
                # Intentionally IGNORE caller-supplied `now` (kept only to test
                # attacks against older APIs). The authority reads its own clock.
                server_time=self.clock()
                if type(server_time)!=int or server_time < grant['payload']['issued_at']-10 or server_time>=grant['payload']['expires_at']:
                    c.rollback();return 'DENY_EXPIRED'
                c.execute('UPDATE operations SET status=? WHERE operation_id=?',('RESERVED',subject['operation_id']))
                c.execute('INSERT INTO audit(operation_id,event,detail) VALUES(?,?,?)',
                          (subject['operation_id'],'RESERVED','server-side online CAS'))
                c.commit();return 'RESERVED'
            except BaseException:
                c.rollback();raise
    def state(self, operation_id):
        with closing(self._connect()) as c:
            row=c.execute('SELECT status,remote_sha,receipt_sha256 FROM operations WHERE operation_id=?',(operation_id,)).fetchone()
            return row
    def ack(self, operation_id, remote_sha, receipt):
        with closing(self._connect()) as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                row=c.execute('SELECT status,remote_sha,receipt_sha256,subject FROM operations WHERE operation_id=?',(operation_id,)).fetchone()
                if row is None or self.remote_bare is None:
                    c.rollback();return 'HOLD_NO_TRUSTED_REMOTE_CHECK'
                verified=verified_remote_proof(self.remote_bare,json.loads(row[3]),remote_sha)
                if verified is None or verified!=receipt:
                    c.rollback();return 'HOLD_INVALID_REMOTE_PROOF'
                digest=sha256(canon(receipt))
                if row[:3]==('PUBLISHED',remote_sha,digest):c.rollback();return 'ACK_IDEMPOTENT'
                if row[0]!='RESERVED':c.rollback();return 'HOLD_UNEXPECTED_STATE'
                c.execute('UPDATE operations SET status=?,remote_sha=?,receipt_sha256=? WHERE operation_id=?',
                          ('PUBLISHED',remote_sha,digest,operation_id))
                c.execute('INSERT INTO audit(operation_id,event,detail) VALUES(?,?,?)',
                          (operation_id,'PUBLISHED',remote_sha))
                c.commit();return 'ACK_PUBLISHED'
            except BaseException:
                c.rollback();raise

class CreateOnlyPublisher:
    """A constrained *local* Git publisher; no ability to issue approval.

    Caller must PIN this code and trust anchor outside editable candidate branch.
    This implementation uses file:// bare remote only to avoid accidental network writes.
    """
    def __init__(self, remote_bare, trust):
        self.remote=str(remote_bare)
        self.trust=trust
        if not Path(self.remote).is_dir() or not Path(self.remote,'HEAD').is_file():
            raise ValueError('local test bare Git remote required')
    def _ref(self, ref):
        p=_run(['git','--git-dir',self.remote,'rev-parse','--verify',ref],ok=False)
        return p.stdout.strip() if p.returncode==0 else None
    def _proof(self, subject, gitsha):
        return verified_remote_proof(self.remote,subject,gitsha)
    def publish(self, authority, grant, subject, payload:bytes, *, now, crash_after_push=False):
        try:
            check_expected(subject)
            # Recover AFTER a previous push; do not re-push ambiguous operations.
            # Verification on recovery checks signature and bound subject at the issue
            # epoch, rather than demanding an unexpired authorization to ACK a
            # pre-existing remote ref. The recovery path MUST NEVER push.
            state=authority.state(subject['operation_id'])
            recovery=bool(state and state[0] in ('RESERVED','PUBLISHED'))
            signature_time=grant.get('payload',{}).get('issued_at',now) if isinstance(grant,dict) and recovery else now
            ok,why=verify(grant,self.trust,subject,signature_time)
            if not ok:return 'HOLD_'+why,None
            if not isinstance(payload,bytes) or sha256(payload)!=subject['artifact_sha256'] or b'\0' in payload or len(payload)>8192:
                return 'HOLD_PAYLOAD_MISMATCH',None
            try:
                payload.decode('utf-8')
            except UnicodeDecodeError:
                return 'HOLD_PAYLOAD_NOT_UTF8',None
            if state and state[0] in ('RESERVED','PUBLISHED'):
                remote_sha=self._ref(subject['target_ref'])
                proof=self._proof(subject,remote_sha) if remote_sha else None
                if proof:
                    outcome=authority.ack(subject['operation_id'],remote_sha,proof)
                    return 'RECOVERED_'+outcome,proof
                return 'HOLD_AMBIGUOUS',None
            if self._ref(subject['target_ref']) is not None:return 'HOLD_TARGET_EXISTS',None
            if self._ref('refs/heads/master')!=subject['target_base_sha']:
                return 'HOLD_BASE_DRIFT',None
            res=authority.reserve_online(subject,grant,now=now)
            if res!='RESERVED':return 'HOLD_'+res,None
            # An independent admin can revoke before reservation. After reservation the
            # grant is in flight; late revoke cannot promise delivery cancellation.
            with tempfile.TemporaryDirectory(prefix='r21-publisher-') as d:
                _run(['git','clone','-q','--no-hardlinks',self.remote,d])
                _run(['git','checkout','-q','--detach',subject['target_base_sha']],cwd=d)
                # Git can materialize untrusted tracked symlinks. NEVER follow them.
                parent=Path(d,'research')
                if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
                    return 'HOLD_UNSAFE_WORKTREE',None
                parent.mkdir(exist_ok=True)
                parent_fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:
                    try:
                        fd=os.open('payload.txt',os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,
                                   0o600,dir_fd=parent_fd)
                    except FileExistsError:
                        return 'HOLD_TARGET_FILE_EXISTS',None
                    with os.fdopen(fd,'wb') as out:
                        out.write(payload)
                finally:
                    os.close(parent_fd)
                _run(['git','add','--','research/payload.txt'],cwd=d)
                env=dict(os.environ,GIT_AUTHOR_NAME='CI-TRACE Lab',GIT_AUTHOR_EMAIL='ci-trace@example.invalid',
                         GIT_COMMITTER_NAME='CI-TRACE Lab',GIT_COMMITTER_EMAIL='ci-trace@example.invalid')
                p=subprocess.run(['git','-c','user.name=CI-TRACE Lab','-c','user.email=ci-trace@example.invalid',
                                  'commit','-qm','CI-TRACE-R21 operation='+subject['operation_id']],cwd=d,env=env,
                                  capture_output=True,text=True,timeout=12)
                if p.returncode: return 'HOLD_COMMIT_FAILED',None
                localsha=_run(['git','rev-parse','HEAD'],cwd=d).stdout.strip()
                push=_run(['git','push','--force-with-lease='+subject['target_ref']+':','origin',
                          'HEAD:'+subject['target_ref']],cwd=d,ok=False)
                if push.returncode:return 'HOLD_PUSH_REJECTED',None
                if crash_after_push:os._exit(91)
            proof=self._proof(subject,localsha)
            if not proof:return 'HOLD_POST_PUSH_VERIFY',None
            receipt=authority.ack(subject['operation_id'],localsha,proof)
            return receipt,proof
        except (OSError,ValueError,RuntimeError,sqlite3.Error,KeyError,TypeError) as exc:
            return 'HOLD_EXCEPTION_'+type(exc).__name__,None


def create_git_lab(bare, *, base_file='baseline\n'):
    bare=Path(bare)
    _run(['git','init','-q','--bare',str(bare)])
    with tempfile.TemporaryDirectory() as tmp:
        _run(['git','clone','-q',str(bare),tmp])
        Path(tmp,'README.md').write_text(base_file)
        _run(['git','add','.'],cwd=tmp)
        _run(['git','-c','user.name=CI-TRACE Lab','-c','user.email=ci-trace@example.invalid','commit','-qm','base'],cwd=tmp)
        _run(['git','push','-q','origin','HEAD:refs/heads/master'],cwd=tmp)
    return _run(['git','--git-dir',str(bare),'rev-parse','refs/heads/master']).stdout.strip()
