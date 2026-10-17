"""Local mTLS issuer, separate OS process. No external-business institution claim.
Trust boundary: its private SM2 key and SQLite are never transmitted to the publisher.
Endpoint /issue, /reserve, /confirm, /state require TLS client certificate CN=ci-trace-publisher.
Approval is preloaded by administrator from an immutable test fixture, not remotely selectable.
"""
import hashlib,http.server,json,os,re,sqlite3,ssl,subprocess,sys,time
from pathlib import Path
from .crypto_sm import canonical,sign,verify,sm3,strict_json
VALID_REF=re.compile(r'^refs/heads/research/[A-Za-z0-9/_-]{8,120}$')
HEX40=re.compile(r'^[0-9a-f]{40}$')
HEX64=re.compile(r'^[0-9a-f]{64}$')
OPID=re.compile(r'^[a-zA-Z0-9_-]{8,60}$')
ALLOWED_SUBJECT_KEYS={'operation_id','source_platform','recipient','artifact_sm3','target_repo','target_ref','base_sha','policy_id','source_commit_sha','workflow_identity'}

def validate_subject(subject):
    if not isinstance(subject,dict) or set(subject)!=ALLOWED_SUBJECT_KEYS:return False
    if any(not isinstance(x,str) for x in subject.values()):return False
    if not OPID.fullmatch(subject['operation_id']):return False
    if not HEX40.fullmatch(subject['base_sha']) or not HEX40.fullmatch(subject['source_commit_sha']):return False
    if not HEX64.fullmatch(subject['artifact_sm3']):return False
    if not VALID_REF.fullmatch(subject['target_ref']) or '..' in subject['target_ref'] or '//' in subject['target_ref']:return False
    return (subject['recipient']=='customer-A' and subject['target_repo']=='gitee.com/liljunlin/test'
            and subject['source_platform'] in ('CODEARTS','GITEE_GO')
            and subject['workflow_identity']=={'CODEARTS':'codearts/lab-pipeline','GITEE_GO':'gitee-go/lab-pipeline'}[subject['source_platform']]
            and subject['policy_id']=='LAB-CN-ISSUER-NOT-REAL-ORG')

def git(*args,cwd=None):
    p=subprocess.run(['git',*map(str,args)],cwd=cwd,capture_output=True,timeout=10,env={**os.environ,'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_NOSYSTEM':'1'})
    if p.returncode:raise ValueError('remote Git verification rejected: '+p.stderr.decode(errors='replace')[-200:])
    return p.stdout

def verify_actual(remote,subject,submitted_sha):
    try:
        if not re.fullmatch('[a-f0-9]{40}',submitted_sha):return None
        ref=subject['target_ref']
        if not VALID_REF.fullmatch(ref) or '..' in ref or '//' in ref:return None
        actual=git('--git-dir',remote,'rev-parse','--verify',ref).decode().strip()
        if actual!=submitted_sha:return None
        parents=git('--git-dir',remote,'rev-list','--parents','-n','1',actual).decode().split()
        if parents!=[actual,subject['base_sha']]:return None
        msg=git('--git-dir',remote,'log','-1','--format=%B',actual).decode().strip()
        if msg!='CI-TRACE-CN operation='+subject['operation_id']:return None
        changed=git('--git-dir',remote,'diff-tree','--no-commit-id','--name-only','-r','--no-renames',actual).decode().splitlines()
        if changed!=['release/payload.bin']:return None
        tree=git('--git-dir',remote,'ls-tree',actual,'--','release/payload.bin').decode()
        if not tree.startswith('100644 blob '):return None
        data=git('--git-dir',remote,'show',actual+':release/payload.bin')
        if sm3(data)!=subject['artifact_sm3']:return None
        return {'operation_id':subject['operation_id'],'recipient':subject['recipient'],
          'platform':subject['source_platform'],'target_platform':'Gitee (target metadata only)',
          'target_ref':ref,'base_sha':subject['base_sha'],'actual_commit_sha':actual,
          'artifact_sm3':subject['artifact_sm3'],
          'source_commit_sha':subject['source_commit_sha'],'workflow_identity':subject['workflow_identity'],
          'execution_backend':'ISOLATED_LOCAL_GIT_FIXTURE',
          'business_authority':'EPHEMERAL_LAB_ISSUER_NOT_REAL_COMPANY'}
    except (OSError,ValueError,KeyError,UnicodeError):return None

class State:
    def __init__(self,db,private,pub,remote,approved):
        self.db,self.private,self.pub,self.remote=str(db),str(private),str(pub),str(remote)
        self.approved=approved
        if not (Path(self.remote)/'CI_TRACE_DISPOSABLE_LOCAL_LAB_ONLY').is_file():
            raise ValueError('issuer will verify only disposable local Git fixtures')
        if not validate_subject(approved):raise ValueError('unsupported lab subject')
        with sqlite3.connect(db) as cx:
            cx.execute('CREATE TABLE IF NOT EXISTS ops (id TEXT PRIMARY KEY,subject TEXT NOT NULL,state TEXT NOT NULL,grant TEXT,receipt TEXT,actual_sha TEXT)')
            cx.execute('INSERT OR IGNORE INTO ops (id,subject,state) VALUES (?,?,?)',
                (approved['operation_id'],canonical(approved).decode(),'PREAPPROVED'))
    def execute(self,operation,data):
        with sqlite3.connect(self.db,timeout=10,isolation_level=None) as cx:
            cx.execute('BEGIN IMMEDIATE')
            try:
                opid=data.get('operation_id')
                row=cx.execute('SELECT subject,state,grant,receipt,actual_sha FROM ops WHERE id=?',(opid,)).fetchone()
                if not row:return {'ok':False,'reason':'UNKNOWN_OPERATION'}
                subj=json.loads(row[0]);state,grantstr,receiptstr,old_sha=row[1:]
                if operation=='state':return {'ok':True,'state':state}
                if operation=='issue':
                    if state!='PREAPPROVED':return {'ok':False,'reason':'ISSUANCE_STATE_'+state}
                    if data.get('subject')!=subj:return {'ok':False,'reason':'SUBJECT_MISMATCH'}
                    now=int(time.time());body={'kind':'grant','version':1,'payload':{'subject':subj,'issued_at':now,'expires_at':now+90,'grant_id':sm3(canonical(subj)+str(now).encode())[:24]}}
                    g=sign(body,self.private)
                    cx.execute('UPDATE ops SET state=?,grant=? WHERE id=?',('ISSUED',canonical(g).decode(),opid))
                    cx.commit();return {'ok':True,'grant':g}
                if operation=='reserve':
                    if state!='ISSUED':return {'ok':False,'reason':'RESERVE_STATE_'+state}
                    env=data.get('grant');g=json.loads(grantstr)
                    if env!=g or not verify(env,self.pub,'grant'):return {'ok':False,'reason':'INVALID_GRANT'}
                    t=int(time.time());p=g['body']['payload']
                    if p['subject']!=subj or not p['issued_at']-5<=t<p['expires_at']:return {'ok':False,'reason':'EXPIRED_OR_BOUND_MISMATCH'}
                    cx.execute('UPDATE ops SET state=? WHERE id=?',('RESERVED',opid))
                    cx.commit();return {'ok':True,'decision':'RESERVED'}
                if operation=='revoke':
                    # ADMIN-ONLY in production. Never let publisher revoke or approve.
                    return {'ok':False,'reason':'ADMIN_ONLY_REVOKE'}
                if operation=='confirm':
                    if state=='PUBLISHED' and receiptstr:
                        # Recheck live remote; do not blindly return stale receipt on ref mutation.
                        if verify_actual(self.remote,subj,old_sha) is None:return {'ok':False,'reason':'REMOTE_CHANGED_AFTER_CONFIRM'}
                        return {'ok':True,'decision':'IDEMPOTENT_VERIFIED','receipt':json.loads(receiptstr)}
                    if state!='RESERVED':return {'ok':False,'reason':'NOT_RESERVED'}
                    proof=verify_actual(self.remote,subj,data.get('actual_sha'))
                    if not proof:return {'ok':False,'reason':'NO_VERIFIED_REMOTE_PROOF'}
                    proof.update({'confirmed_at':int(time.time()),'grant_sm3':sm3(grantstr.encode())})
                    receipt=sign({'kind':'receipt','version':1,'payload':proof},self.private)
                    cx.execute('UPDATE ops SET state=?,actual_sha=?,receipt=? WHERE id=?',('PUBLISHED',proof['actual_commit_sha'],canonical(receipt).decode(),opid))
                    cx.commit();return {'ok':True,'decision':'PUBLISHED_VERIFIED','receipt':receipt}
                return {'ok':False,'reason':'UNKNOWN_METHOD'}
            except BaseException:
                cx.rollback();raise

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):pass
    def do_POST(self):
        try:
            # Reject clients not identified as the separately minted publisher cert.
            cert=self.connection.getpeercert();cn=[t[1] for rdn in cert.get('subject',[]) for t in rdn if t[0]=='commonName']
            if cn!=['ci-trace-publisher']:
                self.respond(403,{'ok':False,'reason':'WRONG_CLIENT_CN'});return
            raw=self.rfile.read(min(int(self.headers.get('Content-Length','0')),20001))
            data=strict_json(raw)
            if not isinstance(data,dict) or self.path not in ('/issue','/reserve','/confirm','/state','/revoke'):
                self.respond(400,{'ok':False,'reason':'BAD_REQUEST'});return
            result=self.server.state.execute(self.path[1:],data)
            self.respond(200,result)
        except Exception as exc:
            self.respond(400,{'ok':False,'reason':'REQUEST_REJECTED'})
    def respond(self,status,body):
        b=canonical(body);self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)

def serve(state,ca_cert,cert,key,port):
    srv=http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler);srv.state=state
    ctx=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,cafile=ca_cert)
    ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.load_cert_chain(cert,key)
    srv.socket=ctx.wrap_socket(srv.socket,server_side=True)
    srv.serve_forever()
