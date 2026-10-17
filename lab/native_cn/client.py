"""Publisher stays separate from issuer: private authority key and DB never held here."""
import copy,json,os,ssl,subprocess,tempfile,urllib.request
from pathlib import Path
from .crypto_sm import canonical,verify,sm3
from .authority_server import git

class MTLSClient:
    def __init__(self,endpoint,ca,certificate,key):
        self.endpoint=endpoint
        self.ssl=ssl.create_default_context(cafile=str(ca));self.ssl.load_cert_chain(str(certificate),str(key))
        self.ssl.check_hostname=True;self.ssl.verify_mode=ssl.CERT_REQUIRED
    def call(self,method,body):
        req=urllib.request.Request(self.endpoint+'/'+method,canonical(body),{'Content-Type':'application/json'},method='POST')
        with urllib.request.urlopen(req,context=self.ssl,timeout=10) as rsp:return json.loads(rsp.read())

def fresh_subject(base,payload,operation_id='cn-release-00000001',platform='CODEARTS'):
    if platform not in ('CODEARTS','GITEE_GO'):raise ValueError('unsupported platform')
    workflow={'CODEARTS':'codearts/lab-pipeline','GITEE_GO':'gitee-go/lab-pipeline'}[platform]
    return {'operation_id':operation_id,'source_platform':platform,
        'recipient':'customer-A','artifact_sm3':sm3(payload),
        'source_commit_sha':'c'*40,'workflow_identity':workflow,
        'target_repo':'gitee.com/liljunlin/test','target_ref':'refs/heads/research/native-cn-r23-'+operation_id[-8:],
        'base_sha':base,'policy_id':'LAB-CN-ISSUER-NOT-REAL-ORG'}

def push_local_create_only(remote,subject,payload,*,force_collision=False,crash_after_push=False):
    # In this isolated study the target repo is a DISPOSABLE local Git bare repository.
    # Never upgrade the actual destination to Gitee without explicit trusted credentials and policy.
    if not (Path(remote)/'CI_TRACE_DISPOSABLE_LOCAL_LAB_ONLY').is_file():
        raise ValueError('refuse non-disposable target; REAL REMOTE PUSH IS DISABLED')
    with tempfile.TemporaryDirectory(prefix='r23-publisher-') as wc:
        git('clone','-q','--no-hardlinks',remote,wc)
        git('checkout','-q','--detach',subject['base_sha'],cwd=wc)
        dest=Path(wc)/'release'
        if dest.is_symlink() or (dest.exists() and not dest.is_dir()):return 'UNSAFE_DIRECTORY',None
        dest.mkdir(exist_ok=True)
        dfd=os.open(dest,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            fd=os.open('payload.bin',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dfd)
            try:
                with os.fdopen(fd,'wb') as f:f.write(payload)
            except:raise
        finally:os.close(dfd)
        git('add','--','release/payload.bin',cwd=wc)
        git('-c','user.name=CITraceCNLab','-c','user.email=lab@example.invalid','commit','-qm','CI-TRACE-CN operation='+subject['operation_id'],cwd=wc)
        sha=git('rev-parse','HEAD',cwd=wc).decode().strip()
        if force_collision:
            git('--git-dir',remote,'update-ref',subject['target_ref'],subject['base_sha'])
        cmd=['git','push','--force-with-lease='+subject['target_ref']+':','origin','HEAD:'+subject['target_ref']]
        p=subprocess.run(cmd,cwd=wc,capture_output=True,timeout=15,env={**os.environ,'GIT_TERMINAL_PROMPT':'0'})
        if p.returncode:return 'CREATE_ONLY_REJECTED',None
        if crash_after_push:return 'CRASH_AFTER_PUSH',sha
        return 'PUSHED',sha

def publish(client,public_key,subject,payload,local_remote,*,collision=False,crash_after_push=False):
    issue=client.call('issue',{'operation_id':subject['operation_id'],'subject':subject})
    if not issue.get('ok'):return issue
    grant=issue['grant']
    if not verify(grant,public_key,'grant'):return {'ok':False,'reason':'OFFLINE_GRANT_INVALID'}
    if grant['body']['payload']['subject']!=subject or sm3(payload)!=subject['artifact_sm3']:
        return {'ok':False,'reason':'ARTIFACT_OR_SUBJECT_MISMATCH'}
    reserve=client.call('reserve',{'operation_id':subject['operation_id'],'grant':grant})
    if not reserve.get('ok'):return reserve
    result,sha=push_local_create_only(str(local_remote),subject,payload,force_collision=collision,crash_after_push=crash_after_push)
    if result=='CREATE_ONLY_REJECTED':return {'ok':False,'reason':'CREATE_ONLY_REJECTED'}
    if result=='CRASH_AFTER_PUSH':return {'ok':True,'decision':'CRASH_AFTER_PUSH','remote_sha':sha}
    if result!='PUSHED':return {'ok':False,'reason':result}
    receipt=client.call('confirm',{'operation_id':subject['operation_id'],'actual_sha':sha})
    if not receipt.get('ok') or not verify(receipt['receipt'],public_key,'receipt'):
        return {'ok':False,'reason':'RECEIPT_INVALID'}
    return receipt
