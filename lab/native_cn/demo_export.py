"""Export only public key, grant, subject and receipt; no CA or private keys."""
import argparse,hashlib,json,os,shutil,sys
from pathlib import Path
from .test_native import NativeLab,NativeGiteeGoLab
from .client import push_local_create_only
from .crypto_sm import canonical
from .offline_verify import validate

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',default='results_r23/offline_lab_evidence');p.add_argument('--platform',choices=['CODEARTS','GITEE_GO'],default='CODEARTS');a=p.parse_args()
    output=Path(a.output);output.mkdir(parents=True,exist_ok=True)
    labtype=NativeLab if a.platform=='CODEARTS' else NativeGiteeGoLab
    lab=labtype('test_04_valid_publish_with_actual_git_proof');lab.setUp()
    try:
        grant=lab.issue();reserved=lab.reserve(grant)
        if not reserved.get('ok'):raise RuntimeError(reserved)
        decision,sha=push_local_create_only(lab.remote,lab.sub,lab.payload)
        if decision!='PUSHED':raise RuntimeError(decision)
        result=lab.client.call('confirm',{'operation_id':lab.sub['operation_id'],'actual_sha':sha})
        if not result.get('ok'):raise RuntimeError(result)
        shutil.copyfile(lab.tls['sm_public'],output/'issuer_public.pem')
        for name,object_ in [('subject',lab.sub),('grant',grant),('receipt',result['receipt'])]:
            (output/(name+'.json')).write_bytes(canonical(object_))
        fingerprint=hashlib.sha256((output/'issuer_public.pem').read_bytes()).hexdigest()
        status,reason=validate(grant,result['receipt'],lab.sub,output/'issuer_public.pem',fingerprint)
        if not status:raise RuntimeError(reason)
        instructions={'issuer_public_sha256':fingerprint,'verified':status,'verified_meaning':reason,
            'source_platform':a.platform,'execution_backend':'ISOLATED_LOCAL_GIT_FIXTURE',
            'cloud_product_integrated':False,'gitee_remote_updated':False,
            'private_issuer_key_exported':False,'certificate_authority_key_exported':False}
        (output/'VERIFICATION.json').write_text(json.dumps(instructions,indent=2,ensure_ascii=False)+'\n')
        print(json.dumps(instructions,ensure_ascii=False,indent=2))
    finally:lab.tearDown()
if __name__=='__main__':main()
