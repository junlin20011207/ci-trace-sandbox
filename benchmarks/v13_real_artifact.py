"""Real authenticated GitHub Artifact -> signed sealed FD -> root broker -> nobody.

Research test ONLY on disposable GitHub-hosted runner and internal PRs.
Client receives no API token, approval private key, or protected SQLite file.
"""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from ci_trace.github_api_gate import load_authenticated_metadata
from ci_trace.sealed_signed_release_v11 import issue_sealed_member
from ci_trace.redeem_v13 import RedemptionLedger
from ci_trace.issuer_broker_v13 import bind_broker_listener,new_grant,service_once
from ci_trace.provenance_guard import Denied

def main():
    if os.geteuid()!=0:
        raise RuntimeError('This particular isolation test requires root')
    workspace=Path(os.environ['WORKSPACE'])
    temp=Path(os.environ['TEMP'])
    protected=temp/'ci-trace-keys'
    policy=json.loads((protected/'policy.json').read_text())
    keys=json.loads((protected/'keys.json').read_text())
    package=json.loads(Path('approval-package.json').read_text())
    event,artifact=load_authenticated_metadata(os.environ['REPO'],38138006392,
                     int(os.environ['SOURCE_ARTIFACT_ID']),os.environ['GH_TOKEN'])
    fd,cap=issue_sealed_member('artifact.zip',event,artifact,policy,package,
                        keys,temp/'ci-trace-release',workspace,'probe.txt')
    root=tempfile.TemporaryDirectory(prefix='ci-v13-broker-',dir='/tmp')
    top=Path(root.name);os.chmod(top,0o755)
    # Stage public reader package only; token, private grant DB and protected
    # approvals remain inaccessible to the client UID.
    public=top/'ci_trace'
    shutil.copytree(workspace/'ci_trace',public,
                    ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
    for item in public.rglob('*'):
        os.chmod(item,0o755 if item.is_dir() else 0o644)
    os.chmod(public,0o755)
    private=top/'issuer-only';private.mkdir(mode=0o700)
    db=private/'grants.sqlite'
    ledger=RedemptionLedger(db)
    endpoint=top/'broker.sock'
    listener=bind_broker_listener(endpoint,backlog=4)
    os.chmod(endpoint,0o666)
    verified_digest=cap['trusted_expected_sha256']
    source='''import json,os,socket,sys
from ci_trace.issuer_broker_v13 import claim_once
sockpath,grant,digest,db=sys.argv[1:5]
try:
    try:open(db,'rb'); db_open='BAD'
    except (PermissionError,OSError):db_open='denied'
    connection=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    connection.settimeout(5);connection.connect(sockpath)
    value,peer=claim_once(connection,grant,
        trusted_expected_sha256=digest,allowed_broker_uid=0)
    print(json.dumps({'result':'accepted','data':value.decode(),
                      'protected_db':db_open,'broker_uid':peer['uid']}))
except Exception as exc:
    print(json.dumps({'result':'denied','reason':str(exc)}))
'''
    def child(uid,grant):
        def drop():
            os.setgid(uid);os.setuid(uid)
        return subprocess.Popen([sys.executable,'-c',source,str(endpoint),
                grant,verified_digest,str(db)],preexec_fn=drop,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),
                     'PYTHONPATH':str(top),'HOME':'/tmp'})
    def once(process):
        conn,_=listener.accept()
        conn.settimeout(5)
        with conn:
            try:issued=service_once(conn,ledger,fd,cap['proof'],
                                       trusted_expected_sha256=verified_digest)
            except Denied as exc:issued={'status':'denied','reason':str(exc)}
        stdout,stderr=process.communicate(timeout=7)
        assert process.returncode==0,stderr
        return issued,json.loads(stdout)
    try:
        grant=new_grant(ledger,verified_digest,65534)
        wrong=child(1,grant)
        rejected,failed=once(wrong)
        assert rejected['reason']=='grant_not_redeemable'
        assert failed['result']=='denied'
        correct=child(65534,grant)
        accepted,valid=once(correct)
        assert accepted['status']=='released'
        assert valid['result']=='accepted'
        assert valid['data']=='ci-trace layout probe\n'
        assert valid['protected_db']=='denied'
        duplicate=child(65534,grant)
        replay,denied=once(duplicate)
        assert replay['reason']=='grant_not_redeemable'
        assert denied['result']=='denied'
        print(json.dumps({'real_github_artifact':True,'test_client_uid':65534,
            'test_broker_uid':0,'different_uid_separation':True,
            'wrong_uid_denied':True,'replay_denied':True,
            'protected_grant_database':True,'original_signed_bytes':len(valid['data'])}))
    finally:
        listener.close();os.close(fd);root.cleanup()

if __name__=='__main__':
    main()
