"""Generate only disposable localhost CA and mTLS test certificates, no production keys."""
import os,subprocess,tempfile
from pathlib import Path
from .crypto_sm import keypair
from .authority_server import git

def run(*args):
    p=subprocess.run(args,capture_output=True,timeout=12)
    if p.returncode:raise RuntimeError('openssl cert creation: '+p.stderr.decode(errors='replace')[-250:])

def certificates(folder):
    d=Path(folder);d.mkdir(exist_ok=True)
    ca,ca_key=d/'ca.pem',d/'ca.key'
    run('openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1', '-subj','/CN=CI-TRACE-R23-EPHEMERAL-LAB-CA',
        '-addext','basicConstraints=critical,CA:TRUE',
        '-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',str(ca_key),'-out',str(ca))
    result={'ca':str(ca)}
    for name,cn,ext in [('server','localhost','subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\nbasicConstraints=CA:FALSE'),
                         ('publisher','ci-trace-publisher','extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature,keyEncipherment\nbasicConstraints=CA:FALSE'),
                         ('attacker','ci-trace-attacker','extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature,keyEncipherment\nbasicConstraints=CA:FALSE')]:
        key,csr,cert=d/(name+'.key'),d/(name+'.csr'),d/(name+'.pem')
        run('openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN='+cn,'-keyout',str(key),'-out',str(csr))
        run('openssl','x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey',str(ca_key),'-CAcreateserial','-out',str(cert),'-days','1','-sha256','-extfile','/dev/stdin') if False else None
        extfile=d/(name+'.ext');extfile.write_text(ext+'\n')
        run('openssl','x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey',str(ca_key),'-CAcreateserial','-out',str(cert),'-days','1','-sha256','-extfile',str(extfile))
        key.chmod(0o600)
        result[name+'_cert']=str(cert);result[name+'_key']=str(key)
    ca_key.chmod(0o600)
    sm_priv,sm_pub=keypair(d)
    result.update(sm_private=sm_priv,sm_public=sm_pub)
    return result

def local_git_repo(path):
    path=str(path);git('init','--bare','--initial-branch=master',path)
    (Path(path)/'CI_TRACE_DISPOSABLE_LOCAL_LAB_ONLY').write_text('NO REAL GITEE WRITE\n')
    with tempfile.TemporaryDirectory(prefix='r23-seed-') as d:
        git('clone','-q',path,d)
        Path(d,'README.md').write_text('CI-TRACE CN lab root\n')
        git('add','README.md',cwd=d)
        git('-c','user.name=CITraceCNLab','-c','user.email=lab@example.invalid','commit','-qm','seed',cwd=d)
        git('push','-q','origin','HEAD:refs/heads/master',cwd=d)
    return git('--git-dir',path,'rev-parse','refs/heads/master').decode().strip()
