"""SM2/SM3 operation-grant and receipt envelopes, using OpenSSL 3.x.
Research only: keys are generated in an ephemeral test directory. ID is fixed and checked.
This module never treats a signer as a real company's business approver.
"""
import base64,hashlib,json,subprocess,tempfile
from pathlib import Path
DOMAIN=b'CI-TRACE:CN:V1\x00'
DIST_ID='CI-TRACE-CN-R23'

def canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')

def strict_json(b):
    def pairs(p):
        d={}
        for k,v in p:
            if k in d:raise ValueError('duplicate key')
            d[k]=v
        return d
    if len(b)>20000:raise ValueError('oversized')
    return json.loads(b.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError(x)))

def sm3(data):return hashlib.new('sm3',data).hexdigest()

def cmd(args):
    p=subprocess.run(args,capture_output=True,timeout=15)
    if p.returncode: raise RuntimeError('openssl command failed: '+p.stderr.decode(errors='replace')[-350:])
    return p.stdout

def keypair(directory):
    folder=Path(directory);folder.mkdir(parents=True,exist_ok=True)
    priv,pub=folder/'lab_sm2_private.pem',folder/'lab_sm2_public.pem'
    cmd(['openssl','genpkey','-algorithm','SM2','-out',str(priv)])
    cmd(['openssl','pkey','-in',str(priv),'-pubout','-out',str(pub)])
    priv.chmod(0o600)
    return str(priv),str(pub)

def sign(body,priv):
    if not isinstance(body,dict) or set(body)!={'kind','version','payload'} or body['version']!=1 or body['kind'] not in ('grant','receipt'):raise ValueError('unexpected signed schema')
    with tempfile.TemporaryDirectory(prefix='r23-sm2-') as d:
        inp,sig=Path(d)/'body.bin',Path(d)/'sig.bin'
        inp.write_bytes(DOMAIN+canonical(body))
        cmd(['openssl','pkeyutl','-sign','-in',str(inp),'-inkey',str(priv),'-out',str(sig),'-rawin','-digest','sm3','-pkeyopt','distid:'+DIST_ID])
        return {'body':body,'algorithm':'SM2-SM3','dist_id':DIST_ID,'signature_b64':base64.b64encode(sig.read_bytes()).decode('ascii')}

def verify(envelope,pub,kind):
    try:
        if not isinstance(envelope,dict) or set(envelope)!={'body','algorithm','dist_id','signature_b64'}:return False
        if envelope['algorithm']!='SM2-SM3' or envelope['dist_id']!=DIST_ID:return False
        body=envelope['body']
        if set(body)!={'kind','version','payload'} or body['kind']!=kind or body['version']!=1 or not isinstance(body['payload'],dict):return False
        sig=base64.b64decode(envelope['signature_b64'],validate=True)
        if len(sig)<40 or len(sig)>100:return False
        with tempfile.TemporaryDirectory(prefix='r23-sm2-verify-') as d:
            inp,s=Path(d)/'body.bin',Path(d)/'sig.bin'
            inp.write_bytes(DOMAIN+canonical(body));s.write_bytes(sig)
            result=subprocess.run(['openssl','pkeyutl','-verify','-in',str(inp),'-pubin','-inkey',str(pub),'-sigfile',str(s),'-rawin','-digest','sm3','-pkeyopt','distid:'+DIST_ID],capture_output=True,timeout=15)
            return result.returncode==0
    except (ValueError,KeyError,TypeError,RuntimeError,FileNotFoundError,subprocess.TimeoutExpired):return False
