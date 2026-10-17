"""Local-only separate-UID Unix-socket authority: NOT a production trust boundary.
The root sandbox operator can impersonate either UID; no real institution is involved.
"""
import json,os,socket,socketserver,struct,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from release_gate import parse_json_strict
from protocol import Authority

MAX_MSG=28000

class Endpoint(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
 daemon_threads=True
 request_queue_size=128
 allow_reuse_address=True

class Handler(socketserver.StreamRequestHandler):
 def handle(self):
  owner=self.server  # type: ignore
  try:
   pid,uid,gid=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
   line=self.rfile.readline(MAX_MSG+1)
   if len(line)>MAX_MSG or not line.endswith(b'\n'):
    response={'result':'HOLD_BAD_FRAMING'}
   elif uid not in {owner.publisher_uid,0}:
    response={'result':'DENY_PEER_UID'}
   else:
    req=parse_json_strict(line.strip())
    action=req.get('action')
    if action=='issue' and uid==owner.publisher_uid:
     grant,result=owner.authority.issue(req['subject'],now=owner.authority.clock(),ttl=90)
     response={'result':result,'grant':grant}
    elif action=='reserve' and uid==owner.publisher_uid:
     # Ignore supplied times; trusted issuer uses own wall-clock.
     result=owner.authority.reserve_online(req['subject'],req['grant'],now=req.get('now'))
     response={'result':result}
    elif action=='revoke' and uid==0:
     response={'result':owner.authority.revoke(req['operation_id'])}
    elif action=='state':
     response={'result':owner.authority.state(req['operation_id'])}
    else:
     response={'result':'DENY_ACTION_OR_ROLE'}
  except Exception as e:
   response={'result':'HOLD_'+type(e).__name__}
  self.wfile.write((json.dumps(response,sort_keys=True,separators=(',',':'))+'\n').encode())

def client(path,req):
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
  s.settimeout(8)
  s.connect(path)
  s.sendall((json.dumps(req,sort_keys=True,separators=(',',':'))+'\n').encode())
  buf=b''
  while not buf.endswith(b'\n'):
   chunk=s.recv(8192)
   if not chunk:break
   buf+=chunk
  return json.loads(buf)

def serve(privatedir,socket_path,publisher_uid):
 p=Path(privatedir)
 priv=(p/'signing.key').read_bytes()
 key=Ed25519PrivateKey.from_private_bytes(priv)
 auth=Authority(p/'issuer.sqlite',key,remote_bare=p/'local.git')
 # Approved subjects are pre-loaded BY THE PRIVATE AUTHORITY ADMIN (not API callers).
 subject=json.loads((p/'approved-subject.json').read_text())
 try:auth.approve_subject(subject)
 except Exception as e:
  if 'UNIQUE' not in str(e):raise
 with Endpoint(socket_path,Handler) as svc:
  svc.publisher_uid=int(publisher_uid)
  svc.authority=auth
  os.chmod(socket_path,0o666)
  print('ISSUER_SOCKET_READY',flush=True)
  svc.serve_forever(poll_interval=.1)

if __name__=='__main__':
 if sys.argv[1]=='serve':serve(sys.argv[2],sys.argv[3],int(sys.argv[4]))
 elif sys.argv[1]=='client':print(json.dumps(client(sys.argv[2],json.loads(sys.argv[3]))))
