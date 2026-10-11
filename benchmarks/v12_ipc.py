"""Deterministic author-designed forged/authorized IPC trials, not attack prevalence."""
import argparse
import hashlib
import json
import os
import socket
import threading
from ci_trace.provenance_guard import Denied
from ci_trace.sealed_handoff_v11 import seal_bytes,consume_sealed_fd
from ci_trace.authenticated_ipc_v12 import send_sealed,receive_authorized

GOOD=b'approved benign CI data'
BAD=b'different unapproved CI data'
SHA=hashlib.sha256(GOOD).hexdigest()

def trial(payload, allowed_uid=None):
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    left.settimeout(3);right.settimeout(3)
    fd,proof=seal_bytes(payload)
    report={}
    def sender():
        try:send_sealed(right,fd,proof,allowed_receiver_uid=os.getuid())
        except (OSError,Denied) as e:report['send_error']=str(e)
        finally:right.close();os.close(fd)
    worker=threading.Thread(target=sender,daemon=True)
    worker.start()
    try:
        baseline,oldproof=seal_bytes(payload)
        try:report['self_consistent']=consume_sealed_fd(baseline,oldproof)==payload
        finally:os.close(baseline)
        try:
            data,peer=receive_authorized(left,trusted_expected_sha256=SHA,
                      allowed_uid=os.getuid() if allowed_uid is None else allowed_uid)
            report['v12']='accepted' if data==payload else 'incorrect_data'
        except Denied as e:report['v12']=str(e)
    finally:left.close();worker.join(timeout=4)
    return report

def evaluate(trials):
    assert 1<=trials<=200
    out={'trials_per_case':trials,
         'legacy_self_consistent_forged_accepted':0,
         'v12_forged_denied':0,
         'v12_legitimate_accepted':0,
         'v12_wrong_peer_uid_denied':0}
    for _ in range(trials):
        bad=trial(BAD)
        out['legacy_self_consistent_forged_accepted']+=int(bad['self_consistent'])
        out['v12_forged_denied']+=int(bad['v12']=='handoff_not_authorized')
        good=trial(GOOD)
        out['v12_legitimate_accepted']+=int(good['v12']=='accepted')
        wrong=trial(GOOD,allowed_uid=os.getuid()+1)
        out['v12_wrong_peer_uid_denied']+=int(wrong['v12']=='ipc_peer_uid_denied')
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('--trials',type=int,default=30)
    args=p.parse_args()
    result=evaluate(args.trials)
    print(json.dumps({'design':'controlled, author-labeled IPC adversarial comparison',
                      'result':result},indent=2))
    assert all(v==args.trials for k,v in result.items() if k!='trials_per_case')

if __name__=='__main__':main()
