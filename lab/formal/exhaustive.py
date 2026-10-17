"""Finite-state explicit interleaving model: research abstraction, not code proof."""
from dataclasses import dataclass,replace,asdict
from collections import deque
from pathlib import Path
import json

@dataclass(frozen=True)
class State:
 status:str='ISSUED'
 revoked:bool=False
 ref:str='ABSENT'
 ack:bool=False
 issued_time:int=0
 now:int=0
 pushes:int=0
 checked_absent:bool=False


def transitions(s,unsafe=False):
 out=[]
 if s.status=='ISSUED' and not s.revoked:
  out.append(('revoke_before_reserve',replace(s,revoked=True,status='REVOKED')))
  if s.now<2:out.append(('online_reserve',replace(s,status='RESERVED')))
 if s.now<3:out.append(('clock_tick',replace(s,now=s.now+1)))
 if s.ref=='ABSENT':out.append(('other_actor_creates_ref',replace(s,ref='OTHER')))
 if s.status=='RESERVED':
  if unsafe:
   if not s.checked_absent and s.ref=='ABSENT':out.append(('client_checks_absence',replace(s,checked_absent=True)))
   if s.checked_absent and s.ref in ('ABSENT','OTHER'):
    out.append(('ordinary_git_push',replace(s,ref='CANDIDATE',pushes=s.pushes+1,status='AWAIT_ACK')))
  elif s.ref=='ABSENT':out.append(('atomic_create_only_git_push',replace(s,ref='CANDIDATE',pushes=s.pushes+1,status='AWAIT_ACK')))
 if s.status=='AWAIT_ACK' and s.ref=='CANDIDATE':
  out.append(('verified_ack',replace(s,status='PUBLISHED',ack=True)))
  out.append(('process_crash',replace(s,status='CRASHED')))
 if s.status=='CRASHED' and s.ref=='CANDIDATE':out.append(('read_only_recovery',replace(s,status='PUBLISHED',ack=True)))
 return out

def invalid(s):
 if s.pushes>1:return 'double Git publication'
 if s.ack and (s.ref!='CANDIDATE' or s.pushes!=1):return 'unverified ACK'
 if s.ref=='CANDIDATE' and s.pushes!=1:return 'publication not tied to atomic operation'
 if s.revoked and s.pushes:return 'revoked-before-reserve publication'
 return None

def check(unsafe=False):
 q=deque([(State(),[])]);seen={State()};counterexample=None;edges=0
 while q:
  s,trace=q.popleft()
  for action,nxt in transitions(s,unsafe):
   edges+=1
   failure=invalid(nxt)
   if unsafe and action=='ordinary_git_push' and s.ref=='OTHER':failure='TOCTOU overwrite of other actor Git ref'
   if failure:
    return {'unsafe':unsafe,'states_seen':len(seen),'transitions_checked':edges,'counterexample':trace+[action], 'violation':failure}
   if nxt not in seen:
    seen.add(nxt);q.append((nxt,trace+[action]))
 return {'unsafe':unsafe,'states_seen':len(seen),'transitions_checked':edges,'invariants_hold':True,'invariants':['at_most_one_publication','ack_implies_verified_git_ref','revoke_before_reserve_blocks','create_only_ref_no_overwrite']}

if __name__=='__main__':
 correct=check(False);bug=check(True)
 assert correct['invariants_hold'] and bug['violation']=='TOCTOU overwrite of other actor Git ref'
 result={'correct_protocol':correct,'deliberately_unsafe_model':bug,
  'scope':'Finite-state abstraction: three logical clock ticks, one operation, one competing ref; not a proof of the concrete program or external server'}
 dst=Path(__file__).resolve().parent.parent/'results'/'state_space.json';dst.write_text(json.dumps(result,indent=2))
 print(json.dumps(result,indent=2))
