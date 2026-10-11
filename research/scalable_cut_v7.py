#!/usr/bin/env python3
"""CI-TRACE V7: exact MILP minimum-cost risk path interdiction.

ONLY for finite risk-path/candidate-action models with separately verified
path coverage and release-preservation. It does not infer YAML semantics.
UNKNOWN is preferable to an unjustified security/optimality certificate.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
from scipy.optimize import milp, Bounds, LinearConstraint
from scipy.sparse import csc_matrix

MAX_RISKS=200
MAX_PATCHES=150

def solve(data, time_limit=10):
    if data.get('evidence_complete') is not True:
        return {'status':'UNKNOWN','reason':'incomplete evidence; cannot certify risk paths'}
    risks=data.get('risk_paths',[])
    required=data.get('required_release_paths',[])
    patches=data.get('patches',[])
    if not isinstance(risks,list) or not isinstance(required,list) or not isinstance(patches,list):
        return {'status':'REFUSED','reason':'invalid input shape'}
    if not risks or len(risks)>MAX_RISKS or len(patches)>MAX_PATCHES:
        return {'status':'REFUSED','reason':'out of validated graph bounds'}
    if len(set(risks))!=len(risks) or len(set(required))!=len(required) or len({p.get('id') for p in patches})!=len(patches):
        return {'status':'REFUSED','reason':'duplicate identifiers'}
    for p in patches:
        if type(p.get('cost')) is not int or p['cost']<1 or p['cost']>1000000:
            return {'status':'REFUSED','reason':'non-positive or excessive integer cost'}
        if not isinstance(p.get('blocks'),list) or not isinstance(p.get('breaks_required',[]),list):
            return {'status':'REFUSED','reason':'invalid paths data'}
        if set(p['blocks'])-set(risks) or set(p.get('breaks_required',[]))-set(required):
            return {'status':'REFUSED','reason':'unknown path in candidate'}
    eligible=[p for p in patches if not p.get('breaks_required') and p['blocks']]
    if not eligible: return {'status':'UNSAT','reason':'no release-preserving action'}
    eligible=sorted(eligible,key=lambda p:p['id'])
    covered=set().union(*(set(p['blocks']) for p in eligible))
    if set(risks)-covered:
        return {'status':'UNSAT','reason':'risk path without release-preserving covering patch', 'uncovered':sorted(set(risks)-covered)}
    # First solve integer min-cost set-cover. Solver optimality gap must be 0.
    A=csc_matrix(np.array([[int(r in p['blocks']) for p in eligible] for r in risks],dtype=np.float64))
    N=len(eligible)
    res=milp(c=np.array([float(p['cost']) for p in eligible]),integrality=np.ones(N),bounds=Bounds(0,1),constraints=LinearConstraint(A,lb=np.ones(len(risks)),ub=np.full(len(risks),np.inf)),options={'time_limit':float(time_limit),'mip_rel_gap':0.0,'presolve':True})
    if res.status!=0 or res.x is None or res.mip_gap is None or res.mip_gap>1e-9:
        return {'status':'UNKNOWN','reason':'MILP solver did not certify global optimality','solver_status':int(res.status)}
    selected=[p for p,x in zip(eligible,res.x) if x>0.5]
    total=sum(p['cost'] for p in selected)
    if not set(risks) <= set().union(*(set(p['blocks']) for p in selected)):
        raise AssertionError('selected actions fail independent path coverage')
    if any(p.get('breaks_required') for p in selected):
        raise AssertionError('selected action breaks an explicit release path')
    # Secondary optimal-patch-count objective with exactly the same minimum cost.
    from scipy.sparse import vstack
    A2=vstack([A,csc_matrix(np.array([[float(p['cost']) for p in eligible]]))],format='csc')
    res2=milp(c=np.ones(N),integrality=np.ones(N),bounds=Bounds(0,1),constraints=LinearConstraint(A2,lb=np.append(np.ones(len(risks)),float(total)),ub=np.append(np.full(len(risks),np.inf),float(total))),options={'time_limit':float(time_limit),'mip_rel_gap':0.0})
    if res2.status==0 and res2.x is not None and res2.mip_gap is not None and res2.mip_gap<=1e-9:
        selected2=[p for p,x in zip(eligible,res2.x) if x>0.5]
        if sum(p['cost'] for p in selected2)==total and set(risks)<=set().union(*(set(p['blocks']) for p in selected2)):
            selected=selected2
    canonical=json.dumps(data,ensure_ascii=False,sort_keys=True,separators=(',',':'))
    return {'status':'OPTIMAL','cost':total,'patches':sorted(p['id'] for p in selected),'risk_paths':len(risks),'candidates':len(patches),'eligible_candidates':N,'release_paths_kept':len(required),'input_sha256':hashlib.sha256(canonical.encode()).hexdigest(),'solver':'scipy.optimize.milp / HiGHS','certified_zero_mip_gap':True,'assumptions':['Candidate blocks are independently proven','All business-required paths enumerated','Reported cost is relative, not verified engineering hours']}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('case');p.add_argument('--out');a=p.parse_args();res=solve(json.loads(Path(a.case).read_text()));body=json.dumps(res,indent=2,ensure_ascii=False)
    if a.out:Path(a.out).write_text(body+'\n',encoding='utf8')
    else:print(body)
    raise SystemExit(0 if res['status']=='OPTIMAL' else 2)
