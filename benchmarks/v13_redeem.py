"""100-way race experiment for one-use SQLite grant; NOT live attack prevalence."""
import concurrent.futures
import hashlib
import json
import os
import secrets
import statistics
import tempfile
import time
from pathlib import Path
from ci_trace.redeem_v13 import RedemptionLedger
from ci_trace.provenance_guard import Denied

SHA=hashlib.sha256(b'inert signed data').hexdigest()

def run(repeats=10,workers=100):
    measurements=[]
    with tempfile.TemporaryDirectory(prefix='ci-v13-race-') as td:
        folder=Path(td)/'protected'
        folder.mkdir(mode=0o700)
        db=RedemptionLedger(folder/'grants.sqlite')
        for _ in range(repeats):
            key=secrets.token_hex(32)
            db.issue(key,SHA,65534,time.time()+60)
            def redeem(_):
                try:db.redeem(key,SHA,65534);return 1
                except Denied:return 0
            start=time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                results=list(pool.map(redeem,range(workers)))
            elapsed=(time.perf_counter()-start)*1000
            measurements.append({'successful_redemptions':sum(results),
                                 'denied':workers-sum(results),'duration_ms':elapsed})
        assert all(x['successful_redemptions']==1 for x in measurements)
        return {'study':'author-designed same-grant concurrent redemption',
           'iterations':repeats,'claimants_per_iteration':workers,
           'total_success':sum(x['successful_redemptions'] for x in measurements),
           'total_denied':sum(x['denied'] for x in measurements),
           'median_batch_ms':round(statistics.median(x['duration_ms'] for x in measurements),3),
           'claim_limit':'at-most-once not exactly-once delivery'}

if __name__=='__main__':
    print(json.dumps(run(),indent=2))
