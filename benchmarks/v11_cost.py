"""V11 sealing cost on one Linux host, excluding network and pipeline costs."""
import json
import os
import statistics
import time
from ci_trace.sealed_handoff_v11 import seal_bytes, consume_sealed_fd

def measure(size, iterations=30):
    data=os.urandom(size)
    values=[]
    for _ in range(iterations):
        start=time.perf_counter_ns()
        fd,proof=seal_bytes(data,limit=max(size,1))
        try:
            assert consume_sealed_fd(fd,proof,max_bytes=max(size,1)) == data
        finally:
            os.close(fd)
        values.append((time.perf_counter_ns()-start)/1e6)
    return {'bytes':size,'n':iterations,
            'median_ms':round(statistics.median(values),4),
            'min_ms':round(min(values),4),
            'max_ms':round(max(values),4)}

if __name__=='__main__':
    print(json.dumps({'platform':'Linux kernel sealed memfd, single-process cost only',
                      'measurements':[measure(n) for n in (4096,262144,1048576)]},indent=2))
