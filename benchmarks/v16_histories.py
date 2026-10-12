"""2026 Zenodo MSR workflow histories: 2.5MB public repository metadata sample.

This archive enumerates real public repositories but has NO audited security
ground-truth labels. It is kept separate from disclosed GHSL positives.
"""
import csv
import gzip
import hashlib
import io
import json
import os
import random
import re
from pathlib import Path
from urllib.request import urlopen
from benchmarks.v16_public_eval import evaluate

URL='https://zenodo.org/records/20340547/files/repositories.csv.gz?download=1'
MD5='a345384e924083ae4da327e4fdf3af74'
SEED=20261012
COUNT=15

def fetch():
    with urlopen(URL,timeout=65) as handle:
        raw=handle.read(10_000_000)
    actual=hashlib.md5(raw).hexdigest()
    if actual!=MD5:
        # Archive provider documents occasional nested gzip compression.
        if raw.startswith(b'\x1f\x8b'):
            candidate=gzip.decompress(raw)
            if hashlib.md5(candidate).hexdigest()==MD5:
                raw=candidate
            else:raise ValueError('Zenodo 2026 metadata md5 mismatch '+actual)
        else:raise ValueError('Zenodo metadata not gzip and md5 mismatch')
    return raw

def extract_csv(raw):
    while raw.startswith(b'\x1f\x8b'):
        raw=gzip.decompress(raw)
    return raw.decode('utf8-sig')

def candidates(text):
    stream=io.StringIO(text)
    reader=csv.DictReader(stream)
    fields=reader.fieldnames or []
    key=next((name for name in ('repository','full_name','repo','name') if name in fields),None)
    if key is None:raise ValueError('missing repository field: '+repr(fields))
    seen=set()
    rng=random.Random(SEED)
    selected=[]
    total=0
    for row in reader:
        repo=(row.get(key) or '').strip()
        if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo) or
            repo in seen):continue
        seen.add(repo)
        total+=1
        sha=next((row[k] for k in ('lastCommitSHA','commit_hash','sha')
                if k in row and re.fullmatch('[a-fA-F0-9]{40}',row[k] or '')),None)
        item={'repo':repo,'ref':sha or 'DEFAULT','advisory':None,
              'class':'unlabeled_2026_workflow_histories','required':[]}
        if len(selected)<COUNT:selected.append(item)
        else:
            j=rng.randrange(total)
            if j<COUNT:selected[j]=item
    return selected,total,fields

def main():
    output=Path('results');output.mkdir(exist_ok=True)
    status={'source':URL,'checksum_md5':MD5,'seed':SEED,'sample_requested':COUNT}
    try:
        raw=fetch()
        rows,total,fields=candidates(extract_csv(raw))
        status.update({'metadata_records_eligible':total,'metadata_columns':fields,
                       'metadata_verified':True,'chosen_repositories':len(rows)})
        manifest={'selection':'2026-05-22 public workflow histories; deterministic reservoir of unique repository names, no binary safety labels',
                  'sources':rows,'max_workflows_per_repo':6}
        (output/'v16_histories_manifest.json').write_text(json.dumps(manifest,indent=2))
        code=evaluate(manifest,output/'v16_histories_eval.json',
                      os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN',''))
        status['evaluation_code']=code
        status['status']='evaluated' if code==0 else 'partial_or_unavailable'
    except Exception as e:
        status['status']='unavailable'
        status['error']=type(e).__name__+': '+str(e)[:280]
    (output/'v16_histories_status.json').write_text(json.dumps(status,indent=2))
    print('HISTORIES '+json.dumps(status,sort_keys=True))
    return 0
if __name__=='__main__':
    raise SystemExit(main())
