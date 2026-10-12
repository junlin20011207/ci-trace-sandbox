"""Optional GHALogs V1.0.1 repository-metadata sample (Zenodo, 2025).

Download ~69 MB gzip metadata, verify publisher MD5, draw reproducible
reservoir sample of historical repos, then fetch only publicly accessible
workflow code at the *historical full commit SHA*. No run logs downloaded.
No assertion that unlabelled historical workflows are vulnerability-free.
"""
import gzip
import hashlib
import json
import random
import tempfile
from pathlib import Path
from urllib.request import urlopen
from benchmarks.v16_public_eval import evaluate
import os

URL="https://zenodo.org/records/14796970/files/repositories.json.gz?download=1"
EXPECTED_MD5="a44ed2c635348ecc8641f966748e32d2"
SEED=20261012
SAMPLE=15

def download_verified(path):
    digest=hashlib.md5()
    total=0
    with urlopen(URL,timeout=75) as response, path.open('wb') as target:
        while True:
            buf=response.read(1024*1024)
            if not buf:break
            total+=len(buf)
            if total>100_000_000:raise ValueError("metadata_over_100mb")
            digest.update(buf)
            target.write(buf)
    if digest.hexdigest()!=EXPECTED_MD5:
        raise ValueError("GHALogs_metadata_MD5_mismatch")
    return total

def sample_rows(path):
    rng=random.Random(SEED)
    rows=[]
    eligible=0
    with gzip.open(path,'rt',encoding='utf8') as stream:
        for line in stream:
            try:
                data=json.loads(line)
                repo=data.get("_id") or (data.get("repo") or {}).get("name")
                sha=(data.get("repo") or {}).get("lastCommitSHA")
                if (not isinstance(repo,str) or repo.count('/')!=1 or
                    not isinstance(sha,str) or len(sha)!=40):continue
            except (ValueError,AttributeError):continue
            eligible+=1
            entry={'repo':repo,'ref':sha,'advisory':None,
                   'class':'GHALogs_external_unlabeled_historical','required':[]}
            if len(rows)<SAMPLE:rows.append(entry)
            else:
                pos=rng.randrange(eligible)
                if pos<SAMPLE:rows[pos]=entry
    return rows,eligible

def main():
    result=Path('results');result.mkdir(exist_ok=True)
    progress={'source':URL,'publisher_md5':EXPECTED_MD5,'seed':SEED,
              'sample_target':SAMPLE,'status':'not_started'}
    try:
        with tempfile.TemporaryDirectory() as root:
            source=Path(root)/'repositories.json.gz'
            progress['downloaded_bytes']=download_verified(source)
            rows,eligible=sample_rows(source)
            progress['eligible_repo_metadata_records']=eligible
            manifest={'selection':'deterministic uniform reservoir over qualifying GHALogs 2025 historical repository metadata, no workflow security labels',
                      'sources':rows,'max_workflows_per_repo':6}
            (result/'v16_ghalogs_sample_manifest.json').write_text(
                json.dumps(manifest,indent=2))
            progress['status']='metadata_verified'
            rc=evaluate(manifest,result/'v16_ghalogs_eval.json',
                        os.getenv('GH_TOKEN') or os.getenv('GITHUB_TOKEN',''))
            progress['evaluation_exit_code']=rc
            progress['status']='evaluated' if rc==0 else 'insufficient_accessible_workflows'
    except Exception as exc:
        progress['status']='unavailable'
        progress['error']=type(exc).__name__+": "+str(exc)[:240]
    (result/'v16_ghalogs_status.json').write_text(json.dumps(progress,indent=2))
    print("GHALOGS "+json.dumps(progress,sort_keys=True))
    # Failing to download does NOT make claims about the sample's accuracy.
    return 0

if __name__=="__main__":
    raise SystemExit(main())
