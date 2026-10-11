"""One GitHub REST -> signed approval -> immutable ZIP snapshot gate.

The caller must retain result in trusted memory and use read_verified_member
for data sinks; arbitrary code execution is NEVER authorized by this CLI.
"""
import argparse
import json
import os
from pathlib import Path
from .github_api_gate import load_authenticated_metadata
from .github_signed_gate import protected_config
from .signed_snapshot_v10 import verify_signed_snapshot_release
from .provenance_guard import Denied

def main():
    p=argparse.ArgumentParser(description='CI-TRACE immutable artifact release gate')
    p.add_argument('--repository',required=True)
    p.add_argument('--run-id',type=int,required=True)
    p.add_argument('--artifact-id',type=int,required=True)
    p.add_argument('--token-env',default='GH_TOKEN')
    p.add_argument('--archive',required=True)
    p.add_argument('--approval-package',required=True)
    p.add_argument('--trusted-keys',required=True)
    p.add_argument('--trusted-policy',required=True)
    p.add_argument('--output-root',required=True)
    p.add_argument('--workspace',required=True)
    a=p.parse_args()
    try:
        keys=protected_config(a.trusted_keys,a.workspace)
        policy=protected_config(a.trusted_policy,a.workspace)
        package=json.loads(Path(a.approval_package).read_text(encoding='utf-8'))
        event,art=load_authenticated_metadata(a.repository,a.run_id,a.artifact_id,
                                               os.environ.get(a.token_env,''))
        result=verify_signed_snapshot_release(a.archive,event,art,policy,package,
                                              keys,a.output_root,a.workspace)
        result['safe_to_execute_or_publish']=False
        print(json.dumps(result,sort_keys=True))
        return 0
    except (Denied,OSError,ValueError,TypeError,KeyError) as exc:
        print(json.dumps({'status':'denied','reason':str(exc)},sort_keys=True))
        return 1

if __name__=='__main__':
    raise SystemExit(main())
