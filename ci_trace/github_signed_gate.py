"""End-to-end GitHub authenticated Artifact and signed approved-revision gate.

Trusted keys/policy MUST be protected separately from PR checkout; checking
path topology does not prove the operating system or runner is uncompromised.
"""
import argparse
import json
import os
from pathlib import Path
from .github_api_gate import load_authenticated_metadata
from .signed_authorization import verify_signed_release
from .provenance_guard import Denied, _require

def protected_config(path,workspace):
    source=Path(path).resolve(strict=True)
    root=Path(workspace).resolve(strict=True)
    _require(source.is_file(),'trusted_configuration_not_file')
    _require(source != root and root not in source.parents,
             'trusted_configuration_inside_workspace')
    return json.loads(source.read_text(encoding='utf-8'))

def main():
    p=argparse.ArgumentParser(description='CI-TRACE signed artifact authorization')
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
    args=p.parse_args()
    try:
        keys=protected_config(args.trusted_keys,args.workspace)
        policy=protected_config(args.trusted_policy,args.workspace)
        package=json.loads(Path(args.approval_package).read_text(encoding='utf-8'))
        event,artifact=load_authenticated_metadata(args.repository,args.run_id,
              args.artifact_id,os.environ.get(args.token_env,''))
        outcome=verify_signed_release(args.archive,event,artifact,policy,package,
                       keys,args.output_root,args.workspace)
        print(json.dumps(outcome,sort_keys=True))
        return 0
    except (Denied,OSError,ValueError,TypeError,KeyError) as exc:
        print(json.dumps({'status':'denied','reason':str(exc)},sort_keys=True))
        return 1

if __name__=='__main__':raise SystemExit(main())
