"""GitHub REST authenticated artifact release with separately approved commit SHA."""
import argparse
import json
import os
from pathlib import Path
from .github_api_gate import load_authenticated_metadata
from .authorization_binding import verify_authorized_release
from .provenance_guard import Denied

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--repository',required=True)
    p.add_argument('--run-id',type=int,required=True)
    p.add_argument('--artifact-id',type=int,required=True)
    p.add_argument('--approved-sha',required=True)
    p.add_argument('--token-env',default='GH_TOKEN')
    p.add_argument('--archive',required=True)
    p.add_argument('--policy',required=True)
    p.add_argument('--output-root',required=True)
    p.add_argument('--workspace',required=True)
    args=p.parse_args()
    try:
        event,artifact=load_authenticated_metadata(args.repository,args.run_id,
                         args.artifact_id,os.environ.get(args.token_env,''))
        policy=json.loads(Path(args.policy).read_text(encoding='utf-8'))
        approval={'repository':args.repository,'run_id':args.run_id,
                  'artifact_name':policy.get('artifact_name'),
                  'commit_sha':args.approved_sha}
        output=verify_authorized_release(args.archive,event,artifact,policy,
                                         approval,args.output_root,args.workspace)
        print(json.dumps(output,sort_keys=True))
        return 0
    except (Denied,OSError,ValueError,TypeError,KeyError) as exc:
        print(json.dumps({'status':'denied','reason':str(exc)},sort_keys=True))
        return 1

if __name__=='__main__':raise SystemExit(main())
