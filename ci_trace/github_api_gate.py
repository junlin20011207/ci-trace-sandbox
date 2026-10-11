"""Fetch bound GitHub Actions provenance from GitHub's authenticated REST API.

The archive remains a separate input. Never accept a provenance JSON from the
artifact or echo a token into logs. Trusted default-branch deployment required.
"""
import argparse
import json
import os
import re
from pathlib import Path
from urllib.request import Request, urlopen
from .provenance_guard import Denied, _require, verify_and_extract

REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')


def load_authenticated_metadata(repository, run_id, artifact_id, token, opener=urlopen):
    """Require exact immutable GitHub API origin and cross-object identity."""
    _require(bool(REPO.fullmatch(repository)), 'invalid_repo_identifier')
    _require(type(run_id) is int and run_id > 0, 'invalid_run_identifier')
    _require(type(artifact_id) is int and artifact_id > 0, 'invalid_artifact_identifier')
    _require(isinstance(token, str) and bool(token.strip()), 'missing_github_api_token')

    def fetch(path):
        url = 'https://api.github.com/repos/' + repository + '/' + path
        request = Request(url, headers={
            'Accept': 'application/vnd.github+json',
            'Authorization': 'Bearer ' + token,
            'X-GitHub-Api-Version': '2026-03-10',
            'User-Agent': 'ci-trace-provenance-guard'})
        try:
            with opener(request, timeout=20) as response:
                result = json.load(response)
        except (OSError, ValueError, TypeError) as exc:
            raise Denied('authenticated_github_api_request_failed') from exc
        _require(isinstance(result, dict), 'github_api_invalid_json')
        return result

    run = fetch(f'actions/runs/{run_id}')
    artifact = fetch(f'actions/artifacts/{artifact_id}')
    _require(run.get('id') == run_id, 'github_api_run_identity_mismatch')
    _require(artifact.get('id') == artifact_id, 'github_api_artifact_identity_mismatch')
    repo = run.get('repository') or {}
    _require(repo.get('full_name', '').lower() == repository.lower(), 'github_api_repo_mismatch')
    observed = artifact.get('workflow_run') or {}
    _require(observed.get('id') == run_id, 'github_api_artifact_from_other_run')
    _require(observed.get('head_sha') == run.get('head_sha'), 'github_api_sha_mismatch')
    if repo.get('id') is not None and observed.get('repository_id') is not None:
        _require(repo['id'] == observed['repository_id'], 'github_api_repository_id_mismatch')
    event = {'repository': {'full_name': repo['full_name']},
             'workflow_run': {
                 'id': run['id'], 'event': run.get('event'),
                 'head_sha': run.get('head_sha'),
                 'head_branch': run.get('head_branch'),
                 'head_repository': run.get('head_repository'),
                 'conclusion': run.get('conclusion')}}
    return event, artifact


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repository', required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--artifact-id', type=int, required=True)
    parser.add_argument('--token-env', default='GH_TOKEN')
    parser.add_argument('--archive', required=True)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--output-root', required=True)
    parser.add_argument('--workspace', required=True)
    args = parser.parse_args()
    try:
        event, artifact = load_authenticated_metadata(
            args.repository, args.run_id, args.artifact_id,
            os.environ.get(args.token_env, ''))
        policy = json.loads(Path(args.policy).read_text(encoding='utf-8'))
        outcome = verify_and_extract(args.archive, event, artifact, policy,
                                     args.output_root, args.workspace)
        print(json.dumps(outcome, sort_keys=True))
        return 0
    except (Denied, ValueError, OSError, json.JSONDecodeError) as err:
        print(json.dumps({'status': 'denied', 'reason': str(err)}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
