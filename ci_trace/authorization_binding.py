"""Bind a cross-run artifact to an independently trusted approval snapshot.

The caller must obtain authorization from an immutable, protected source.
This module does NOT authenticate caller-supplied approval records.
"""
from .provenance_guard import Denied, _require, SHA, verify_and_extract


def require_authorized_revision(event, artifact, policy, authorization):
    """Require that the actual run and artifact match the approved commit."""
    _require(isinstance(event, dict) and isinstance(event.get('workflow_run'), dict),
             'missing_authenticated_event')
    _require(isinstance(artifact, dict), 'missing_authenticated_artifact')
    _require(isinstance(policy, dict), 'invalid_policy')
    _require(isinstance(authorization, dict), 'missing_trusted_authorization')
    required = ('repository', 'run_id', 'commit_sha', 'artifact_name')
    _require(all(k in authorization for k in required), 'incomplete_authorization_binding')
    expected_sha = authorization.get('commit_sha')
    _require(isinstance(expected_sha, str) and SHA.fullmatch(expected_sha) is not None,
             'invalid_authorized_sha')
    _require(expected_sha == expected_sha.lower(), 'unauthorized_sha_not_canonical')
    _require(authorization['repository'] == policy.get('repository'),
             'authorization_repository_mismatch')
    _require(type(authorization['run_id']) is int and authorization['run_id'] > 0,
             'authorization_run_id_invalid')
    _require(authorization['run_id'] == policy.get('expected_run_id'),
             'authorization_run_id_mismatch')
    _require(authorization['artifact_name'] == policy.get('artifact_name'),
             'authorization_artifact_name_mismatch')
    _require(event.get('repository', {}).get('full_name') == authorization['repository'],
             'authenticated_repository_not_authorized')
    run = event['workflow_run']
    _require(run.get('id') == authorization['run_id'], 'authenticated_run_not_authorized')
    _require(run.get('head_sha') == expected_sha, 'approved_commit_changed')
    linked = artifact.get('workflow_run') or {}
    _require(linked.get('id') == run['id'] and linked.get('head_sha') == expected_sha,
             'artifact_not_from_approved_commit')
    return {'authorized_repository': authorization['repository'],
            'authorized_commit_sha': expected_sha,
            'authorized_run_id': authorization['run_id']}


def verify_authorized_release(archive_path, event, artifact_api, policy,
                              authorization, output_root, workspace):
    """Reject mutable-revision substitutions before digest/isolation enforcement."""
    binding = require_authorized_revision(event, artifact_api, policy, authorization)
    result = verify_and_extract(archive_path, event, artifact_api, policy,
                                output_root, workspace)
    result['approval_binding'] = binding
    result['authorization_status'] = 'exact_revision_bound'
    result['safe_to_execute_or_publish'] = False
    return result
