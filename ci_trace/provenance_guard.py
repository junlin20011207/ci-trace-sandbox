"""Fail-closed CI artifact provenance and isolated extraction policy gate.

GitHub metadata MUST come from an authenticated GitHub API call, not from an
artifact member. This module has no network authority to independently verify
that a caller-provided metadata JSON file is genuine.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import zipfile

SHA = re.compile(r"[a-fA-F0-9]{40}")
DIGEST = re.compile(r"sha256:([a-fA-F0-9]{64})")


class Denied(ValueError):
    """A policy or archive violation; no artifact is released."""


def _require(condition, code):
    if not condition:
        raise Denied(code)


def _origin(event, artifact, policy):
    """Bind an authentic event to authentic GitHub API artifact metadata."""
    run = event.get('workflow_run')
    _require(isinstance(run, dict), 'missing_run_event')
    _require(run.get('id') == policy.get('expected_run_id'), 'run_id_not_expected')
    _require(run.get('conclusion') == 'success', 'producer_not_successful')
    _require(run.get('event') in policy.get('allowed_events', []), 'source_event_denied')
    _require(bool(SHA.fullmatch(str(run.get('head_sha', '')))), 'invalid_head_sha')
    repo = policy.get('repository')
    _require(isinstance(repo, str) and '/' in repo, 'invalid_repository_policy')
    _require(event.get('repository', {}).get('full_name') == repo, 'consumer_repo_mismatch')
    art_run = artifact.get('workflow_run')
    _require(isinstance(art_run, dict), 'missing_artifact_run')
    _require(art_run.get('id') == run['id'], 'artifact_from_other_run')
    _require(art_run.get('head_sha') == run['head_sha'], 'artifact_head_mismatch')
    _require(artifact.get('name') == policy.get('artifact_name'), 'artifact_name_mismatch')
    _require(artifact.get('expired') is False, 'artifact_expired')
    _require(isinstance(artifact.get('id'), int) and artifact['id'] > 0, 'invalid_artifact_id')
    if policy.get('require_same_repo', False):
        h = run.get('head_repository') or {}
        _require(h.get('full_name') == repo, 'foreign_head_repository')
    prefix = policy.get('branch_prefix')
    if prefix is not None:
        _require(isinstance(prefix, str) and prefix and
                 str(run.get('head_branch', '')).startswith(prefix), 'branch_not_authorized')
    match = DIGEST.fullmatch(str(artifact.get('digest', '')))
    _require(match is not None, 'missing_github_digest')
    return match.group(1).lower(), run


def _members(archive, allowed_extensions, max_entries, max_uncompressed):
    manifest = []
    seen = set()
    total = 0
    _require(archive.infolist(), 'empty_archive')
    _require(len(archive.infolist()) <= max_entries, 'too_many_archive_entries')
    for info in archive.infolist():
        name = info.filename
        _require(isinstance(name, str) and name and '\\' not in name and '\x00' not in name,
                 'invalid_archive_path')
        path = PurePosixPath(name)
        _require(not path.is_absolute() and not any(c in ('', '.', '..') for c in name.rstrip('/').split('/')),
                 'path_escape')
        _require(not re.match(r'^[a-zA-Z]:', name), 'drive_path')
        normalized = path.as_posix().rstrip('/')
        key = normalized.casefold()
        _require(key not in seen, 'duplicate_or_case_collision')
        seen.add(key)
        mode = (info.external_attr >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)
        _require(kind in (0, stat.S_IFDIR, stat.S_IFREG), 'special_archive_entry')
        _require(not stat.S_ISLNK(mode), 'symlink_member')
        _require(not (mode & (stat.S_ISUID | stat.S_ISGID)), 'privileged_mode')
        if info.is_dir():
            manifest.append((info, path, True))
            continue
        suffix = path.suffix.lower()
        _require(suffix in allowed_extensions, 'file_type_denied')
        total += info.file_size
        _require(total <= max_uncompressed, 'uncompressed_limit_exceeded')
        _require(info.compress_size > 0 or info.file_size == 0, 'compression_size_invalid')
        _require(info.file_size <= 100 * max(1, info.compress_size), 'compression_ratio_exceeded')
        manifest.append((info, path, False))
    return manifest


def _outside_workspace(root, workspace):
    root = Path(root).resolve(strict=True)
    workspace = Path(workspace).resolve(strict=True)
    _require(root.is_dir(), 'invalid_output_root')
    _require(root != workspace and workspace not in root.parents and root not in workspace.parents,
             'extraction_root_overlaps_workspace')
    return root


def verify_and_extract(archive_path, event, artifact_api, policy, output_root, workspace):
    """Return isolated extraction path and attested-to-metadata evidence.

    An untrusted JSON input cannot be used as an authentic GitHub API response.
    The caller must securely retrieve event and API metadata, separately from
    the archive, and enforce their authenticity and transport security.
    """
    _require(isinstance(policy, dict), 'invalid_policy')
    digest, run = _origin(event, artifact_api, policy)
    archive_path = Path(archive_path).resolve(strict=True)
    root = _outside_workspace(output_root, workspace)
    _require(root not in archive_path.parents, 'archive_in_extraction_root')
    _require(archive_path.stat().st_size <= int(policy.get('max_archive_bytes', 20 * 1024 * 1024)),
             'archive_size_limit_exceeded')
    with archive_path.open('rb') as stream:
        sha = hashlib.sha256()
        for chunk in iter(lambda: stream.read(65536), b''):
            sha.update(chunk)
    actual = sha.hexdigest()
    _require(actual == digest, 'artifact_digest_mismatch')
    extensions = policy.get('allow_extensions', ['.json', '.txt'])
    _require(isinstance(extensions, list) and bool(extensions) and
             all(isinstance(x, str) and x.startswith('.') for x in extensions),
             'invalid_extension_policy')
    stage = None
    success = False
    try:
        with zipfile.ZipFile(archive_path) as z:
            members = _members(z, set(extensions),
                               int(policy.get('max_entries', 100)),
                               int(policy.get('max_uncompressed_bytes', 1024 * 1024)))
            stage = Path(tempfile.mkdtemp(prefix='ci-trace-verified-', dir=root))
            for info, relative, directory in members:
                target = stage.joinpath(*relative.parts)
                if directory:
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info, 'r') as inp, target.open('xb') as out:
                    shutil.copyfileobj(inp, out, length=64 * 1024)
                os.chmod(target, 0o600)
        success = True
        return {'status': 'approved', 'release_dir': str(stage),
                'run_id': run['id'], 'artifact_id': artifact_api['id'],
                'archive_sha256': actual, 'head_sha': run['head_sha'],
                'head_branch_from_event': run.get('head_branch'),
                'rule': 'github_authenticated_metadata_required'}
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError) as exc:
        raise Denied('archive_unreadable_or_unsafe') from exc
    finally:
        if stage is not None and not success:
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', required=True)
    parser.add_argument('--event', required=True)
    parser.add_argument('--artifact-api', required=True)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--output-root', required=True)
    parser.add_argument('--workspace', required=True)
    args = parser.parse_args()
    try:
        obj = verify_and_extract(args.archive,
                                 json.loads(Path(args.event).read_text()),
                                 json.loads(Path(args.artifact_api).read_text()),
                                 json.loads(Path(args.policy).read_text()),
                                 args.output_root, args.workspace)
        print(json.dumps(obj, sort_keys=True))
        return 0
    except (Denied, ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({'status': 'denied', 'reason': str(exc)}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
