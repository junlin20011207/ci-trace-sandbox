"""V10: use the exact immutable input bytes for both digest and extraction.

This removes V9's pathname-reopen TOCTOU. No claims about postrelease
mutation or arbitrary execution safety. Run only after authenticated API
metadata and signed authorization have been verified.
"""
import hashlib
import io
import os
from pathlib import Path
import shutil
import tempfile
import zipfile
from .provenance_guard import Denied, _require, _origin, _outside_workspace, _members

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024

def verify_and_extract_snapshot(archive_path, event, artifact_api, policy, output_root, workspace):
    _require(isinstance(policy, dict), 'invalid_policy')
    digest, run = _origin(event, artifact_api, policy)
    archive_path = Path(archive_path).resolve(strict=True)
    root = _outside_workspace(output_root, workspace)
    _require(root not in archive_path.parents, 'archive_in_extraction_root')
    configured_limit = int(policy.get('max_archive_bytes', 20 * 1024 * 1024))
    _require(0 < configured_limit <= MAX_ARCHIVE_BYTES, 'invalid_archive_limit')
    # Capture one bounded immutable byte snapshot. Never reopen archive_path
    # between the check and its use.
    with archive_path.open('rb') as stream:
        snapshot = stream.read(configured_limit + 1)
    _require(len(snapshot) <= configured_limit, 'archive_size_limit_exceeded')
    actual = hashlib.sha256(snapshot).hexdigest()
    _require(actual == digest, 'artifact_digest_mismatch')
    extensions = policy.get('allow_extensions', ['.json', '.txt'])
    _require(isinstance(extensions, list) and bool(extensions) and
             all(isinstance(x, str) and x.startswith('.') for x in extensions),
             'invalid_extension_policy')
    stage = None
    success = False
    file_manifest = []
    try:
        with zipfile.ZipFile(io.BytesIO(snapshot), 'r') as z:
            members = _members(z, set(extensions),
                               int(policy.get('max_entries', 100)),
                               int(policy.get('max_uncompressed_bytes', 1024 * 1024)))
            stage = Path(tempfile.mkdtemp(prefix='ci-trace-v10-', dir=root))
            for info, relative, is_dir in members:
                target = stage.joinpath(*relative.parts)
                if is_dir:
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                member_sha = hashlib.sha256()
                with z.open(info, 'r') as inp, target.open('xb') as out:
                    while True:
                        chunk = inp.read(64 * 1024)
                        if not chunk:
                            break
                        member_sha.update(chunk)
                        out.write(chunk)
                os.chmod(target, 0o600)
                file_manifest.append({'path': relative.as_posix(),
                                      'sha256': member_sha.hexdigest(),
                                      'bytes': info.file_size})
        success = True
        return {'status': 'approved', 'release_dir': str(stage),
                'run_id': run['id'], 'artifact_id': artifact_api['id'],
                'archive_sha256': actual, 'head_sha': run['head_sha'],
                'head_branch_from_event': run.get('head_branch'),
                'snapshot_type': 'immutable_bytes', 'file_manifest': file_manifest,
                'rule': 'same_snapshot_digest_and_extraction'}
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError) as exc:
        raise Denied('archive_unreadable_or_unsafe') from exc
    finally:
        if stage is not None and not success:
            shutil.rmtree(stage)
