"""Return only bytes that match V10's extraction-time content commitment.

The release record MUST be retained in trusted memory. This does not prove
execution or publishing safety, and no filesystem path is endorsed as safe.
Linux/GitHub-hosted Ubuntu platform assumptions: openat, O_NOFOLLOW.
"""
import hashlib
import os
import stat
from pathlib import PurePosixPath
from .provenance_guard import Denied, _require

MAX_READ_BYTES = 8 * 1024 * 1024

def read_verified_member(release_record, member_name, max_bytes=1024 * 1024):
    _require(isinstance(release_record, dict) and release_record.get('status') == 'approved'
             and release_record.get('snapshot_type') == 'immutable_bytes',
             'unverified_release_record')
    _require(isinstance(member_name, str) and member_name and
             '\\' not in member_name and '\x00' not in member_name,
             'invalid_member_name')
    parts = member_name.split('/')
    _require(all(p not in ('', '.', '..') for p in parts)
             and not PurePosixPath(member_name).is_absolute(), 'member_path_escape')
    manifest = release_record.get('file_manifest')
    _require(isinstance(manifest, list), 'missing_file_manifest')
    entries = [e for e in manifest if isinstance(e, dict) and e.get('path') == member_name]
    _require(len(entries) == 1, 'file_not_in_verified_manifest')
    expected = entries[0]
    _require(isinstance(max_bytes, int) and 0 < max_bytes <= MAX_READ_BYTES,
             'invalid_read_limit')
    _require(isinstance(expected.get('bytes'), int) and 0 <= expected['bytes'] <= max_bytes,
             'member_exceeds_read_limit')
    opened = []
    try:
        root_fd = os.open(release_record['release_dir'],
                          os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.append(root_fd)
        cur = root_fd
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=cur)
            opened.append(nxt)
            cur = nxt
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=cur)
        opened.append(fd)
        stat_info = os.fstat(fd)
        _require(stat.S_ISREG(stat_info.st_mode), 'member_not_regular_file')
        _require(stat_info.st_size == expected['bytes'], 'member_length_changed')
        with os.fdopen(os.dup(fd), 'rb') as inp:
            data = inp.read(max_bytes + 1)
        _require(len(data) == expected['bytes'] and len(data) <= max_bytes,
                 'member_length_changed')
        _require(hashlib.sha256(data).hexdigest() == expected['sha256'],
                 'member_content_changed')
        return data
    except OSError as exc:
        raise Denied('member_open_failed') from exc
    finally:
        for fd in reversed(opened):
            os.close(fd)
