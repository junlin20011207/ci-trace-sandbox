"""V10 post-extraction integrity checks; reuse the same benign V9/V10 fixture."""
import json
from pathlib import Path
import pytest
from test_snapshot_v10 import fixture
from ci_trace.snapshot_guard_v10 import verify_and_extract_snapshot
from ci_trace.verified_reader_v10 import read_verified_member
from ci_trace.provenance_guard import Denied

def ready(tmp_path):
    archive, swap, e, api, p, out, ws, package, keys = fixture(tmp_path)
    return verify_and_extract_snapshot(archive, e, api, p, out, ws)

def test_exact_bytes_are_consumed(tmp_path):
    record=ready(tmp_path)
    assert json.loads(read_verified_member(record, 'report.json'))=={'payload':'VALID'}

def test_postrelease_same_size_mutation_rejected(tmp_path):
    record=ready(tmp_path)
    path=Path(record['release_dir'])/'report.json'
    raw=path.read_bytes()
    path.write_bytes(raw.replace(b'VALID', b'EVILL'))
    assert path.stat().st_size==len(raw)
    with pytest.raises(Denied, match='member_content_changed'):
        read_verified_member(record,'report.json')

def test_postrelease_leaf_symlink_rejected(tmp_path):
    record=ready(tmp_path)
    path=Path(record['release_dir'])/'report.json'
    other=tmp_path/'fake.json'
    other.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(other)
    with pytest.raises(Denied, match='member_open_failed'):
        read_verified_member(record,'report.json')

def test_member_not_in_manifest_rejected(tmp_path):
    record=ready(tmp_path)
    with pytest.raises(Denied, match='file_not_in_verified_manifest'):
        read_verified_member(record,'extra.json')

def test_path_escape_rejected(tmp_path):
    record=ready(tmp_path)
    with pytest.raises(Denied, match='member_path_escape'):
        read_verified_member(record,'../report.json')

def test_manifest_modified_in_memory_causes_denial(tmp_path):
    record=ready(tmp_path)
    record['file_manifest'][0]['sha256']='0'*64
    with pytest.raises(Denied, match='member_content_changed'):
        read_verified_member(record,'report.json')
