"""Signed provenance to sealed fd, entirely within one trusted function call.

The only released data capability is an immutable, non-executable memfd.
No authorization to execute arbitrary artifact files is inferred.
"""
import hmac
import shutil
from .provenance_guard import _require
from .signed_snapshot_v10 import verify_signed_snapshot_release
from .sealed_handoff_v11 import seal_verified_member

def issue_sealed_member(archive,event,artifact,policy,approval,keys,
                        output_root,workspace,member,*,max_bytes=1024*1024,now=None):
    record=verify_signed_snapshot_release(archive,event,artifact,policy,approval,
                                          keys,output_root,workspace,now=now)
    fd=None
    try:
        entries=[m for m in record['file_manifest'] if m['path']==member]
        _require(len(entries)==1,'member_not_in_verified_manifest')
        expected_digest=entries[0]['sha256']
        fd,proof=seal_verified_member(record,member,limit=max_bytes)
        _require(hmac.compare_digest(proof['sha256'],expected_digest),
                 'sealed_member_digest_mismatch')
        return fd, {'proof':proof,'trusted_expected_sha256':expected_digest,
                    'authorized_commit':record['approval_binding']['authorized_commit_sha'],
                    'source_run':record['run_id'],
                    'safe_to_execute_or_publish':False}
    except BaseException:
        if fd is not None:
            import os
            os.close(fd)
        raise
    finally:
        shutil.rmtree(record['release_dir'])
