"""Kernel-enforced immutable handoff of a V10 verified data member.

Linux only. A sealed memfd cannot be written, grown or shrunk, even by a
process given a descriptor. The consumer gets only a data descriptor, not
an authorization to execute, publish, or perform a privileged operation.
"""
import fcntl
import hashlib
import os
import stat
from .provenance_guard import Denied, _require
from .verified_reader_v10 import read_verified_member

# Linux UAPI MFD_NOEXEC_SEAL, needed when os omits the constant.
MFD_NOEXEC_SEAL = getattr(os, 'MFD_NOEXEC_SEAL', 0x0008)
REQUIRED_SEALS = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                  fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
MAX_DATA = 8 * 1024 * 1024


def seal_bytes(data, *, limit=1024 * 1024):
    """Return one caller-owned, sealed, non-executable memfd and its digest.

    No mutable filesystem paths are returned. Caller MUST close fd.
    """
    _require(isinstance(data, bytes), 'invalid_handoff_bytes')
    _require(type(limit) is int and 0 < limit <= MAX_DATA, 'invalid_handoff_limit')
    _require(len(data) <= limit, 'handoff_size_exceeded')
    _require(hasattr(os, 'memfd_create'), 'memfd_unavailable')
    fd = None
    try:
        fd = os.memfd_create('ci-trace-verified-data',
            flags=os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        _require(offset == len(data), 'handoff_short_write')
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, REQUIRED_SEALS)
        actual = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        _require(actual & REQUIRED_SEALS == REQUIRED_SEALS, 'handoff_not_sealed')
        _require((os.fstat(fd).st_mode & 0o111) == 0, 'handoff_executable')
        proof = {'sha256': hashlib.sha256(data).hexdigest(), 'length': len(data),
                 'seals': actual, 'kernel_immutable': True,
                 'safe_to_execute_or_publish': False}
        return fd, proof
    except (OSError, ValueError) as exc:
        if fd is not None:
            os.close(fd)
        if isinstance(exc, Denied):
            raise
        raise Denied('sealed_handoff_unavailable') from exc


def seal_verified_member(record, name, *, limit=1024 * 1024):
    """Prove the V10 commitment then seal exactly the verified byte copy."""
    data = read_verified_member(record, name, max_bytes=limit)
    return seal_bytes(data, limit=limit)


def consume_sealed_fd(fd, proof, *, max_bytes=1024 * 1024):
    """Consumer checks seals, digest and size *on the received descriptor*."""
    _require(type(fd) is int and fd >= 0, 'invalid_handoff_descriptor')
    _require(isinstance(proof, dict), 'invalid_handoff_proof')
    _require(type(max_bytes) is int and 0 < max_bytes <= MAX_DATA,
             'invalid_handoff_limit')
    try:
        seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
        _require(seals & REQUIRED_SEALS == REQUIRED_SEALS, 'handoff_not_sealed')
        st = os.fstat(fd)
        _require(stat.S_ISREG(st.st_mode) and not (st.st_mode & 0o111),
                 'handoff_not_regular_data')
        _require(type(proof.get('length')) is int and 0 <= proof['length'] <= max_bytes,
                 'invalid_handoff_proof')
        _require(st.st_size == proof['length'], 'handoff_length_mismatch')
        data = os.pread(fd, max_bytes + 1, 0)
        _require(len(data) == proof['length'], 'handoff_length_mismatch')
        _require(hashlib.sha256(data).hexdigest() == proof.get('sha256'),
                 'handoff_digest_mismatch')
        return data
    except OSError as exc:
        raise Denied('handoff_read_failed') from exc


def consume_authorized_sealed_fd(fd, proof, *, trusted_expected_sha256, max_bytes=1024 * 1024):
    """Bind sealed data to the digest supplied by an INDEPENDENT trusted parent.

    Passing the trusted_expected_sha256 from the same untrusted peer as the fd
    is NOT authentication. The digest must originate from verified provenance.
    """
    import hmac
    import re
    _require(isinstance(trusted_expected_sha256, str) and
             re.fullmatch(r'[a-f0-9]{64}', trusted_expected_sha256),
             'invalid_trusted_digest')
    _require(isinstance(proof, dict) and
             isinstance(proof.get('sha256'), str) and
             hmac.compare_digest(trusted_expected_sha256, proof['sha256']),
             'handoff_not_authorized')
    return consume_sealed_fd(fd, proof, max_bytes=max_bytes)
