"""Linux UNIX SOCK_SEQPACKET authenticated sealed-data handoff.

The receiver MUST independently trust the approved digest and UID policy.
An OS UID is not by itself an application-level signer identity.
Only inert verified bytes are returned; nothing is authorized for execution.
"""
import array
import hmac
import json
import os
import re
import secrets
import socket
import struct
from .provenance_guard import Denied, _require
from .sealed_handoff_v11 import consume_authorized_sealed_fd, MAX_DATA

PROTOCOL = 1
HEADER_MAX = 1024
NONCE_LEN = 32
MAX_FDS = 4
DIGEST_RE = re.compile(r"[a-f0-9]{64}\Z")


def _assert_transport(conn):
    _require(conn.family == socket.AF_UNIX and
             (conn.type & 0xf) == socket.SOCK_SEQPACKET,
             'ipc_transport_must_be_seqpacket')


def kernel_peer(conn):
    """Linux SO_PEERCRED identifies the kernel-known socket peer."""
    _assert_transport(conn)
    try:
        pid, uid, gid = struct.unpack('3i', conn.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
    except (OSError, struct.error) as exc:
        raise Denied('ipc_peercred_unavailable') from exc
    _require(pid > 0 and uid >= 0 and gid >= 0, 'ipc_peercred_invalid')
    return {'pid': pid, 'uid': uid, 'gid': gid}


def send_sealed(conn, fd, proof, *, allowed_receiver_uid, allowed_receiver_pid=None):
    """Check receiver credentials before responding to its nonce with one FD."""
    _assert_transport(conn)
    _require(type(allowed_receiver_uid) is int and allowed_receiver_uid >= 0,
             'ipc_receiver_uid_policy_required')
    receiver = kernel_peer(conn)
    _require(receiver['uid'] == allowed_receiver_uid, 'ipc_receiver_uid_denied')
    if allowed_receiver_pid is not None:
        _require(type(allowed_receiver_pid) is int and allowed_receiver_pid > 0,
                 'ipc_receiver_pid_policy_invalid')
        _require(receiver['pid'] == allowed_receiver_pid, 'ipc_receiver_pid_denied')
    _require(conn.gettimeout() is not None, 'ipc_timeout_required')
    _require(type(fd) is int and fd >= 0, 'invalid_handoff_descriptor')
    _require(isinstance(proof, dict), 'invalid_handoff_proof')
    try:
        nonce = conn.recv(NONCE_LEN + 1)
        _require(len(nonce) == NONCE_LEN, 'ipc_challenge_invalid')
        payload = json.dumps({'version': PROTOCOL, 'challenge': nonce.hex(),
            'sha256': proof.get('sha256'), 'length': proof.get('length')},
            separators=(',', ':'), sort_keys=True).encode('ascii')
        _require(len(payload) <= HEADER_MAX, 'ipc_header_too_large')
        sent = conn.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                          array.array('i', [fd]))])
        _require(sent == len(payload), 'ipc_short_send')
    except OSError as exc:
        raise Denied('ipc_send_failure') from exc


def _decode_exact_json(payload):
    def unique_pairs(pairs):
        obj = {}
        for k, v in pairs:
            _require(k not in obj, 'ipc_duplicate_key')
            obj[k] = v
        return obj
    try:
        header = json.loads(payload.decode('utf-8'), object_pairs_hook=unique_pairs)
    except (ValueError, UnicodeError) as exc:
        if isinstance(exc, Denied):
            raise
        raise Denied('ipc_invalid_json_header') from exc
    _require(isinstance(header, dict) and set(header) ==
             {'version', 'challenge', 'sha256', 'length'}, 'ipc_header_schema_invalid')
    return header


def receive_authorized(conn, *, trusted_expected_sha256, allowed_uid,
                       allowed_pid=None, max_bytes=1024 * 1024):
    """Receive a single sealed FD only from a credential-approved socket peer.

    Trusted digest and peer identity must come from protected parent policy,
    NOT from untrusted IPC header. Close every received FD even upon failure.
    """
    _assert_transport(conn)
    _require(conn.gettimeout() is not None, 'ipc_timeout_required')
    _require(type(allowed_uid) is int and allowed_uid >= 0, 'ipc_uid_policy_required')
    _require(allowed_pid is None or (type(allowed_pid) is int and allowed_pid > 0),
             'ipc_pid_policy_invalid')
    _require(isinstance(trusted_expected_sha256, str) and
             DIGEST_RE.fullmatch(trusted_expected_sha256), 'invalid_trusted_digest')
    _require(type(max_bytes) is int and 0 < max_bytes <= MAX_DATA,
             'invalid_handoff_limit')
    peer = kernel_peer(conn)
    _require(peer['uid'] == allowed_uid, 'ipc_peer_uid_denied')
    if allowed_pid is not None:
        _require(peer['pid'] == allowed_pid, 'ipc_peer_pid_denied')
    # Connection credentials alone are fixed at connection time. Requiring
    # kernel-generated SCM_CREDENTIALS for EACH message detects socket
    # delegation from an approved process to a different sender.
    try:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    except OSError as exc:
        raise Denied('ipc_message_credentials_unavailable') from exc
    challenge = secrets.token_bytes(NONCE_LEN)
    fds = []
    try:
        conn.sendall(challenge)
        payload, controls, flags, _ = conn.recvmsg(
            HEADER_MAX, socket.CMSG_SPACE(MAX_FDS * array.array('i').itemsize)
            + socket.CMSG_SPACE(struct.calcsize('3i')),
            socket.MSG_CMSG_CLOEXEC)
        sender_creds = []
        for level, typ, data in controls:
            if level == socket.SOL_SOCKET and typ == socket.SCM_CREDENTIALS:
                _require(len(data) >= struct.calcsize('3i'), 'ipc_malformed_credentials')
                pid,uid,gid = struct.unpack('3i',data[:struct.calcsize('3i')])
                sender_creds.append({'pid':pid,'uid':uid,'gid':gid})
            elif level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
                ints = array.array('i')
                ints.frombytes(data[:len(data) - len(data) % ints.itemsize])
                fds.extend(ints)
            else:
                raise Denied('ipc_unexpected_ancillary')
        _require(len(sender_creds) == 1, 'ipc_expected_message_credentials')
        _require(sender_creds[0] == peer, 'ipc_delegated_socket_sender')
        _require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC),
                 'ipc_truncated_message')
        _require(len(fds) == 1, 'ipc_expected_single_fd')
        header = _decode_exact_json(payload)
        _require(type(header['version']) is int and header['version'] == PROTOCOL,
                 'ipc_protocol_version_mismatch')
        _require(isinstance(header['challenge'], str) and
                 hmac.compare_digest(header['challenge'], challenge.hex()),
                 'ipc_challenge_mismatch')
        proof = {'sha256': header['sha256'], 'length': header['length']}
        payload_bytes = consume_authorized_sealed_fd(
            fds[0], proof, trusted_expected_sha256=trusted_expected_sha256,
            max_bytes=max_bytes)
        return payload_bytes, peer
    except OSError as exc:
        raise Denied('ipc_receive_failure') from exc
    finally:
        for fd in fds:
            os.close(fd)
