"""V10 signed approval + immutable ZIP snapshot enforcement.

No claim that returned paths are immutable after release or safe to execute.
"""
from .signed_authorization import verify_approval_package
from .authorization_binding import require_authorized_revision
from .snapshot_guard_v10 import verify_and_extract_snapshot

def verify_signed_snapshot_release(archive, event, artifact, policy, package, keys,
                                   output_root, workspace, now=None):
    approval = verify_approval_package(package, keys, now=now)
    binding = require_authorized_revision(event, artifact, policy, approval)
    result = verify_and_extract_snapshot(archive, event, artifact, policy, output_root, workspace)
    result['approval_binding'] = binding
    result['authorization_status'] = 'exact_revision_bound'
    result['approval_signature'] = {'verified': True, 'key_id': package['key_id'],
                                    'purpose': approval['purpose']}
    result['safe_to_execute_or_publish'] = False
    return result
