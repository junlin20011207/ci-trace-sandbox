"""Signed commit authorization for the ACTUAL checked-out Git revision.

For issue_comment and other events, workflow_run.head_sha can identify default
branch code, not the PR subject. This gate checks git HEAD directly, before
running PR code. Assumes trusted signature/public key and trusted runner.
"""
from pathlib import Path
import subprocess
from .provenance_guard import Denied, _require
from .signed_authorization import verify_approval_package

def _git(root,*args):
    cmd=['git','-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',
         '-C',str(root),*args]
    try:
        obj=subprocess.run(cmd,text=True,capture_output=True,check=True,
                           timeout=10,stdin=subprocess.DEVNULL)
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
        raise Denied('checkout_git_verification_failed') from exc
    return obj.stdout.strip()

def verify_approved_checkout(checkout,package,trusted_keys,now=None):
    record=verify_approval_package(package,trusted_keys,now=now)
    root=Path(checkout).resolve(strict=True)
    _require(root.is_dir(),'checkout_not_directory')
    top=Path(_git(root,'rev-parse','--show-toplevel')).resolve(strict=True)
    _require(top==root,'checkout_root_mismatch')
    sha=_git(root,'rev-parse','--verify','HEAD^{commit}')
    _require(sha==record['commit_sha'],'checked_out_commit_not_approved')
    _require(not _git(root,'status','--porcelain=v1','--untracked-files=all'),
             'checkout_not_clean')
    return {'status':'approved','approved_sha':sha,'checkout_root':str(root),
            'approval_signature_verified':True,'safe_to_execute_or_publish':False}
