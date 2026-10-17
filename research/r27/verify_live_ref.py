"""Read-only freshness check for the historical R27 offline bundle.

This is separate from offline validation. It performs public HTTPS API reads
and a Git ls-remote; it never sends credentials or writes a remote ref.
"""
import argparse
import datetime
import json
import subprocess
import urllib.request
from pathlib import Path

from verify_deep import PIN, check
from proposal.crypto_sm import strict_json


def get_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": "CI-TRACE-R27-readonly"})
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise ValueError("HTTP status was not 200")
        return json.load(response)


def inspect(bundle, trusted_sha256):
    offline = check(bundle, trusted_sha256)
    if not offline.startswith("VALID_"):
        return {"valid": False, "reason": "OFFLINE_" + offline}
    root = Path(bundle)
    e = strict_json((root / "proposal/merge_evidence.json").read_bytes())
    prefix = "https://gitee.com/api/v5/repos/liljunlin/test/"
    pr = get_json(prefix + "pulls/1")
    branch = get_json(prefix + "branches/ci-trace-r26-protected-20261017")
    master = get_json(prefix + "branches/master")
    p = subprocess.run([
        "git", "ls-remote", "https://gitee.com/liljunlin/test.git",
        "refs/heads/master", "refs/heads/ci-trace-r26-protected-20261017",
        "refs/heads/ci-trace-r26-dev-control-20261017",
    ], check=True, capture_output=True, text=True, timeout=30)
    refs = dict(reversed(line.split("\t", 1)) for line in p.stdout.splitlines())
    expected = {
        "refs/heads/master": e["remote"]["master_after"],
        "refs/heads/ci-trace-r26-protected-20261017": e["remote"]["commit"],
        "refs/heads/ci-trace-r26-dev-control-20261017": e["pr"]["source_commit"],
    }
    valid = (refs == expected and pr["state"] == "merged"
             and pr["merged_at"] == e["pr"]["merged_at"]
             and branch["protected"] is True
             and branch["commit"]["sha"] == e["remote"]["commit"]
             and master["commit"]["sha"] == e["remote"]["master_after"])
    return {
        "valid": valid,
        "reason": "CURRENT_PUBLIC_REFS_MATCH_HISTORICAL_LAB_OBSERVATION" if valid else "CURRENT_REMOTE_DRIFT_OR_MISMATCH",
        "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "refs": refs, "protected": branch["protected"], "pr_state": pr["state"],
        "scope": "read-only public API and Git check at observation time; no Git push or vendor attestation",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--trusted-public-sha256", default=PIN)
    args = parser.parse_args()
    try:
        result = inspect(args.bundle, args.trusted_public_sha256)
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, TimeoutError) as error:
        result = {"valid": False, "reason": "LIVE_CHECK_UNAVAILABLE", "error_type": type(error).__name__}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
