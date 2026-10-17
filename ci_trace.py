#!/usr/bin/env python3
"""One-command, offline competition demonstration over preserved research artifacts.

The local publisher is intentionally restricted to disposable Git repositories.
The archived Gitee proof is read-only historical evidence, never a release target.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LAB = ROOT / "lab"
ARCHIVE = ROOT / "evidence/r27/CI_TRACE_R27_Deep_Gitee_Proof.zip"
ARCHIVE_SHA256 = "0426dd4dca6e0222d5c168ab08a5efdddca91e60265ed4fb6544a4120f4307db"
TRUSTED_LAB_PUBLIC_SHA256 = "8c648b361866cc1144788f7ff1317420e683a8ba3c819427dc45697877edd45d"


def command(args: list[str], cwd: Path) -> str:
    process = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=120)
    if process.returncode:
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(args)}\n"
            f"stdout: {process.stdout[-3000:]}\nstderr: {process.stderr[-3000:]}"
        )
    return process.stdout


def json_command(args: list[str], cwd: Path):
    return json.loads(command(args, cwd))


def extract_r27(destination: Path) -> Path:
    actual = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
    if actual != ARCHIVE_SHA256:
        raise RuntimeError(f"R27 archive SHA-256 mismatch: {actual}")
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ARCHIVE) as archive:
        for item in archive.infolist():
            path = Path(item.filename)
            if path.is_absolute() or ".." in path.parts or item.is_dir() and item.file_size:
                raise RuntimeError("unsafe archive entry")
        archive.extractall(destination)
    if not (destination / "verify_deep.py").is_file():
        raise RuntimeError("R27 verifier missing")
    return destination


def verify_r27(bundle: Path, *, expect_valid: bool = True) -> dict:
    process = subprocess.run(
        [
            sys.executable,
            str(bundle / "verify_deep.py"),
            "--bundle",
            str(bundle),
            "--trusted-public-sha256",
            TRUSTED_LAB_PUBLIC_SHA256,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=120,
    )
    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"R27 verifier produced no JSON: {process.stderr[-1000:]}") from error
    if bool(result.get("valid")) != expect_valid or process.returncode != (0 if expect_valid else 2):
        raise RuntimeError(f"unexpected R27 result: {result} (exit {process.returncode})")
    return result


def demonstrate(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ci-trace-entry-") as tmp:
        temporary = Path(tmp)
        platform_results = {}
        for platform in ("CODEARTS", "GITEE_GO"):
            public_export = temporary / platform.lower()
            result = json_command(
                [
                    sys.executable,
                    "-m",
                    "native_cn.demo_export",
                    "--platform",
                    platform,
                    "--output",
                    str(public_export),
                ],
                LAB,
            )
            if result["verified"] is not True or result["gitee_remote_updated"] is not False:
                raise RuntimeError(f"local SM2 demo failed: {platform}")
            platform_results[platform] = {
                "verified": True,
                "public_key_sha256": result["issuer_public_sha256"],
                "environment": result["execution_backend"],
                "vendor_pipeline_executed": result["cloud_product_integrated"],
            }
        local_scenarios = json_command([sys.executable, "demo_engine.py", "--all"], LAB)
        if len(local_scenarios) != 9 or not all(row["passed"] for row in local_scenarios):
            raise RuntimeError("local protocol scenario failure")

        bundle = extract_r27(temporary / "r27")
        historical = verify_r27(bundle)
        if historical.get("valid") is not True:
            raise RuntimeError("historical Gitee LAB archive failed offline verification")
        object_file = bundle / "proof/objects/merge_commit.raw"
        object_file.write_bytes(object_file.read_bytes() + b"\n")
        tampered = verify_r27(bundle, expect_valid=False)
        if tampered.get("valid") is not False:
            raise RuntimeError("tampered local copy was accepted")

    summary = {
        "schema": "CI-TRACE competition demo v1",
        "local_sm2_platform_contracts": platform_results,
        "local_git_protocol": {
            "scenario_count": len(local_scenarios),
            "passed": sum(bool(row["passed"]) for row in local_scenarios),
            "outcomes": {row["scenario"]: row["decision"] for row in local_scenarios},
            "environment": "DISPOSABLE_LOCAL_BARE_GIT",
        },
        "archived_real_gitee_web_merge": {
            "offline_valid": True,
            "verifier_reason": historical["reason"],
            "archive_sha256": ARCHIVE_SHA256,
            "lab_public_key_sha256": TRUSTED_LAB_PUBLIC_SHA256,
            "tampered_local_copy_rejected": True,
            "gitee_write_during_this_demo": False,
        },
        "hosted_public_witness": {
            "run_url": "https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/39031776743",
            "attestation_url": "https://github.com/junlin20011207/ci-trace-sandbox/attestations/56943794",
            "checked_online_during_this_demo": False,
        },
        "claim_boundary": (
            "Local SM2/Git tests, archived real Gitee Web merge and past hosted readback "
            "are separate evidence types; none proves a vendor-signed approval or Git CLI push denial."
        ),
    }
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="CI-TRACE offline competition entry point")
    parser.add_argument("command", choices=("demo", "verify-gitee"))
    parser.add_argument("--output", type=Path, default=Path("run_output"))
    args = parser.parse_args()
    try:
        if args.command == "demo":
            result = demonstrate(args.output.resolve())
        else:
            with tempfile.TemporaryDirectory(prefix="ci-trace-proof-") as tmp:
                result = verify_r27(extract_r27(Path(tmp) / "r27"))
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (RuntimeError, OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"CI-TRACE failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
