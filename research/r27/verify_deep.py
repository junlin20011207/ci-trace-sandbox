"""Offline consistency check for the R26 signed LAB observation.

The prior receipt authenticates the LAB observer. This module recomputes Git
object IDs and relationships and checks archived public API snapshots against
that receipt. Public API snapshots are not vendor-signed attestations.
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "proposal"))
from crypto_sm import canonical, sm3, strict_json, verify
from verify_release import check as verify_r26


PIN = "8c648b361866cc1144788f7ff1317420e683a8ba3c819427dc45697877edd45d"
OID = re.compile(r"[0-9a-f]{40}\Z")
OBJECTS = {
    "base_commit": ("commit", "base_commit.raw"),
    "source_commit": ("commit", "source_commit.raw"),
    "merge_commit": ("commit", "merge_commit.raw"),
    "base_tree": ("tree", "base_tree.raw"),
    "source_tree": ("tree", "source_tree.raw"),
    "readme_blob": ("blob", "readme_blob.raw"),
}
COMMITTED_FILES = {
    "proof/object_manifest.json",
    *("proof/objects/" + filename for _, filename in OBJECTS.values()),
    "snapshots/pr1_merged_public_api.json",
    "snapshots/protected_branch_after_merge_api.json",
    "snapshots/master_after_merge_api.json",
}


def object_id(kind, data):
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()


def commit_fields(data):
    header = data.split(b"\n\n", 1)[0]
    fields = {}
    for line in header.split(b"\n"):
        if line.startswith((b"tree ", b"parent ", b"author ")):
            key, value = line.split(b" ", 1)
            fields.setdefault(key.decode(), []).append(value.decode("utf-8"))
    return fields


def tree_entries(data):
    entries = {}
    i = 0
    while i < len(data):
        space = data.index(b" ", i)
        end = data.index(b"\0", space)
        if end + 21 > len(data):
            raise ValueError("truncated tree")
        mode = data[i:space].decode("ascii")
        name = data[space + 1:end].decode("utf-8")
        if name in entries:
            raise ValueError("duplicate tree entry")
        entries[name] = (mode, data[end + 1:end + 21].hex())
        i = end + 21
    return entries


def load_snapshot(path, expected_url):
    wrapper = strict_json(path.read_bytes())
    if wrapper["status"] != 200 or wrapper["url"] != expected_url:
        raise ValueError("snapshot endpoint or status mismatch")
    return wrapper["response"]


def check(bundle, trusted_sha256=PIN):
    root = Path(bundle)
    baseline = verify_r26(root / "proposal", trusted_sha256)
    if not baseline.startswith("VALID_"):
        return "R26_" + baseline
    try:
        grant = strict_json((root / "proposal/grant.json").read_bytes())
        g = grant["body"]["payload"]
        evidence = strict_json((root / "proposal/merge_evidence.json").read_bytes())
        p, remote = evidence["pr"], evidence["remote"]
        extra = strict_json((root / "r27_receipt.json").read_bytes())
        if not verify(extra, str(root / "proposal/issuer_public.pem"), "receipt"):
            return "R27_RECEIPT_SIGNATURE_INVALID"
        extra_payload = extra["body"]["payload"]
        if (set(extra_payload) != {"operation_id", "r26_receipt_sm3", "proof_commitment_sm3", "backend", "business_authority"}
                or extra_payload["operation_id"] != g["operation_id"]
                or extra_payload["r26_receipt_sm3"] != sm3(canonical(strict_json((root / "proposal/receipt.json").read_bytes())))
                or extra_payload["backend"] != "OFFLINE_GIT_OBJECT_AND_API_SNAPSHOT_CROSSCHECK"
                or extra_payload["business_authority"] != g["business_authority"]):
            return "R27_RECEIPT_BINDING_MISMATCH"
        committed = strict_json((root / "proof_commitment.json").read_bytes())
        if (set(committed) != {"kind", "files"} or committed["kind"] != "R27_LAB_ARCHIVE_SHA256"
                or set(committed["files"]) != COMMITTED_FILES
                or sm3(canonical(committed)) != extra_payload["proof_commitment_sm3"]):
            return "PROOF_COMMITMENT_MISMATCH"
        for name, digest in committed["files"].items():
            if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
                return "PROOF_FILE_DIGEST_MISMATCH"
        manifest = strict_json((root / "proof/object_manifest.json").read_bytes())
        if set(manifest) != set(OBJECTS):
            return "PROOF_MANIFEST_INVALID"
        raw = {}
        expected = {
            "base_commit": g["expected_target_base"],
            "source_commit": g["source_commit"],
            "merge_commit": p["merge_commit"],
            "source_tree": g["source_tree"],
        }
        for label, (kind, filename) in OBJECTS.items():
            item = manifest[label]
            path = root / "proof/objects" / filename
            if (set(item) != {"kind", "oid", "file", "size", "sha256"}
                    or item["kind"] != kind or item["file"] != "objects/" + filename
                    or not isinstance(item["size"], int) or item["size"] < 0):
                return "PROOF_MANIFEST_INVALID"
            data = path.read_bytes()
            oid = object_id(kind, data)
            if (len(data) != item["size"] or oid != item["oid"]
                    or hashlib.sha256(data).hexdigest() != item["sha256"]
                    or not OID.fullmatch(oid)):
                return "GIT_OBJECT_ID_MISMATCH"
            if label in expected and oid != expected[label]:
                return "GIT_OBJECT_ID_MISMATCH"
            raw[label] = data
        base = commit_fields(raw["base_commit"])
        source = commit_fields(raw["source_commit"])
        merged = commit_fields(raw["merge_commit"])
        if (source.get("tree") != [g["source_tree"]]
                or source.get("parent") != [g["expected_target_base"]]
                or merged.get("tree") != [g["source_tree"]]
                or merged.get("parent") != [g["expected_target_base"], g["source_commit"]]
                or base.get("tree") != [manifest["base_tree"]["oid"]]):
            return "GIT_GRAPH_MISMATCH"
        base_entries = tree_entries(raw["base_tree"])
        entries = tree_entries(raw["source_tree"])
        if (entries.get("README.md") != ("100644", manifest["readme_blob"]["oid"])
                or raw["readme_blob"] != (root / "proposal/README.control.md").read_bytes()
                or sm3(raw["readme_blob"]) != g["artifact_sm3"]):
            return "GIT_ARTIFACT_MISMATCH"
        if (set(base_entries) != set(entries)
                or base_entries["README.md"][0] != "100644"
                or base_entries["README.md"] == entries["README.md"]
                or any(base_entries[k] != entries[k] for k in entries if k != "README.md")):
            return "GIT_CHANGED_PATHS_MISMATCH"

        prefix = "https://gitee.com/api/v5/repos/liljunlin/test/"
        pr = load_snapshot(root / "snapshots/pr1_merged_public_api.json", prefix + "pulls/1")
        branch = load_snapshot(root / "snapshots/protected_branch_after_merge_api.json", prefix + "branches/ci-trace-r26-protected-20261017")
        master = load_snapshot(root / "snapshots/master_after_merge_api.json", prefix + "branches/master")
        bc = branch["commit"]
        if (pr["number"] != p["number"] or pr["state"] != "merged"
                or pr["merged_at"] != p["merged_at"]
                or pr["user"]["login"] != p["author_login"]
                or pr["head"]["sha"] != g["source_commit"]
                or pr["head"]["ref"] != g["source_ref"].removeprefix("refs/heads/")
                or pr["base"]["ref"] != p["target_branch"]
                or pr["base"]["sha"] != g["expected_target_base"]):
            return "PR_SNAPSHOT_MISMATCH"
        if (branch["protected"] is not True or branch["name"] != p["target_branch"]
                or bc["sha"] != p["merge_commit"]
                or bc["commit"]["tree"]["sha"] != g["source_tree"]
                or [x["sha"] for x in bc["parents"]] != merged["parent"]
                or bc["author"]["login"] != p["merger_login"]
                or bc["commit"]["author"]["email"] not in merged.get("author", [""])[0]
                or bc["commit"]["message"].encode() != raw["merge_commit"].split(b"\n\n", 1)[1]):
            return "BRANCH_SNAPSHOT_MISMATCH"
        if (master["name"] != "master" or master["commit"]["sha"] != remote["master_after"]):
            return "MASTER_SNAPSHOT_MISMATCH"
        return "VALID_LAB_OBSERVATION_WITH_OFFLINE_GIT_OBJECT_AND_API_CONSISTENCY"
    except (OSError, ValueError, KeyError, TypeError, IndexError, UnicodeError):
        return "INVALID_OR_MISSING_PROOF"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--trusted-public-sha256", required=True)
    args = parser.parse_args()
    reason = check(args.bundle, args.trusted_public_sha256)
    valid = reason.startswith("VALID_")
    print(json.dumps({"valid": valid, "reason": reason,
                      "scope": "historical LAB observation; archived public API is not vendor-signed; no Git CLI push claim"},
                     ensure_ascii=False, sort_keys=True))
    return 0 if valid else 2


if __name__ == "__main__":
    raise SystemExit(main())
