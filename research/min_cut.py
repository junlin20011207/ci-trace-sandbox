"""CI-TRACE bounded trust-path minimum cut. Offline research model, not a GitHub Runner."""
import argparse
import itertools
import json
from pathlib import Path

def check(case, choice):
    if case.get("evidence_complete") is not True:
        return False, "UNKNOWN: provenance incomplete"
    byid = {p["id"]: p for p in case["patches"]}
    if len(set(choice)) != len(choice) or set(choice) - set(byid):
        return False, "invalid patch identifiers"
    selected = [byid[x] for x in choice]
    damaged = set().union(*(set(p.get("breaks_required", [])) for p in selected))
    covered = set().union(*(set(p["blocks"]) for p in selected))
    if damaged & set(case["required_release_paths"]):
        return False, "required release blocked"
    if set(case["risk_paths"]) - covered:
        return False, "risk path still reachable"
    return True, "bounded path-cut certificate valid"

def solve(case):
    if case.get("evidence_complete") is not True:
        return {"status": "UNKNOWN", "reason": "unresolved evidence"}
    risks = set(case["risk_paths"])
    required = set(case["required_release_paths"])
    patches = case["patches"]
    if not risks or len(risks) > 32 or len(patches) > 18:
        return {"status": "REFUSED", "reason": "unsupported graph size"}
    if len({p["id"] for p in patches}) != len(patches):
        return {"status": "REFUSED", "reason": "duplicate patch ids"}
    for p in patches:
        if type(p["cost"]) is not int or p["cost"] <= 0:
            return {"status": "REFUSED", "reason": "invalid cost"}
        if set(p["blocks"]) - risks or set(p.get("breaks_required", [])) - required:
            return {"status": "REFUSED", "reason": "unknown risk or release path"}
    safe = [p for p in patches if not set(p.get("breaks_required", [])) & required]
    best = None
    for k in range(len(safe) + 1):
        for subset in itertools.combinations(safe, k):
            cost = sum(p["cost"] for p in subset)
            if best is not None and cost > best[0]:
                continue
            covered = set().union(*(set(p["blocks"]) for p in subset))
            if risks <= covered:
                chosen = tuple(sorted(p["id"] for p in subset))
                candidate = (cost, len(chosen), chosen)
                if best is None or candidate < best:
                    best = candidate
    if best is None:
        return {"status": "UNSAT", "reason": "no release-preserving cut"}
    ok, description = check(case, best[2])
    assert ok, description
    return {"status": "OPTIMAL", "cost": best[0], "patches": list(best[2]),
            "certificate": description}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("case")
    args = ap.parse_args()
    result = solve(json.loads(Path(args.case).read_text(encoding="utf-8")))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result["status"] == "OPTIMAL" else 2)
