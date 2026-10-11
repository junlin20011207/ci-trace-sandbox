# CI-TRACE CTA001 research baseline

The detector reports possible cross-workflow artifact trust boundaries. It is a **triage heuristic**, not an exploit verifier. A finding does not demonstrate that downloaded bytes reach executed code or that elevated privileges exist.

## Running
```sh
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m ci_trace.scanner .github/workflows
```

## Constraints
- Untrusted producer heuristically identified by pull_request or pull_request_target.
- Workflow_run consumer linked by the producer's workflow name.
- Upload/download steps located by known actions or gh run download.
- Execution is a broad shell command heuristic, not path-sensitive taint analysis.
- YAML may use unsupported dynamic expressions, reusable workflows or composite actions.
- Unknown outcomes must be evaluated separately from confirmed true/false positives.

## Next research tasks
Implement artifact path/name provenance, default extraction destinations, real command reachability, privilege and checkout control, then evaluate a frozen labeled GitHub Actions dataset. Compare against zizmor and Poutine using identical inputs; do not claim hosted CI validation until the GitHub Actions run is checked.
