## V9 — cryptographically bound approval (experimental)

New independent research branch: [V9 Draft PR](https://github.com/junlin20011207/ci-trace-sandbox/pull/7) and [ROUND9_REPORT.md](ROUND9_REPORT.md).

- `authorization_binding.py`: exact approved commit SHA is compared to authenticated GitHub run/artifact metadata; mismatch denies before extraction.
- `signed_authorization.py`: Ed25519 verification of signed approval records, issuer key allowlist, purpose, and time validity.
- `github_signed_gate.py`: combines authentic GitHub REST metadata with protected key/policy files, signed approval, digest verification, and ZIP isolation.
- `checkout_gate.py`: verifies a signed approval against **actual git HEAD** and a clean worktree, for event types where workflow run SHA does not denote reviewed PR code.
- `benchmarks/revision_binding_v9.py`: 400 seeded synthetic counterfactuals under hosted CI, not real vulnerabilities.

Usage: `python -m ci_trace.github_signed_gate --help`, `python -m pytest -q`, `python -m benchmarks.revision_binding_v9 --cases 400`.

**Trust boundary:** Approved signatures/public keys MUST originate from an independently protected approval service. The CI keys are ephemeral demonstration keys; this project does not provide production maintainer authorization or prove real-world attack prevention.

---

# CI-TRACE — Evidence-to-Enforcement for GitHub Actions Artifacts

Research prototype for defensive CI/CD supply-chain security and the Chinese Graduate Student Cybersecurity Innovation Competition creative works track.

## Capabilities

1. **V3–V6 structural scanning:** GitHub Actions workflow trigger matching, artifact identity, possible direct execution, path semantics, conditional evidence and unknown-state triage.
2. **V7 trust-boundary evidence:** explicit Artifact overlay into checked-out JavaScript helpers, and artifact metadata propagated into privileged Git ref write operations. Two independently disclosed GHSL workflows and their fixed versions are included as a small historical regression corpus.
3. **V8 runtime enforcement:** `ci_trace/provenance_guard.py` validates matching source runs/artifacts and SHA-256 digests, rejects unsafe ZIPs, and releases inert data only into a private directory outside checkout.
4. **Direct authentic source:** `ci_trace/github_api_gate.py` retrieves run/Artifact metadata directly from authenticated GitHub REST API and cross-checks object identity instead of trusting user-supplied provenance JSON.

## Reproduce

```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.public_cases_v7 --assert-results
python -m benchmarks.provenance_gate
python -m benchmarks.fuzz_gate
python -m ci_trace.scanner_v7 .github/workflows
```

## Operational runtime gate

Use only trusted default-branch code, a **trusted repository policy**, and an authenticated GitHub Actions read token:

```bash
export GH_TOKEN="..." # token must have Actions: read
python -m ci_trace.github_api_gate \
    --repository OWNER/REPO --run-id SOURCE_RUN_ID --artifact-id ARTIFACT_ID \
    --archive downloaded.zip --policy trusted-policy.json \
    --output-root "$RUNNER_TEMP/ci-trace-release" \
    --workspace "$GITHUB_WORKSPACE"
```

The policy is JSON requiring, for example, `repository`, `expected_run_id`, `artifact_name`, `allowed_events`, `allow_extensions`, `require_same_repo`, and optional `branch_prefix`. The output-root directory must already exist and must not contain, or lie within, the trusted checkout.

**Important:** A returned `approved` decision means only the *specific provenance/digest/layout policy* passed. It does not mean arbitrary artifact bytes are safe to execute or publish. Callers must enforce the result, keep the returned data isolated, and derive any sensitive branch selection from the trusted event rather than an artifact file.

## Evidence snapshot, 2026-10-11

- [V8 real authenticated GitHub Artifact gate run](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38139479227): GitHub Artifact API SHA-256 matched a 156-byte historical real ZIP; isolated release and direct authenticated-API checks passed; deliberately wrong run ID was denied.
- [Combined hosted CI](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38139650218): **162 Python tests passed**, 500 seeded synthetic mutations (200 expected allow, 300 expected deny) were classified as expected.
- [V7 public GHSL historical cases](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38137847258): V6 matched 2/4 known historical/fixed states; V7 matched 4/4. **Only two distinct vulnerabilities**, no precision/recall generalization.

Complete experiment design, caveats, relevant source documentation and next steps are in [ROUND8_REPORT.md](ROUND8_REPORT.md).

## Research safety and limitations

Every experiment is defensive; no untrusted artifact was executed under elevated permissions in a third-party repository. V8 combines standard known safety controls, and **novelty beyond existing security products has not yet been independently established**. The static scan and runtime enforcement are separate components; automatic end-to-end policy synthesis is not yet implemented. The control corpus is too small for real-world efficacy claims.

V8 research branch is intentionally a **Draft PR**, not a merged production deployment.
