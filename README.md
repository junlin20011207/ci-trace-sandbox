## V12 — Kernel-message-authenticated UNIX sealed-data transfer

[Draft PR #10](https://github.com/junlin20011207/ci-trace-sandbox/pull/10) · [ROUND12_REPORT.md](ROUND12_REPORT.md)

V11's sealed FD + hash preserves bytes but does not authenticate remote process identity. V12 adds mutual Linux `SO_PEERCRED` checks, **per-message `SCM_CREDENTIALS`** checks, a 256-bit fresh challenge, framed `SOCK_SEQPACKET` and exactly-one-`SCM_RIGHTS` FD. The receiver must already possess the independently authorized expected SHA-256.

A falsification experiment showed an authorized process A could pass its connected socket to B: `SO_PEERCRED` continued to report A while `SCM_CREDENTIALS` identified B. V12 now rejects this delegation mismatch.

Reproduce on Linux: `python -m pytest -q`, `python -m benchmarks.v12_ipc --trials 30`. The branch also runs actual benign prior-run GitHub Artifact -> V11 signed seal -> V12 independent child process protocol on a hosted runner.

**Not a new Linux primitive or production trusted identity system.** UID/PID alone do not implement organization authorization, and protected signer/digest/policy infrastructure is not deployed. V12 returns inert bytes only, never authorization to execute or publish.

---

## V11 — Kernel-sealed, provenance-bound data handoff (research only)

[Draft PR #9](https://github.com/junlin20011207/ci-trace-sandbox/pull/9) · [ROUND11_REPORT.md](ROUND11_REPORT.md)

V10 **already safely detects postrelease mutation if its committed-byte reader is used**. V11 reduces downstream cross-process API misuse by issuing a non-executable Linux sealed memfd instead of asking consumers to reopen a mutable filesystem path.

- `ci_trace/sealed_handoff_v11.py`: kernel `memfd_create` + immutable seals, read-only data verification, independent trusted digest requirement.
- `ci_trace/sealed_signed_release_v11.py`: one-call signed origin -> verified ZIP snapshot -> sealed member, with staging cleanup and no filename handoff.
- `benchmarks/v11_handoff.py`: 30 mutation controls each for unsafe raw-path usage, **correct V10 manifest usage**, and sealed V11 descriptor.
- `benchmarks/v11_cost.py`: Linux single-runner microbenchmark; excludes network and full pipeline costs.

Reproduce: `python -m pytest -q`, `python -m benchmarks.v11_handoff`, and `python -m benchmarks.v11_cost`.

**This is a data-only capability, not an arbitrary artifact executor.** Original Linux seals and signed provenance are existing technologies; production signers and independent trust roots remain undeployed.

---

## V10 — Verified bytes are the bytes consumed (experimental)

[Draft PR #8](https://github.com/junlin20011207/ci-trace-sandbox/pull/8) · [ROUND10_REPORT.md](ROUND10_REPORT.md)

A new, **deterministically reproduced V9 digest-to-extraction TOCTOU flaw** existed because V9 hashed a ZIP by pathname and then reopened the mutable pathname for extraction. The same file path could refer to different bytes at those two stages, including after valid signed approval.

- `ci_trace/snapshot_guard_v10.py` checks and unpacks exactly one immutable bounded ZIP byte snapshot, not a re-opened pathname.
- `ci_trace/signed_snapshot_v10.py` and `github_signed_gate_v10.py` retain authenticated GitHub REST and signed approval requirements while using the repaired release path.
- `ci_trace/verified_reader_v10.py` returns only content matching an in-memory digest commitment using Linux no-follow descriptor traversal.
- `ci_trace/json_consumer_v10.py` handles schema-limited inert JSON in the same trusted process and deletes the temporary release directory after consumption.
- `benchmarks/v10_path_swap.py` reproduces the V9 violation and V10 counterfactual with controlled real local ZIP file replacement; `benchmarks/v10_cost.py` measures performance trade-offs.

Reproduce:

```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.v10_path_swap --trials 40
python -m benchmarks.v10_cost
python -m ci_trace.github_signed_gate_v10 --help
```

**Security boundary:** In a real deployment, protected public keys, signed approval subject and trusted policy must be managed separately from PR-controlled code. V10 neither proves remote exploitability of the V9 prototype flaw nor makes arbitrary artifact bytes safe to execute/publish. Ordinary code that reopens a released path instead of using the sink-bound API is outside the postrelease integrity guarantee.

---

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
