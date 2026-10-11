# CI-TRACE Round 9 — Signed Authorization, Immutable Revision and Runtime Enforcement
Date: 2026-10-11. Status: experimental Draft PR #7 (not production).

## Problem diagnosis
Earlier V3–V7 mostly accumulated static source/sink patterns on two known GHSL cases. The parallel V8 trust-gate already provided real GitHub REST identity checks, Artifact digest verification and isolated ZIP extraction, but *no independent maintainer-approved commit identity*. A run and artifact can be mutually authentic while an unapproved revision is deployed. SHA-256 verifies bytes match GitHub artifact storage; it does **not** establish those bytes were authorized or are benign.

The independent public September 2026 GHSL-2026-226 Marimo issue shows a same-second timestamp race between maintainer command authorization and later PR checkout. An original vulnerable Marimo workflow (commit `b4181abaf6bd896b6b0dac5490c9cf08269b590c`, Git blob SHA `90cdd8b3ecf29588d0e0654f33836489c223a7c1`) is frozen as `research_corpus/marimo_bot_toctou_vuln.yml`.

## Technical interventions — three rounds, not more scanner regexes
1. **Immutable approval SHA binding:** `ci_trace/authorization_binding.py` requires the GitHub API run HEAD and the artifact's workflow-run HEAD to match a distinct approval subject (`repository`, `run_id`, `commit_sha`, `artifact_name`). `ci_trace/github_authorized_gate.py` calls GitHub's authenticated REST API before verifying the ZIP.
2. **Cryptographically signed approval record:** `ci_trace/signed_authorization.py` verifies Ed25519 signatures over domain-separated canonical JSON including purpose and validity bounds, with a pinned trusted public-key mapping. `ci_trace/github_signed_gate.py` unifies authenticated REST verification, signature checking, SHA match, ZIP digest and isolated extraction. It rejects untrusted public-key or policy files stored inside the checkout workspace.
3. **Checkout-specific authorization:** `ci_trace/checkout_gate.py` validates the *actual* git HEAD and rejects dirty tracked/untracked checkout trees, solving the crucial scope mismatch where an `issue_comment` run's own `head_sha` can refer to default-branch code rather than the PR target. Must be invoked before any untrusted checkout code executes.

These are engineering combinations of known verification techniques, not a claim of first invention of Ed25519, content-addressing, GitHub Artifact provenance or an arbitrary formal taint engine.

## Measurements, including failed hypothesis
The first local mutation generator contained a test-data error: it replaced the approved SHA even for legitimate samples, producing **100 false denials**. This was corrected before final comparative measurements; the original failure is **not** evidence of a V9 runtime failure.

- Local Python V9 standalone suite: **85/85 passed** (signed approval, checkout gate, REST gate regression).
- Seeded **1000** *synthetic counterfactual* cases, seed `20261011`: 250 unchanged approved revisions and 750 changed revisions. In this controlled experiment, digest-only V8 accepted all 750 changed versions; V9 SHA binding accepted **0/750** and rejected **0/250** legitimate versions. The old timestamp comparison accepted 500 same-second changed versions. These were created to exercise a specified authorization invariant: **not real-world prevention rates**.
- Hosted GitHub Actions, initial V9: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38141931311 — **179 tests passed**; 400-case counterfactual test: V8 accepted 300 changed, V9 0; V9 rejected 0 unchanged.
- Hosted signed approval regression: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38142325646 — **196 tests passed**.
- Real GitHub API and innocuous historical artifact: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38142325731 — **success** for exact SHA approval, deliberately wrong SHA denial, Ed25519 verification, tampered signed record denial and the unified signed CLI. The Artifact is ID `11701577994`, source run `38138006392`, size 156 bytes, SHA-256 `b8359ff587ac13b80c68184bdf74194ad7df887a306f0911f819380a9b5bfca9`. Source run SHA `b6d81e195455f1681365b0cb5ce8e05803c638fb` was pinned in the experiment before calling the API.
- Latest checkout-specific GitHub CI is **separately tracked** from the above fixed run references. Check the most recent branch commit's GitHub Actions result before claiming its final pass count.

## Reproduce on PR branch
```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.revision_binding_v9 --cases 400
python -m benchmarks.public_cases_v7 --assert-results
```

The signed gate CLI accepts `--repository`, `--run-id`, `--artifact-id`, `--archive`, `--approval-package`, `--trusted-keys`, `--trusted-policy`, `--output-root` and `--workspace`, reading `GH_TOKEN` from the environment. It requires the trusted public keys and policy to resolve **outside** checkout. Test signing keys are generated ephemerally in CI; **no production signer credentials are bundled**.

## Scientific and security limitations
- **No production independent signer.** CI's ephemeral signing keys test cryptographic implementation but do not represent a real maintainer's approval. Approval keys must reside in an independent protected signing service; the runner must trust a pinned public key outside attacker-controlled inputs. File path separation alone does not establish operating-system integrity.
- **Marimo scope mismatch.** `workflow_run.head_sha` is not always the reviewed PR commit, especially under `issue_comment`. The checkout-specific gate mitigates only if the signed record binds the actual selected commit and the check occurs **before** executing any PR code. This project has not executed or exploited the real Marimo workflow.
- **Post-check TOCTOU.** A process could mutate a checkout after `git status`; freezing the tree, sandboxing, and not executing low-trust code with publisher privileges remain necessary.
- **Attestation distinction.** A GitHub Artifact API digest and a custom approval signature are not substitutes for verifying the build's OIDC/Sigstore artifact attestation. GitHub offers existing authenticated build provenance/attestation mechanisms; novelty claims must be benchmarked against those systems.
- **No blind large corpus or generalization estimate.** Public historical advisories were known during design; mutation labels are author-defined. Cannot report real-world precision/recall/attack-prevention rates.
- **No full authorization lifecycle proof.** Key rotation/revocation, approval issuance, protected policy updates, subject binding for reusable jobs, concurrency and multi-repo authorization have not been implemented end-to-end.
- **No unsafe executions.** Tests use inert ZIP contents and temporary Git checkouts, never execute untrusted PR code with privileged credentials.

## Sources
- GHSL-2026-226 (2026-09-16): https://securitylab.github.com/advisories/GHSL-2026-226_marimo-team_marimo_repository/
- GHSL-2026-204 / 225 historical sources: https://securitylab.github.com/advisories/GHSL-2026-204_spiffe_spire_repository/ and https://securitylab.github.com/advisories/GHSL-2026-225_actions_attest/
- GitHub Artifact REST API: https://docs.github.com/en/rest/actions/artifacts?apiVersion=2026-03-10
- GitHub build artifact attestations: https://docs.github.com/en/actions/concepts/security/artifact-attestations
- OWASP GitHub Actions security: https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html
- Zizmor limitations: https://docs.zizmor.sh/usage/

## Current best direction
Research should prioritize **authorization-bound provenance enforcement**, combining static risk path detection, authenticated REST artifact metadata, cryptographically protected commit approval, checked-out code identity and isolation. The competitive research gap is proving correct *subject binding* across diverse event types and workflows, not merely adding more known checks.
