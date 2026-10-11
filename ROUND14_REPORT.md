# CI-TRACE Round 14 — Signed Approval and Crash-State Semantics with TLS Service Identity

Date: 2026-10-11. Status: **research-only**. Draft PR #12 (unmerged, based on V13).

## Root causes of six unresolved constraints

V13 enforces one-use local grants and real distinct-Linux-UID transport, but:
1. A valid artifact provenance/digest is not an **independently issued permission** to consume it.
2. An at-most-once grant can be burned by a crash before delivery; this is **not exactly-once business effect**.
3. Linux UID cannot identify different applications sharing the same account; ordinary file permissions do not isolate their private keys.
4. SCM_RIGHTS is local UNIX IPC and cannot directly cross a host boundary.
5. Success on one real historic benign Artifact + synthetic tests does not establish real-world security/business ROI.
6. Signed attestations, X.509 identities, SQLite transactions and supply-chain policy engines are existing prior art; simply composing them does not prove contest-leading novelty.


### Fourth falsification: same approved commit, different artifact subject

A late adversarial check revealed the first issuer allowlist compared only repository, commit SHA and recipient. Mutating the run ID, artifact ID or content SHA-256 could therefore receive a new issuer signature despite the expected approved artifact being different. The added test initially **failed as expected**. The allowlist was corrected to require an exact match across **repository, run ID, artifact ID, commit SHA, content SHA-256, recipient service identity**, and the test then passed. This is a safety-boundary defect in our experimental issuer, not a publicly exploited vulnerability.

## Three experimental routes

**A. Issuer and revocation.** The V14 Ed25519 authority signs a domain-separated, exact subject record binding repository, source run, Artifact ID, commit SHA, content SHA-256, recipient service URI and short time interval. A separately supplied allowlist constrains who can issue approvals; the protected SQLite store implements grant revoke, key revoke and one-use reservation. The issuer and protected policy have to be trusted: the demo uses ephemeral test keys, not organization authority.

**B. Fail-closed crash accounting.** The persistent grant state is `granted -> uncertain -> acknowledged`; revocation can change unclaimed `granted -> revoked`. A reservation is committed *before* transmitting bytes. Test code actually kills a child process using SIGKILL after the reservation, reopens SQLite, observes `uncertain` and denies replay. This **avoids automatic duplicate release** at the cost of potential lost delivery. It is not reliable exactly-once delivery.

**C. TCP/TLS identity.** A bounded data-only TLS 1.3 protocol mutually validates certificates against a test CA and checks each X.509 SAN URI as the workload service identity. A grant for service A is refused for service B, even when both applications run under the **same Linux UID**. The client independently validates the signed subject and content digest. An actual pair of separate Python processes transfers data across real TCP loopback. **No two different hosts were tested**: unshare network namespaces was denied in the sandbox.

## Measured results

### Independent sandbox (complete V13 and new V14 tests)
- **75 passed, 0 failed** with Python/Pytest in the local container; all V13 tests retained.
- One separate-process client/server TCP/TLS 1.3 transfer successfully issued and acknowledged.
- Five targeted TLS tests: valid transfer, wrong app identity, crash after reserve, missing ACK, wrong expected artifact digest; an additional explicit same-UID private-key-theft test passed by demonstrating the vulnerability.
- 10 groups of 100 concurrent claims: **10 wins and 990 denials** on randomly generated test grants, no group had two winners.
- Real child-process SIGKILL immediately after committed reservation: after SQLite restart, grant remained `uncertain` and retry was denied.
- 50 unchanged test-key signed records accepted, 250 author-generated tampered subject records rejected. **Not independent vulnerability ground truth.**

### GitHub-hosted integrated branch
- [Unit regression run #248](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38151659349): success, **264 passed, 2 root-only skipped** in the normal job, plus **3 separate root-run Linux UID tests passed**. Hosted branch adds five V14 assertions; the sandbox package contains the more extensive 18-assertion standalone V14 suite.
- [Real authentic benign GitHub Artifact gate #52](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38151659409): success, continuing V13 signed 22-byte proof and UID separation. **The new V14 mTLS test uses ephemeral test certificates and inert bytes, not GitHub OIDC certificates or a new production artifact.**
- [Benign Artifact layout #79](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38151659362), [zizmor scan #69](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38151659323): success. The zizmor alerts are in a different taxonomy and do not validate grant protocol safety.

## Reproduction

For the complete sandbox package:
```sh
python -m pip install -r requirements.txt
python -m pytest -q
python -m benchmarks.v14_recovery
python -m benchmarks.v14_mutations
```

Code: `ci_trace/approval_v14.py`, `ci_trace/mtls_v14.py`. The user-visible ZIP contains additional local two-process tests and crash injection. The GitHub draft branch contains a smaller self-contained hosted regression subset and retains older V3–V13 code. If CI versions diverge, treat their test counts independently; do not conflate 75 sandbox assertions with 264 hosted assertions.

## Six research obligations — degree of completion

| Gap | Demonstrated | Still unresolved |
|---|---|---|
| Independent approvals | signed exact subject, issuer allowlist, revoke grant/signing key | actual maintainer identity, protected HSM/TPM, approval audit/governance |
| Fault recovery | durable uncertain-state after actual SIGKILL; replay rejected | guaranteed delivery, downstream idempotency/reconciliation |
| Same UID apps | distinct X.509 service identity even same UID | same-UID ordinary 0600 private keys can be stolen; requires actual workload attestation/key protection |
| Cross-machine | TCP/TLS 1.3 on 2 actual processes | two independently hosted machines, routing, cert rotation and packet-loss tests |
| Business scale | small real historic benign Artifact retained; 1000 synthetic claims | blind independent sample, externally authorized operations, operational impact |
| Novelty | threat-model-specific compositional falsification | same-task comparison with SPIRE, GitHub attestation policy, in-toto and SLSA; independent expert review |

## Current best architecture

Retain V7–V13 source-to-sink evidence, API provenance, signed commit, ZIP byte snapshot, sealed local member, V12 IPC credentials and V13 one-use ledger. Add V14's independently signed short-lived **data-only permission** and application-level TLS certificate identity. For a real multi-host service, replace local FD transport with authenticated byte transfer; the actual protected signer should be isolated and backed by a workload identity authority.

Do **not** turn a signed grant or provenance proof into permission to execute untrusted artifact bytes or run a privileged Git command.

## Prior art and current standards

- SLSA v1.2 specification: https://slsa.dev/spec/v1.2/
- GitHub Artifact Attestations (build provenance and verification): https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/
- in-toto Attestation Framework: https://github.com/in-toto/attestation/blob/main/docs/README.md
- SPIRE workload attestation and selectors: https://spiffe.io/docs/latest/deploying/configuring/
- SPIFFE Workload API: https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/

**No contest award outcome, production zero-defect claim, general vulnerability-detection precision/recall or verified cross-machine deployment is inferred from these test results.**
