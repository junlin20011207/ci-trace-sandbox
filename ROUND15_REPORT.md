# CI-TRACE Round 15 — Idempotent Business Receipts, Isolated Signing and Revocation Atomicity

Research date: 2026-10-12. **Draft PR #15; not production-ready.** This round starts from V14 and preserves V3–V14.

## Root-cause findings and experiment rounds

**H1 — at-most-once grant ≠ at-most-one business outcome.** V14 records whether an authorization was consumed but cannot establish if the final data consumer durably committed a receipt when the network ACK was lost. V15 implements a *narrow, inert, SQLite-only* transactional receipt effect: the signed grant ID is the idempotency key; signed recipient and artifact SHA are verified; the issuer ledger must have a reserved/acknowledged grant; the receipt row and tally are written in a single ACID transaction. A retry returns the existing record without a second effect.

**H2 — same-UID private key theft.** Plain 0600 files do not separate applications sharing a UID. The V15 experimental \`issuer_agent_v15.py\` moves signing into a **different OS principal** and checks actual Linux SO_PEERCRED/SCM_CREDENTIALS on the request. An unprivileged client cannot open the protected signing-key file. This does not protect two independent processes which still share the signer UID or provide a production human approval authority.

**H3 — signing-key revocation check/use race.** V14 looked up key revocation before beginning the grant-reservation transaction. An injected revocation between those operations showed V14 could still reserve the grant. \`AtomicRevocationLedger\` moves the revoked-key lookup and grant state update into one SQLite BEGIN IMMEDIATE write transaction. The test makes the old behavior fail its intended property and the new implementation deny correctly.

**H4 — cross-runner portability.** New workflow \`.github/workflows/v15-two-runner-relay.yml\` uses an Ubuntu 22.04 issuer job and Ubuntu 24.04 consumer job. It exchanges an inert 44-byte message through GitHub Artifact storage; the consumer independently evaluates the signature and SHA-256. This demonstrates **two different hosted runner OS environments communicating asynchronously**, not online mTLS between two self-managed servers. The test signing key is generated within the workflow and its public key travels via authenticated job outputs; no organization approval is demonstrated.

## Reproducible evidence

### Latest hosted GitHub Actions

- [Full pytest/benchmark run #265](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38247040337): **270 passed, 3 skipped** in normal phase, plus **3 pre-existing V13 cross-UID tests and 1 additional V15 privileged key-custody test passed** in their separately executed root phases.
- Same run's V15 12x100 benchmark: **1,200 retry attempts, 12 durable receipt effects, 1,188 deduplicated responses**, median batch time **86.318 ms**. These are synthetic SQLite receipts, not production financial/business transactions or an end-to-end SLA.
- [Two-hosted-runner relay #2](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38247313691): both jobs succeeded. Real logs: 22.04 issuer, 24.04 consumer, **44 inert bytes verified**, store-and-forward, no online cross-host mTLS or protected signer.
- [Real prior-run benign authenticated GitHub Artifact baseline #58](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38247313975), [layout #85](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38247313653) and [zizmor external baseline #75](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38247313705) passed. These are *different* test objectives and do not establish V15 independent enterprise value.

### Independent local sandbox

- Reproduced V14 package base: **75 passed**.
- Expanded V15 sandbox: **86 passed**. Includes an actual child process SIGKILL **after** the SQLite receipt transaction commit; after reopening the database, a signed retry leaves exactly one persistent receipt. Also tests missing reservation, invalid recipient/content, 100 concurrent retries, key isolation under a different Linux UID, and V14/V15 revocation-order counterfactuals.
- Local 12x100 controlled benchmark: 12 receipts, 1,188 deduplicated retries; exploratory median per 100-attempt group **110.179 ms** on this sandbox host, not directly comparable with hosted runs.
- Downloadable standalone archive \`ci_trace_round15_package.zip\` contains the full local source, baseline compatibility tests, new tests, logs and benchmark report.

## Six unfinished security/competition dimensions

| Desired capability | Verified research progress | Still not verified |
|---|---|---|
| Independent production approvals | test-only Ed25519 issuer and protected UID-separated signing process; exact subject allowlist | independently operated human/organization approver, second approver, HSM/TPM, issuer audit/rotation/revocation governance |
| Exactly-once business outcome | **one SQLite ACID durable receipt** under repeated retries, ACK loss and postcommit SIGKILL | arbitrary external effects, e.g. actual Git pushes/payments/publication; distributed transactions; guaranteed delivery |
| Same-UID key theft | signing key is moved to a **different UID** so lower-privilege clients cannot read it | applications remaining under the *same* UID cannot isolate ordinary-file keys; workload attestation and nonextractable keys |
| Genuine multi-machine deployment | two distinct GitHub-hosted OS runner jobs exchange signed inert bytes via Artifact store | two independent self-managed servers with online mutual TLS, trusted issuer and failure injection |
| Large business value | 1,200 controlled retries, real GitHub-hosted transport & benign Artifact, no unsafe operations | blinded independently labeled real incidents, ROI/time-to-detect, customer production authorization |
| Contest originality proof | reproducible counterfactuals including a real internal revocation race, explicit threat-model invariants | comparative independent evaluations against SLSA, in-toto, GitHub Artifact Attestations, SPIRE/Cedar and existing idempotent consumer/outbox systems |

## Limitations and interpretive rules

- V15 does not provide exactly-once delivery, universal exactly-once business execution, arbitrary safe artifact execution, or a production independent approval authority.
- A business record and its counter are atomic **only inside the same SQLite database**. External side effects need their *own* idempotency/reconciliation protocol; a two-database issuer and consumer do not share a distributed transaction.
- Revocation is serialized with initial reservation, but revoking a key cannot undo previously committed legitimate receipts.
- An OS UID is not a high-assurance application identity; root, compromised signing service and same-principal processes remain trusted or out of scope.
- Github test job output as a public-key source is **not** an independent organization trust root.
- Old/V15 tests, benchmark labels and failure injection are author-constructed; no real-world prevention/precision/recall claims follow.

## Prior art and novelty

- GitHub Artifact Attestations link artifacts to build provenance. GitHub explicitly notes that attestations are not a guarantee that software is safe: https://docs.github.com/en/actions/concepts/security/artifact-attestations
- SLSA: https://slsa.dev/spec/v1.2/
- Cedar default-deny policy authorization: https://docs.cedarpolicy.com/auth/authorization.html
- SPIFFE/SPIRE workload identity: https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/

All of signed approval, SQLite idempotent receipts, kernel UID credential checks, and key-isolated services are existing mechanisms. V15's **defensible contribution** is an auditable *composition* with controlled counterexamples; this is not yet proved algorithmically novel or award-winning.

## Reproduce

\`\`\`bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.v15_effects
\`\`\`

On the GitHub branch, the two-OS-runner test runs as a separate GitHub Actions workflow. Leave PR in Draft and unmerged until an independent approved deployment and formal threat review.
