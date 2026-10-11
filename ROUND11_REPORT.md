# CI-TRACE Round 11 — Kernel-sealed provenance-to-consumer handoff
Research date: 2026-10-11. Draft PR #9. All tests are defensive and use inert data.

## Core scientific result
V10 already **correctly rejects modified data** when callers use its `read_verified_member` function. However, a downstream component might incorrectly receive and reopen V10's ordinary extracted filesystem pathname. That bypasses the reader's contractual validation; it is a **consumer integration failure**, not a break of V10's correctly used security API.

V11 tests a Linux data-only *capability handoff* that replaces that mutable pathname with a **non-executable, kernel-sealed anonymous memfd**. The handoff is tied to a content digest produced by previously authenticated/signed V10 provenance.

### Competing hypotheses
- H1: raw-path reuse after V10 verification can yield different bytes; correct V10 revalidation detects this. **Confirmed in a deterministic mutation harness**.
- H2: Linux memfd with `MFD_ALLOW_SEALING | MFD_NOEXEC_SEAL` and `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL` prevents modification even by a child that receives the descriptor. **Confirmed in the sandbox and GitHub runner**.
- H3: sealing establishes *immutability but not authentic origin*. An attacker can create their own internally consistent sealed FD and matching digest. **Confirmed by falsification**; mitigated by requiring a separately trusted expected SHA-256 derived from V10's verified in-memory member commitment.
- H4: a single trusted call can compose signed provenance, one-byte-snapshot validation, member hash verification, kernel seal issuance and staging cleanup. **Confirmed in a local fixture and with one actual prior-run GitHub Artifact on a hosted runner**.

## Deliverables
- `ci_trace/sealed_handoff_v11.py`: `seal_bytes`, `seal_verified_member`, `consume_sealed_fd` and `consume_authorized_sealed_fd`.
- `ci_trace/sealed_signed_release_v11.py`: `issue_sealed_member` — verifies V9 signature and SHA approval, V10 immutable ZIP snapshot and extracted member hash, seals the data, removes staging directory, returns **only fd and bounded source/digest proof**.
- `tests/test_sealed_handoff_v11.py`, `tests/test_sealed_signed_release_v11.py`: regression and falsification tests, child-process FD transfer.
- `benchmarks/v11_handoff.py`: controlled mutation under three explicit consumer interfaces.
- `benchmarks/v11_cost.py`: Linux seal + consume microbenchmark.

## Real GitHub-hosted evidence (same commit)
- [GitHub CI run #204](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38145309577): **237 tests passed**; hosted regression and both benchmarks passed.
- [Real GitHub Artifact gate run #37](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38145309676): existing authenticated/signed V10 and V11 integration succeeded. V11 passed an actual 22-byte benign prior-run TXT Artifact through (a) a seal-based child-process handoff and (b) a one-call signed origin-to-sealed-data API.
- [Benign Artifact layout run #64](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38145309583): success.
- [Independent zizmor workflow scan #54](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38145309591): success; zizmor tests a different threat class and does not confirm V11's kernel FD semantics.
- The initial hosted PR test **failed** due to differences between separate local V10 test fixture and GitHub repository fixture (7 vs 9 returned fields), and because an earlier V10 negative control deliberately mutated its staging file. Both test integration issues were corrected. Earlier failed runs were not reclassified as successful.

### Deterministic 30-trial/path-mutation comparison
| Consumer interface after a trusted initial verification | Outcome |
|---|---|
| Unsafe: raw V10 staging file pathname reopened without validation | 30/30 consumed attacker-replaced bytes |
| **Correct** V10 committed-byte reader | 30/30 detected and rejected altered bytes |
| V11 kernel-sealed descriptor, with trusted digest binding | 30/30 delivered original committed bytes |
| Child attempting to write to sealed FD | 30/30 writes denied by kernel |

These counts are **author-controlled schedules**, not estimates of attack frequency, exploitable vulnerabilities or real-world defensive efficacy. They do not imply V10 correctly used was insecure.

### Hosted overhead, 30 repetitions per payload size
| Payload | Seal + descriptor consumption median |
|---|---:|
| 4 KiB | 0.0295 ms |
| 256 KiB | 0.5141 ms |
| 1 MiB | 1.9831 ms |

These numbers omit GitHub network calls, build steps, signature verification, archive extraction and cross-process IPC. They are an exploratory single-runner microbenchmark, **not production latency or SLO**. Additional resident memory is proportional to data size and limited by this prototype's 8 MiB cap.

## Reproduction
```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.v11_handoff
python -m benchmarks.v11_cost
```

For isolated local replication, use the companion `ci_trace_round11_package.zip`; the GitHub branch is the authoritative integrated source. All secret-bearing functions use ephemeral test keys, not organization credentials.

## Novelty relative to existing research
`memfd_create`, `fcntl(F_ADD_SEALS)`, content-addressing and signed build provenance already exist. Official Linux man-pages explicitly describe FD sealing and transfer to another process. GitHub's Artifact Attestations and the SLSA provenance model also predate this prototype. **Do not claim invention of a kernel primitive or a new signed artifact standard.**

The **proposed research contribution** is explicit, falsifiable composition across the trust boundaries:
`authenticated source -> signed authorized revision -> same verified ZIP bytes -> committed member -> sealed FD -> trusted data consumer`, plus independent expected-digest binding and counterfactual test evidence.

Primary references:
- https://man7.org/linux/man-pages/man2/memfd_create.2.html
- https://man7.org/linux/man-pages/man2/F_GET_SEALS.2const.html
- https://github.com/actions/attest
- https://docs.github.com/en/actions/concepts/security/artifact-attestations

## Remaining limitations
1. **Trust roots remain test-only.** Production approval issuance, trusted public key distribution, policy/key rotation and revocation are not built or deployed. A sealed FD is only as authentic as the independent expected digest and the trusted parent that supplies it. An attacker who controls the FD, its proof and the supposed expected digest can fabricate a fully self-consistent statement.
2. **Cross-process transfer demonstrated with local `pass_fds`**, not a separate mutually untrusted service over SCM_RIGHTS with authenticated peer credentials and authorization policy. Sender, receiver and runner process integrity remain assumptions.
3. **Data-only scope.** No arbitrary binary execution, publishing, secrets exposure or privileged write is authorized. Untrusted data may still trigger logic vulnerabilities in its consumer.
4. **Linux portability:** requires `memfd_create` plus `MFD_NOEXEC_SEAL` and file seals. The module denies if these operations fail. Max sealed payload 8 MiB. No Windows/macOS equivalence yet.
5. **No prospective blinded real-world sample corpus.** Historical source/sink cases are known in advance. No production exploitability, generalized detection precision/recall or award ranking can be inferred.
6. **Runner compromise/out-of-process policy changes:** kernel sealing stops FD writes, but cannot protect a trusted consumer whose code, trust anchors, or downstream decision making has been compromised.

## Best next step
Implement authenticated **UNIX SCM_RIGHTS capability transmission**, with independently protected sender/receiver identity and digest pinning, and demonstrate an *unprivileged* hostile child/peer cannot substitute either payload or policy evidence. Test in a disposable self-hosted runner with explicit trust-boundary controls, then expand to fresh, blind-labeled real workflows.
