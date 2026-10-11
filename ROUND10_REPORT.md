# CI-TRACE Round 10 — Eliminating Digest-to-Extraction TOCTOU

Research date: 2026-10-11. Draft PR #8. All work defensive, with inert, synthetic JSON/TXT ZIP payloads. **Do not deploy as a privileged artifact executor.**

## Executive finding: a concrete V9 safety-invariant violation

V9 `ci_trace/provenance_guard.py` computes SHA-256 by opening `archive_path`, closes the stream, then *reopens the same mutable pathname* via `zipfile.ZipFile(archive_path)`. The digest binds the first version of the file; the path may be replaced before the second open. Ed25519 approval of the producer/run does not cover the bytes **actually extracted** if those bytes are not the same digest-checked snapshot.

### Deterministic reproduction
The test harness creates two harmless ZIPs, both containing a permitted `report.json`: the original contains `VALID` and the replacement contains `FORGED`. The harness instruments the boundary immediately before the ZIP open and invokes a genuine `os.replace()` on the local ZIP pathname, after V9's file hash has been computed.

- **V9 + valid authenticated-shaped metadata:** returns `approved`, but extracts `FORGED` (not the hashed input).
- **V9 + a valid test Ed25519 approval:** same violation, because the gap occurs after authorization.
- **V10 + same simulated mutation schedule:** returns `approved` with `VALID`, the exact digest-checked input. The path replacement cannot alter its in-memory ZIP bytes.
- **Pre-verification ZIP replacement:** V10 denies due to digest mismatch.

The harness does not exploit a third-party GitHub runner or demonstrate that an attacker can independently schedule a file replacement in a privileged production job. It proves that V9's *stated byte-binding invariant* does not follow from its original code under the specified mutable-path threat model.

## Architecture changes

1. `ci_trace/snapshot_guard_v10.py` captures a bounded immutable ZIP byte string once, validates its SHA-256 against authenticated Artifact API metadata, and gives **the same bytes** to `zipfile.ZipFile(io.BytesIO(...))`. The configured ZIP byte limit cannot exceed 64 MiB; default is 20 MiB. Existing compression ratio, extension, entry-count and path guards are retained. Every extracted member receives a hash/length commitment.
2. `ci_trace/signed_snapshot_v10.py` composes the existing V9 Ed25519 approval and immutable producer SHA binding with the new byte-snapshot release. It explicitly does not confer permission to execute/publish.
3. `ci_trace/verified_reader_v10.py` uses Linux `openat`-style directory file descriptors, `O_NOFOLLOW`, exact size checks, and SHA-256 comparison to return precisely the bytes represented by a trusted in-memory file manifest. The consumer must not accept a separately attacker-supplied manifest. It addresses *post-extraction, pre-consumption* mutations for consumers that use this API.
4. `ci_trace/json_consumer_v10.py` performs signed release, committed member reading, schema-constrained scalar JSON decoding, and stage cleanup **inside a single trusted process**. Duplicate JSON keys, non-finite constants, unknown fields, wrong types and sensitive branch/ref fields cannot be accepted by its narrow schema contract.
5. `ci_trace/github_signed_gate_v10.py` integrates the old authenticated GitHub REST metadata call, protected key/policy paths, signed approval, and V10 snapshot release, while retaining the V9 CLI as an unmodified baseline.

## Hosted experiments — same commit / same runner

- [GitHub Actions test & benchmark run #176](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38144308245): **225 unit tests passed** and both V10 microbenchmarks executed successfully.
- [Real authenticated GitHub Artifact run #26](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38144308165): signed V10 CLI, SHA-256 snapshot and a genuine prior-run **benign TXT artifact** passed; postrelease same-length content replacement was detected and denied.
- [Actual Artifact layout probe #53](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38144308258): success.
- [Pinned zizmor external workflow analysis #43](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38144308199): success. zizmor was not used to validate this ZIP consumer bug, because it targets workflow syntax rather than this Python release invariant.

### 40-trial-per-class controlled comparison

| Controlled condition | V9 outcome | V10 outcome |
|---|---|---|
| Path replaced **between hash and ZIP reopen** | 40/40 released wrong JSON bytes while approved | 40/40 released correct hashed JSON bytes |
| No mutation | 40/40 correct release | 40/40 correct release |
| ZIP mutated before digest read | 40/40 denied | 40/40 denied |

No inference about real-world attack frequency, precision, or exploitability is warranted: the replacement schedule is deterministic and controlled by the experiment designer.

### Hosted microbenchmark (10 repetitions/version)

| ZIP content size | V9 median (ms) | V10 median (ms) |
|---|---:|---:|
| 4 KiB | 0.338 | 0.411 |
| 256 KiB | 0.631 | 0.844 |
| 1 MiB | 1.530 | 2.137 |

These are single-runner, cold/warm-cache-confounded exploratory timings. V10 uses additional memory proportional to the compressed ZIP size (bounded by 64 MiB). Do not use these numbers as a throughput/SLO guarantee.

## Three investigation rounds and falsification

- **Round A — find violated invariant:** instrument the V9 path boundary and replace a real local ZIP between hashing and opening. Show an authenticated-looking successful release of bytes that fail the authenticated digest. Reproduce both with/without valid test Ed25519 approval.
- **Round B — bind verification to use:** replace two file opens with one bounded byte snapshot and derive each extracted member commitment. Counterfactual experiments on the same inputs show no wrong bytes released.
- **Round C — bind extracted bytes to trusted sink:** deliberately mutate a released file after extraction, with same length, and verify the manifest reader rejects it. Also test symlink replacement, path traversal, duplicate JSON keys, poisoned branch names and invalid schema fields. Provide an atomic scalar JSON consumer that cleans up intermediate files.
- **Cost evaluation:** measure 3 ZIP sizes in Python on a real GitHub-hosted runner.

One local test fixture initially unpacked the wrong number of returned fields, producing 6 failures despite 7 other tests passing. The fixture was corrected and the local V10 suite passed **21/21**, after which the hosted integrated suite passed **225/225**. The failed local fixture is preserved in this research log, not misrepresented as a scanner failure.

## Reproduction

```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.v10_path_swap --trials 40
python -m benchmarks.v10_cost
python -m ci_trace.github_signed_gate_v10 --help
```

Local independent minimal package: `ci_trace_round10_package.zip` (the complete GitHub branch remains authoritative).

## Relevance to published research

- GitHub Security Lab GHSL-2026-226 describes an independent *authorization-to-checkout* TOCTOU problem in Marimo (September 2026); that is distinct from the **digest-to-extraction** pathname race found within V9. Do not claim the present work discovered or reproduces GHSL-2026-226.
- GitHub artifact attestations and SLSA provenance verification already provide mature build-origin evidence. **Provenance alone does not secure a mutable local consumption path.** The V10 contribution is concrete implementation invariants and validated composition of approval, byte identity and consumption, not a new cryptographic primitive.
- References: https://securitylab.github.com/advisories/GHSL-2026-226_marimo-team_marimo_repository/ ; https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations ; https://github.com/slsa-framework/slsa/blob/main/spec/verifying-artifacts.md

## Open security and scientific gaps

1. **Attacker control not demonstrated.** Test swaps are scheduled via instrumentation; not evidence of exploitable external remote access to this local pathname.
2. **Trusted approval provisioning absent.** CI tests sign with ephemeral keys in a test runner. Real deployments require protected, revocable issuer identity, audit logs, anti-replay controls and policy authority.
3. **Sink boundary is API-scoped.** Ordinary downstream processes that open the returned path instead of using the protected reader remain exposed to postrelease changes. A serialized manifest on an attacker-writable filesystem is not a trusted manifest. The scalar JSON consumer addresses only its limited class of data.
4. **Platform and size scope.** Linux directory-fd and O_NOFOLLOW semantics; in-memory ZIP byte limits; compressed archives larger than 64 MiB need an alternative securely copied file descriptor/snapshot approach.
5. **No systematic cross-repo evaluation.** Existing historical corpus has two independently disclosed workflow vulnerabilities; this V10 defect is an internal prototype invariant failure. There is no blind external test of security detection accuracy or claims of better quality than mature supply-chain tools.
6. **Unmodeled use after read.** Safe returned bytes can still be misused by an untrusted consumer; complex JSON schemas, key rotations, concurrent workflow job execution, attestations and authorization policy changes remain open.

## Research recommendation

Preserve the existing static source-to-sink evidence and authenticated/signed authorization. For contest-level originality, frame the work as **verifiable trust-boundary preservation from authenticated producer through exact bytes consumed**, supported by executable counterfactual tests. Do not claim discovery of a globally novel attack class or a proven high award ranking based on this prototype alone.
