# CI-TRACE Round 12 — Authenticated Linux FD Transfer and Connection-Credential Falsification

Date: 2026-10-11. Draft research PR #10. Read-only security research; all payloads are harmless data. This is **not** a production authorization service or a vulnerability in GitHub Actions itself.

## Diagnosis and research hypothesis

V11 provided a sealed, non-executable Linux `memfd` and a digest bound to V10 authenticated/signed artifact bytes. This holds integrity for **a correctly consumed FD**, but does not, on its own, authenticate independent IPC participants. Passing a descriptor or a self-consistent SHA from the sender does not establish the sender is authorized.

Two separate authentication questions matter:
- **Who is connected?** Linux `SO_PEERCRED` provides kernel credentials recorded at socket connection time.
- **Who actually sent this FD-bearing message?** Linux `SO_PASSCRED` / `SCM_CREDENTIALS` provides kernel-checked per-message sender credentials.

The first design used `SO_PEERCRED` alone. A falsification experiment then discovered that an authorized connection owner (process A) can pass an already-connected socket to process B. The receiver still sees A using `SO_PEERCRED`, but the `SCM_CREDENTIALS` ancillary data correctly identifies B as the actual sender. The first proposal was therefore **not sufficient to prove the identity of each transmitted message**.

## Delivered V12 design

`ci_trace/authenticated_ipc_v12.py` introduces:
1. Linux `AF_UNIX` `SOCK_SEQPACKET` transport, with a required finite socket timeout and bounded metadata.
2. **Mutual kernel credential checks**: sender checks the intended receiver; receiver checks connected sender's UID, optionally PID; receiver then checks the message's `SCM_CREDENTIALS` against the connected peer.
3. A fresh 256-bit recipient-generated nonce required in every reply.
4. Exactly one `SCM_RIGHTS` sealed FD, ancillary-truncation rejection, duplicate JSON key rejection, strict schema/version checks, and closing received FDs on all paths.
5. Independent trusted expected SHA-256 is a receiver-side argument; sender-supplied proof is never sufficient for authorization. V11 kernel seals, digest and length are validated again on the actual received FD.

**Trust-root condition:** UID/PID, FD proof and SHA are not substitutes for organizational authorization. The trusted expected SHA and allowed peer credentials must be supplied by a protected, nonattacker-controlled issuer. PID is a local process-lifetime identifier, not a durable software identity. Root or sufficiently privileged processes can potentially bypass normal process isolation.

## Falsification and iteration

### Round A — forged but internally consistent descriptor
A malicious peer can create a sealed descriptor for `FORGED` bytes and attach the matching hash. V11's low-level consistency checker correctly accepts that data as *self-consistent*, but it is not authenticated to the approved build. V12's independently pinned SHA rejects it.

### Round B — connected peer credential confusion
With only `SO_PEERCRED`, process A connects and passes the socket to process B. In the local reproduction, `SO_PEERCRED.pid == A.pid` while `SCM_CREDENTIALS.pid == B.pid`. Requiring both credentials to agree closes this **specified Linux socket delegation confusion**, under normal unprivileged process assumptions. A real three-process regression is included.

### Round C — protocol adversaries and real artifact integration
Tests include wrong UID/PID policies on both sender and receiver, stale nonce replay, duplicate metadata fields, extra FDs, oversized ancillary data, wrong version, and a correctly connected child. V12 is connected to a GitHub-hosted workflow that fetches an actual historical benign GitHub artifact, verifies V9 signature/commit and V10 bytes, issues a V11 sealed member, then passes it through V12 to a separate child process.

## Verified evidence

- Latest [GitHub Actions test run #219](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38147327466): **251/251 tests passed** (14 new V12 adversarial tests; historical V3–V11 tests retained). The 30-iteration synthetic comparison completed successfully.
- Latest [real GitHub artifact run #42](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38147327548): **success**. Actual signed provenance and previously uploaded harmless 22-byte TXT artifact -> sealed FD -> `SCM_RIGHTS` transport -> kernel credentials and fresh challenge -> independently pinned member digest -> original exact bytes.
- Artifact layout [run #69](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38147327541): success.
- Pinned zizmor [run #59](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38147327545): success; zizmor addresses workflow static weaknesses, **not this IPC invariant**.

### 30-trial comparison, synthetic controlled labels
| Scenario | Observed result |
|---|---:|
| Internally consistent forged descriptor, no external digest anchor | 30/30 passes basic V11 consistency; **NOT authorized** |
| Same forged descriptor with V12 trusted digest | 30/30 denied |
| Valid approved content with V12 | 30/30 accepted |
| Wrong receiver UID policy with V12 | 30/30 denied |

These are not measured attack frequencies, real-world recall, false-positive rates or award competitiveness statistics.

### Independent local sandbox performance exploration
20 repetitions, single Linux process with two threads, excluding GitHub REST, build steps, ZIP extraction and real process creation. V11 values represent direct trusted SHA verification, V12 includes socket handshaking, FD passing, kernel credentials and content revalidation.

| Data size | V11 direct read median | V12 IPC + read median |
|---|---:|---:|
| 4 KiB | 0.0084 ms | 0.2426 ms |
| 256 KiB | 0.1945 ms | 0.4895 ms |
| 1 MiB | 0.8574 ms | 1.1200 ms |

Exploratory one-host timings are **not** a production service latency or throughput guarantee.

## Reproduction
```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.v12_ipc --trials 30
```
See `tests/test_authenticated_ipc_v12.py` for replay, socket delegation, real child peer credentials, multiple FD, wrong UID/PID and forged content regressions. The fully integrated GitHub branch is authoritative; independent local sandbox package is supplementary.

## Comparison to prior art and 2026 technical context

- Linux `SCM_RIGHTS`, `SO_PEERCRED`, `SO_PASSCRED`/`SCM_CREDENTIALS` are documented kernel primitives, **not inventions by this project**: https://man7.org/linux/man-pages/man7/unix.7.html
- SLSA specification v1.2 requires provenance to be evaluated against independently defined expectations: https://slsa.dev/spec/v1.2/ and https://slsa.dev/spec/v1.2/provenance
- Artifact security standards and GitHub attestations already establish rich producer/build identities; V12 adds a narrow consumer-local enforcement proof, not a replacement for signature, SLSA or Sigstore verification.

Potential contribution: a **falsifiable trust-boundary preservation composition** from signed GitHub source, immutable ZIP bytes, kernel-sealed member through local process identity and data-consumption control, plus counterexample-driven regression. No claim of general novelty or discovery of a deployed exploit.

## Open security obligations

1. **No production trusted approver.** The end-to-end CI test uses test-only signing material and a locally pinned digest. Real organizational signer issuance, key revocation and policy provisioning are not deployed.
2. **Same-UID/process compromise:** UID/PID are kernel-level attributes and may not distinguish two applications owned by the same account. File descriptor passing or kernel credentials do not establish permission to perform privileged tasks. A fully compromised privileged sender/receiver remains out of scope.
3. **Credential inheritance edge:** message-level `SCM_CREDENTIALS` repairs the tested socket delegation confusion; this is still not a complete proof against all Linux namespace and privileged credential manipulations. Authenticated peer identity requires an explicit OS principal/isolation policy in a real deployment.
4. **Replay/freshness scope:** nonce controls reuse within the tested connection protocol; it does not implement service-level one-time release tokens, approval revocation or durable audit logs.
5. **No inter-host transport:** AF_UNIX is single-host Linux only. Production multi-host services require a separate mutually authenticated transport (e.g., mTLS) plus source/authorization binding.
6. **Not a generic artifact executor.** Receiver returns inert bytes only. It does not validate downstream code logic or authorize Git, file publishing or secrets access.
7. **No blind, large independent corpus** or live third-party exploit chain. Cannot infer real-world detection precision or an award ranking.

## Next high-impact step

Build and test two genuinely separate local security principals (distinct Linux UIDs/namespaces) with a protected trusted-digest authority and revocable, one-time issuer authorization. Evaluate replay, socket delegation, misbinding, cancellation and fault injection against an independently frozen policy. This is more meaningful than accumulating further rule-count-based unit tests.
