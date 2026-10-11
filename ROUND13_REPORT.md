# CI-TRACE Round 13 — One-use authorization across distinct Linux principals
Research date: 2026-10-11. Status: experimental Draft PR #11; **do not merge or use as a production issuer**.

## Root cause: identity + integrity alone do not constrain the number of releases

V12 ensures that a Linux SOCK_SEQPACKET sealed memfd is bound to signed provenance, an independent trusted digest, a fresh per-connection challenge, and kernel connection/message credentials. However, after receiving a valid payload, **the same authorized local consumer could request the same artifact repeatedly**. V12 has no durable issuance/redemption history and no recipient-specific grant expiration policy.

SLSA v1.2 and GitHub artifact attestations already address provenance verification; they do not themselves implement a project's one-use local release authorization service. Do NOT claim that CI-TRACE invented build attestation, SQLite transactions, UNIX credentials or sealed memfd.

## V13 implementation

- `ci_trace/redeem_v13.py`: a protected issuer-only SQLite ledger. A 256-bit random grant id is bound to a verified member SHA-256, an exact recipient Linux UID and a short expiration. A single `UPDATE ... WHERE redeemed_at IS NULL AND expires > now` is performed within a `BEGIN IMMEDIATE` transaction. Grant IDs are never reusable or reissued.
- `ci_trace/issuer_broker_v13.py`: a SOCK_SEQPACKET issuer serves one request per connection. It compares `SO_PEERCRED` to per-message `SCM_CREDENTIALS` for **both initial redemption request and later nonce challenge**, and transfers one sealed FD via SCM_RIGHTS only after atomically marking the grant redeemed. It returns inert data, never permissions to execute or publish.
- Default-deny file security checks: the SQLite parent directory must deny group/other access, and the SQLite file must be a regular file with no group/other permissions; a symlinked ledger is rejected.

### Falsification A: credential activation timing

In the initial prototype, the server called `setsockopt(SO_PASSCRED)` only *after* accepting a connection. On a real Linux host, an already-queued client message could then surface with a zero sender PID, which did not match the connection's actual process PID. Repeated different-UID experiments exposed this intermittent behavior.

**Fix:** initialize SO_PASSCRED on the listening socket **before** it can accept connections, and require this inherited property when handling messages. Five consecutive local reruns of separate-UID tests passed after the change. Request messages that lack valid credentials fail closed.

### Falsification B: authorization request -> challenge process substitution

Even if process A submits a valid redemption request, A could delegate its connected socket to process B **before the nonce**. Checking only the requesting process does not establish who later receives the sealed FD. V13 compares kernel SCM_CREDENTIALS on the nonce challenge to the original peer identity and rejects this handoff.

### Falsification C: cross-UID execution constraints in hosted CI

The first hosted run failed two root-only integration tests due to GitHub-hosted checkout directory traversal restrictions for the dropped-privilege `nobody`/ `daemon` clients, rather than incorrect authorization decisions. The harness now stages only **public, nonsecret verifier source** in readable temporary storage while keeping the grant database and signing policy in protected storage. Hosted CI was re-run and passed. The root-only step is scoped to internal PRs/push, with checkout credentials no longer persisted.

## Latest verified hosted results (commit c94c69f)

- **[GitHub unit/benchmark run #239](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38149362325): success.** The normal unprivileged phase passed 259 tests, with two distinct-UID tests skipped because it lacks root privilege; an explicitly separate root-run phase then passed 3/3 broker tests using different Linux users.
- **[Actual GitHub-hosted artifact end-to-end #49](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38149362337): success.** The original signed prior-run 22-byte benign TXT artifact was authenticated using the real GitHub REST API, verified against V9/V10 provenance and issued via V11 sealed memfd, then delivered by V13 broker UID 0 to recipient UID 65534 (nobody). A first claimant UID 1 (daemon) was rejected without consuming the grant; the rightful recipient was approved; the same grant was subsequently denied on replay. The unprivileged recipient could not open the protected SQLite database.
- [Artifact layout #76](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38149362308) and [pinned zizmor #66](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38149362440): success. zizmor concerns unrelated workflow findings and is not a direct validation of one-use redemption.

### Real-host 100-claimant contention experiment

10 independent groups, each 100 concurrent redemption attempts against one live SQLite grant on the same hosted runner:

| Metric | Observed |
|---|---:|
| Total eligible group winners | 10 |
| Total denied attempts | 990 |
| Groups with two winners | 0 |
| Median duration per complete 100-claimant group | 70.011 ms |

Labels and concurrency schedules were researcher-chosen. This is an **at-most-once consistency test**, not an estimate of incident prevention rates or global scalability.

### Local independent sandbox replication

- All 57 local tests passed, including the real UID separation, delegated nonce counterexample, and protected grant DB.
- Local 10 x 100 race: 10 grants accepted, 990 duplicate attempts denied; median entire 100-claimant batch **40.515 ms**, a different host. These medians are NOT directly comparable to the hosted runner.

## Reproduction

On the V13 branch:
```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.v13_redeem
# Only in a disposable authorized Linux environment with root access:
sudo -n env PYTHONPATH="$PWD" "$(command -v python)" -m pytest -q tests/test_issuer_broker_v13.py
```
The historical Artifact integration is in `.github/workflows/v8-real-artifact-probe.yml` and uses only inert 22-byte text, repository read permissions and ephemeral test-only signing credentials.

## Limitations

1. **At most once is not exactly-once delivery.** The broker commits redemption *before* transmitting FD. A crash, transport failure or malicious recipient that never completes its challenge irreversibly consumes its grant. A production service needs a documented idempotency/reissue/recovery policy without enabling duplicate release.
2. **Issuer has not been made independent of the research Runner.** Root and protected directories enforce Linux process separation in these tests; there is no organization-managed approval issuer, protected key service, long-running broker, audit monitoring or revocation lifecycle.
3. **Same-UID isolation is weak.** The broker authorizes Linux UIDs, not individual organizations or applications sharing an account. A leaked grant identifier may be redeemed by any process with that UID; the demonstration passes it on the client command line. No assurance is claimed against privileged compromise or process namespace abuse.
4. **No general execution safety.** Sealed text bytes are inert. Do not interpret a successful grant as permission to run scripts, push to Git, publish a release, or expose repository secrets.
5. **No blind real-world security accuracy estimate.** There is one authentic prior-run benign Artifact integration and controlled synthetic contention cases. The original V7 retrospective corpus has only two independent historical public findings.
6. **Host/platform limits.** Linux-only, AF_UNIX only, Python SQLite/local filesystem; no multi-host consensus or signed remote principal identity. Workflow sudo integration is intentionally restricted to same-repository PRs and disposable hosted runners.

## Research recommendation

Keep V13 as an **auditable subject-and-consumption binding layer** for CI-TRACE; its most concrete finding is that authenticated, immutable data transfer does not imply controlled *issuance*. The valuable next experiment is crash recovery, replay-resistant controlled reissue, protected maintainer-issued grants and cross-namespace identity verification, ideally in a dedicated isolated test environment.

## References (prior art)
- https://slsa.dev/spec/v1.2/
- https://slsa.dev/spec/v1.2/tracks
- https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations
- https://man7.org/linux/man-pages/man7/unix.7.html
- https://www.sqlite.org/lang_transaction.html
