# CI-TRACE Round 21 — transaction-fenced publication and authority boundary

Date: 2026-10-12. **Research only: no Gitee credentials, no Gitee write, no production approval.**

## Independent evidence (real GitHub-hosted runner)
Hosted run [38251692138](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38251692138) completed all three jobs successfully:
1. Actual GitHub OIDC JWT RSA/JWKS validation and ephemeral LAB-only Ed25519 grant verification.
2. Two-client actual Git ref race: ordinary push modifies a raced branch; create-only lease rejects it without change.
3. SQLite 32-way reservation: one winner; authority-side clock oracle rejects spoofed client time.
4. Read-only Git access to `https://gitee.com/liljunlin/test.git`; zero pushes.
5. Missing release credentials and independent grant both lead to HOLD.

These are *hosted smoke tests*. The full local study uses a broader separate harness.

## Local sandbox falsification and repair
- 27 protocol unit tests pass with real local Git objects and authority SQLite state.
- 7 separate-UID Unix-socket integration tests pass: issuer UID 65531 and publisher UID 65533, unauthorized peer UID denied, publisher cannot read issuer key or mutate issuer DB, 48 competing socket reservations yield one success.
- **Counterexample A, fixed:** Untrusted client-supplied ACK could mark an uncreated ref PUBLISHED. Require issuer-side remote Git proof instead.
- **Counterexample B, fixed:** Successful push followed by crash and expired grant could not be acknowledged. Reconcile only existing remote object; never repush.
- **Counterexample C, fixed:** Caller-provided old clock could reserve an expired grant. Read real issuer clock instead.
- A revocation committed *before* reserve blocks publication. A revocation arriving *after* successful reserve is TOO_LATE_ALREADY_IN_FLIGHT under the stated linearization semantics, not an immediate cancellation guarantee.
- Recovery proof checks the target ref, exact single-parent base, operation id in commit message, and payload SHA-256.

## Scope and trust limits
- The GitHub default branch is not currently protected; no protected-branch merge was attempted.
- The Gitee repository default branch was last observed unprotected; no Gitee token was used.
- A single sandbox root administrator controls all UIDs. Real external institutional custody, independent signed business policy, Gitee enforcement, and production blind trial are **not proven**.
- GitHub `job_workflow_sha` claim is specific to reusable workflow jobs; a mutable workflow receiving a valid OIDC JWT is **not** an independent authorized publisher.
- A Git candidate branch may be created from a known base, but the default branch can drift in a race. Final deployment must apply the platform's protected merge gate and current-version check.
- Neither SQLite reservation nor Git ref CAS makes arbitrary external business side effects exactly-once.
- Human approval effort and business FPR/FNR are unmeasured.

The full source, red-team logs, and test transcript are packaged separately. This PR holds only a non-credential evidence summary and hosted smoke harness. **Keep Draft. Do not merge.**
