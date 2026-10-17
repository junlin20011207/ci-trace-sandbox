# CI-TRACE R22 Security & Trust Boundaries

## What runs locally

- A single-user, localhost-only FastAPI lab console creates new **local bare Git remotes**, ephemeral LAB Ed25519 keys, issuer-owned SQLite operation ledgers, and test payloads. All data stays in the sandbox.
- For isolated UID experiments, `core/ipc_lab.py` demonstrates real Linux UID filesystem/process isolation on a disposable root-controlled system. Root can still subvert everything; this is NOT an independent institution.
- Publisher checks signed operation identity, approved digest and destination, bounded valid time, issuer-online serialized reservation, create-only Git ref update, and verifies the remote object for ACK or read-only recovery.

## Intended security assumptions

- Source workflow authors cannot edit publisher code, trusted key roster, live revocation policy, or recipient credentials.
- Git refs and SHA/object proof correspond to a server controlled under the recipient's authority; the publisher has only least-privilege target write permission.
- No bypass of policy exists via alternative credentials, administrators, direct pushes, or out-of-band deployment APIs.
- Issuer provides a trustworthy clock and online atomic operation reservation.
- The holder of an already reserved grant may complete the attempted publication; revocation strictly precedes reservations to block publication. Stronger cancellation claims require a separate protocol.

## Explicitly missing for production

- No externally managed issuer, protected root of trust, independent institution, GitHub protected merge gate, or Gitee write access.
- No actual mutual-TLS issuer-publisher channel across two independently administrated machines; GitHub signed provenance transfers between distinct runners verify origin, not business approval or a live mTLS RPC path.
- No cross-system exactly-once arbitrary side effects or guarantees across malicious Git server behavior.
- This application is deliberately NOT a deployable security gateway; do not bind `app.py` to a public interface or load a real Gitee token.

## Falsifiable claims and evidence

- Git race protected with `--force-with-lease=refs/heads/research/..:` and actual local bare remote + GitHub-hosted test.
- Local 64-way online reservation: at most one winner; recover previous Git push only after remote proof verification.
- TLA+ TLC verifies 36 finite-state model states; this is not a theorem about the Python program.
- GitHub first-runner generates SLSA provenance via `actions/attest`, second runner verifies exact signing workflow/source digest/ref; tampered artifact is rejected.
- External weakness labels and PR review histories are independent public observations but do not represent actual release authorization outcomes.
