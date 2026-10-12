# CI-TRACE R20 — authorization-bound publisher research

Research-only, **2026-10-12**, no production secret and no Gitee push.

## Verified on real GitHub-hosted runner
- Job uses `id-token: write` but **no `contents: write`** or Gitee credentials.
- Cryptographically verifies GitHub's live RSA/JWKS OIDC JWT; binds `iss`, `aud`, immutable `repository_id`, workflow path, `ref`, and commit SHA.
- Verifies disposable Ed25519 release grant using an ephemeral **LAB** key; rejects modified destination, expiry, revocation, and untrusted signing key.
- Uses real unauthenticated `git ls-remote` to Gitee `liljunlin/test`; no write.
- Missing authority or release secret leads to HOLD. See Actions run **38248174288**.

## Key red-team lessons
1. An editable research workflow can request a *genuine* OIDC JWT. Signed identity does **not** mean an authorized independent publisher.
2. Whoever controls both a signed grant and the trusted issuer-key list can replace the key and counterfeit any decision. Trust anchors MUST be fixed outside the candidate project.
3. An offline stale revocation list can accept a revoked grant. Online authoritative freshness or bounded risk window is required.
4. SQLite ledger can reserve a business operation once, but crash ambiguity is not cross-system exactly-once delivery.
5. Ordinary Gitee secret in a mutable job is unsafe even if job has a commit-message check. Prior PR #14 was modified to remove that secret reference and pause direct publishing.

## What still needs an external administrator
- Independently owned and protected issuer, policy keys and Gitee write credentials.
- Issuer-side JWT validation with trusted `job_workflow_sha`, repo ID, protected workflow ref, strict audience and signed release content.
- Protected publisher deployment/environments, no direct Gitee credential in mutable research branch.
- Independent business adjudication and real Gitee protected-branch approval/merge testing.

Do not merge this PR or claim legal/institutional independent participation without external signing evidence.
