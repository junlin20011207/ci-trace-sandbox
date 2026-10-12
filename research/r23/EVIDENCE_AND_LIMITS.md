# R23 domestic-source security experiment: exact evidence and limits

**Code repository:** full runnable local source and raw R23 tests are delivered as a separate `ci_trace_round23_study.zip` in this conversation. This PR contains the GitHub-hosted smoke test only; do not claim the entire local Python implementation ran in GitHub Actions.

## Verified hosted facts

Latest known green hosted run before this documentation commit:
https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38269532979

Jobs:
1. Ephemeral LAB-only OpenSSL SM2 / SM3 signing with fixed SM2 Distinguishing ID; no organizational business approval.
2. Different GitHub-hosted runner: public key origin verified through GitHub Sigstore attestation with exact repository, workflow identity, source ref, and commit SHA; verifies SM2 signature and rejects modified subject.
3. Real anonymous **read-only** Gitee `ls-remote` of `https://gitee.com/liljunlin/test.git`, including strict actual Git SHA-1 hex validation. No credential, no Gitee push.

## Locally implemented new national-platform research module

- Custom CODEARTS and GITEE_GO bridge contract (not native vendor event): HMAC provenance of a request, optional SQLite nonce dedup, exact match to independent issuer preapproval.
- Actual localhost mTLS issuer API in a separate process, client-authentication CA, CN restrictions; different/absent TLS client cert denied.
- Actual OpenSSL SM2+SM3 issuer-signed grant and issuer-signed receipt; public-pem pinned offline verification.
- Actual disposable bare Git CAS ref update and independently observed tree/commit check at receipt issuance; concurrent reserve, revocation-before-reserve, crash recovery, proof tampering and source identity attacks.
- **48 new local tests passed**, CodeArts and Gitee Go fixture variants. R22 product regression 4, original protocol regression 30, Linux UID regression 7 also passed in the same sandbox.
- Live Gitee push intentionally blocked by local marker `CI_TRACE_DISPOSABLE_LOCAL_LAB_ONLY` and absence of any real write credential.

## Hard limits, no inferred vendor superiority

Official CodeArts documented HTTP plugin support is NOT equivalent to verified identity of a real CodeArts pipeline job; Gitee Go Release plugin can update releases depending on configuration. The bridge schema is authored by this research, not official source payload. No real independently owned institutional issuer, cloud-host-to-cloud-host online mutual-TLS business RPC, Gitee protected credential/push, independent business incident labels, or SM2 commercial-cryptography compliance certificate. A historic offline SM2 receipt does not prove the remote mutable ref remains unchanged today.

Original PR remains Draft; no merge or main write. Preserve previous R22 research results and failed test fixtures.
