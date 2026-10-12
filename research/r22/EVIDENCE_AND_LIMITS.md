# CI-TRACE R22 — production-scoped safety research, not a real publishing credential

**Final verified run:** https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38263320485 (6 of 6 GitHub-hosted jobs passed).

## What is verified in real cloud infrastructure

- GitHub-hosted Git create-only ref race regression and SQLite reservation smoke tests; Gitee `liljunlin/test` was read-only reachable.
- Real third-party workflow security dataset (source pinned to `sparkrew/github-actions-security@327c162df95c967d01dd34d815c6e01283f5b032`): 2,722 workflow metadata rows, 121 repository list entries, 448 positive weakness labels covering 50 distinct workflows.
- Real public GitHub pull-request review events: in sampled merged PRs: Flask 2 (0 approved events), Node.js 12 (12 with approved review events), Rust 12 (2 with approved events). These **are not** labeled business delivery approvals.
- Real TLA+ TLC v1.7.4 execution: 68 generated states, 36 distinct states, no violation of the specified safety invariants.
- Real SLSA/Sigstore artifact attestation via GitHub Actions `actions/attest@v4`, and `gh attestation verify`.
- Cross-runner signed transfer: separate GitHub-hosted job downloaded signed subject, enforced **exact signer workflow identity**, **source SHA**, and **source ref**, and confirmed that tampering of the downloaded artifact is rejected. Real distinct machines; not a full live business mTLS system.

## Full standalone local product prototype

A separate user-downloadable `ci_trace_round22_study.zip` contains FastAPI Web console and REST API, 9 end-to-end local Git security scenarios, original 30+7 R21 tests, real Git paired local comparator, nine-scenario 10-run latency data, finite-state checker and TLA spec, public third-party aggregate evidence and the research report.

The product archive is delivered as a separate sandbox artifact in this conversation, **not stored in this GitHub PR**. This PR stores the externally reproducible hosted security evidence and TLA source. Do not claim that all local product code has run in GitHub Actions.

## Why competitor result must be framed narrowly

Baseline A (code-approval proxy) and B (enhanced external approval proxy with real issuer SQLite + signing + input binding but ordinary Git push) are researcher-built programs, **not** GitHub/Azure/Harness product configurations. The complete CI-TRACE implementation blocks a demonstrated Git create-only TOCTOU race and can reconcile a successful push after ACK loss. A fully engineered competitor with equivalent CAS+reconciliation could match these mechanisms. No claim of universal vendor superiority.

## Hard limits

No real independent institution owns the approval key. No Gitee write credential or branch-protection transition. No real enterprise release authorization incident labels. No complete two-machine issuer/publisher mutual-TLS business RPC. No cross-system exactly-once claim. Default main remains unchanged. Keep Draft.

Earlier data study run #38262432738 failed from interpreting a headerless repository list as a workflow-row manifest; fixed in later successful run. Do not erase the negative logs.
