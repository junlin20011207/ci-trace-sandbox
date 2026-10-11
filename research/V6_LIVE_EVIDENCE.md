# CI-TRACE V6: independently checked real hosted-runner evidence

**Research only — no production credentials, no write-scoped workflow token.**

## Hosted Github Actions: 2 complete positive-path experiments

| Trial | Producer (push, lab branch) | Consumer (workflow_run, main) | Outcome |
|---|---|---|---|
| 1 | [38126858731](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38126858731) | [38126868204](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38126868204) | both succeeded; SHA-256 verified |
| 2 | [38127142098](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38127142098) | [38127151155](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38127151155) | both succeeded; SHA-256 verified |

Trial 2 was triggered solely by committing `research/LIVE_REGRESSION_V6.md` (commit `a95192c2e9921a1488db15a252b0c0c4319bd2c2`), without changing the installed Actions workflow.

Both original GitHub Actions ZIP artifacts were downloaded through the GitHub connector and verified independently in a clean Python environment:
- Trial 1 artifact ID: `11697757235`; raw zip SHA256 `5f22a367322bef4a65114587aa38f407f90eb779d0a54a26f78afc1251452a3f`
- Trial 2 artifact ID: `11696943661`; raw zip SHA256 `6d2f232547257ee5e930ca6c126d7f2351045d1e86caad630a7ab212860296a3`
- Both extracted `proof.sh` bytes have SHA256 `c07db6c03e9d757d501ff41808a77e24d0fe361e8fcfb75288d97a2f79da6151`.
- ZIP differences arise from ZIP entry timestamps; they do **not** show script tampering.

Pinned Git Blob hashes of actual installed YAML:
- Producer: `ae6735420a774c4373b564244b41e4543b94d8aa`
- Consumer: `f546c2047025639c4fbd07ce119697d16fb66a23`

## Offline independent negative tests

The four exact deployed consumer guard atoms admit 1 of 54 enumerated event/source/branch/outcome conditions and reject 53 (offline interpretation, **NOT 53 hosted Runner runs**). Adversarial checks reject malformed ZIP, corrupted or unexpected content, extra files, traversal paths, and weakened conditions.

Clean extracted V6 research archive: **47/47 pytest checks passed**, comprising 32 retained V5 checks plus 15 new checks; both actual archives revalidated.

## Open limitations

- No actual server-side **negative** GitHub run yet.
- No runnable zizmor or Poutine scanner in the available container, so no real competitor comparison.
- No demonstration of high-privilege exploit; consumer is intentionally read-only.
- Abstract minimum-cut graph cost measurements do not equal measured production engineering cost.
- Repo default branch is **not changed** by this research-file commit. Draft PR #1 remains unmerged.

Full offline executable artifact and audit report were delivered in the corresponding ChatGPT conversation.