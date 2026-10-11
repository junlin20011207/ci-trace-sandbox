# CI-TRACE hosted-runner regression probe (benign)

Research branch: `ci-trace-live-lab`

Purpose: trigger the existing, previously reviewed read-only **producer workflow** through an ordinary research-file commit; the default-branch consumer checks that the produced constant benign script matches an independently pinned SHA-256 before running it. This is a **positive-path regression only**, not a vulnerability exploit or a test of untrusted PR denial.

The producer deliberately ignores repository content and regenerates a fixed non-secret proof.sh; no secrets, write tokens or repository modification by Actions. The repository owner enabled both workflows. Expected marker: `CI_TRACE_CROSS_RUN_VERIFIED=1`.

## Scope of evidence

- Confirm producer event `push`, branch `ci-trace-live-lab`, successful upload of artifact `ci-trace-demo`.
- Confirm consumer `workflow_run` event on `main`, job not skipped.
- Confirm downloads same producing run ID, verifies `proof.sh: OK`, emits success marker.
- Confirm token scopes in logs are read-only; **do not infer that untested negative branches are safe**.

Experiment date: 2026-10-11.
