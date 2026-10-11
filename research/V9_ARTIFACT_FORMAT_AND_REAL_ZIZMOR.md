# CI-TRACE V9 — first shared-corpus real zizmor comparison and artifact v7/v8 live semantics

Date: 2026-10-11. Defensive CI/CD research; no untrusted payload executed with privileged credentials.

## 1. Official zizmor 1.30.1 actually executed in GitHub-hosted Runner

- [Successful original real-workflow scan #38131556616](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38131556616). Actual offline zizmor 1.30.1 output: **3 High `unpinned-uses`** findings for the branch's then-installed runnable workflows.
- [Successful same-corpus scan #38131857515](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38131857515). It scanned the **non-executable** pinned-SHA YAML fixtures in `research/v9_cases/v4_zip/` plus the V7 raw-artifact producer fixture, giving **one High `dangerous-triggers`** finding at `research/v9_cases/v4_zip/consumer.yml`.
- Raw zizmor JSON from GitHub run artifact `11699222132`; archive SHA-256 `7a476184184a8aac049a043069038e2ee3af244cfee27570bf79e3876800bf10`, independently downloaded, ZIP-checked and parsed in the local research package.
- Same pinned `v4_zip` producer/consumer file bytes are anchored by actual Git Blobs `34f2b644475a170f618f755bfee06fad41584a32` and `5f5b533c5fc3a823fa2409933fcd6db3b49e4b18`.
- On those **identical bytes**, CI-TRACE V8: zero confirmed path / one UNKNOWN (unrecognized official immutable SHA refs). CI-TRACE V9: one modeled PR-artifact-workflow_run-download-execution/write-token witness / zero UNKNOWN. zizmor: one `dangerous-triggers` warning. Neither finding constitutes a proven exploit or proof of relative scanner superiority.
- A proposed V7 raw-*consumer* research file was blocked by platform safety review and **was not deposited**. There is no purported same-corpus zizmor comparison for this missing half.

## 2. Actual GitHub-hosted v7 uncompressed upload + v8 download test

- [Successful real format-contract workflow #38131933433](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38131933433), read-scoped. Source: `.github/workflows/ci-trace-v9-format-contract.yml` on research branch.
- Action commits pinned to official upload-v7 `cf430e030ddbb5b0abf93d22962f4752f3646cd9` and download-v8 `9000827ccba6bdab643e8b6fd33ac0654aef8333`.
- `upload-artifact@v7` with `name: ignored-name`, `path: payload.txt`, `archive: false` created artifact **`payload.txt`** (ID `11699900653`, **22 raw bytes**, SHA256 `d834dba796eeb4773e565102c7592debdd8bc5abf5d2deac9658064f7a6682f5`). The uploaded `name` is deliberately ignored for raw-file mode, as documented by GitHub.
- `download-artifact@v8` with `name: payload.txt` succeeded; exact 22 bytes verified independently after downloading through the GitHub connector.
- Trying `name: ignored-name` returned the expected **Artifact not found** error; the workflow intentionally isolated that single expected failure via `continue-on-error` and asserted the original step's outcome was failure. Logs: `V9_UNZIPPED_REAL_OK=1` and `V9_WRONG_NAME_REJECTED=1`.
- This is a same-workflow, multi-job *benign* format and negative-name test; it is **not** a live privileged cross-workflow exploit experiment.

## 3. Research source and reproducibility

- [Version/format reference implementation](./v9_action_contract.py), Git Blob SHA `ed75e82f5970f83211fe4912c5ad570c1fad3c30`, matches the independently tested local code byte-for-byte.
- Full V9 executable bounded graph analyzer, tests, prior V8 correction corpus, real downloaded zizmor JSON and actual non-ZIP bytes are in the downloadable local V9 research package from the chat.
- **118/118** local pytest regression cases passed; actual tool archive digest and three shared Git Blob fingerprints independently verified.
- Historical `main` default branch is **not protected** according to GitHub branch metadata. Any auto-fix requiring protected-main releases must refuse publication absent independent policy confirmation.

## 4. Limits and operational notes

- This is NOT a field precision/recall study; corpus is very small, controlled and partially affected by safety limits.
- zizmor and CI-TRACE produce fundamentally different classes of evidence; one live high-level `dangerous-triggers` finding is not a discovery exclusive to CI-TRACE.
- The first amended zizmor workflow had a literal escaped newline in an artifact path and GitHub rejected its syntax in [run #38131830742](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38131830742). That configuration was corrected and [run #38131857515](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38131857515) then succeeded. Failure is retained, not counted as scanner performance.
- Real privileged consumer malicious-artifact rejection, secure branch protection and end-to-end actual auto-fix effectiveness are still unproven.
