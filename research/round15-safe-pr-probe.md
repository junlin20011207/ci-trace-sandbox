# CI-TRACE Round 15: safe candidate publication probe

This file is a **non-executable, non-production** probe of the GitHub branch -> commit -> draft Pull Request workflow.

- Reference base: `main@a7110e7bb84529682d02af53e9743de0d947214a` (captured on 2026-10-12).
- Candidate branch: `research/safe-pr-probe-20261012`.
- Only intended modified file: `research/round15-safe-pr-probe.md`.
- Do NOT merge this draft probe. Do NOT force-push protected target branches. Do NOT disable branch protections.
- A successful draft PR is evidence for branch/PR API interoperability **only**. At the time of inspection this repository's `main` was reported `protected: false`, and the rulesets endpoint returned `[]`.
- Real protected-branch enforcement, required-check provenance, independent review, and merge queue remain unverified and cannot be claimed from this probe.

The independent local protocol study is packaged separately with a source tree, test harness, and reproducible result data.
