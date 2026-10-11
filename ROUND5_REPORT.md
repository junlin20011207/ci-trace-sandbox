# CI-TRACE — Round 5 evidence report (2026-10-11)

## Scope and hypothesis
This is defensive static analysis of potential PR artifact trust-boundary crossings between GitHub Actions workflows. Findings are **structural review candidates only**: the tool does not prove user control, effective privileges, shell execution, artifact integrity, or exploitability.

**Hypothesis:** explicit static evidence about job/step reachability and working-directory precedence can reduce structurally unjustified alerts, relative to V4, without discarding straightforward positive cases.

## Changes
- Added `ci_trace/scanner_v5.py`, retaining V4 for reproducible comparison.
- Three-valued `if` treatment: provably false cases are not linked; dynamic conditions are annotated `conditional`, not mistaken for definitely true.
- Resolved relative execution paths against `step.working-directory > job.defaults.run.working-directory > workflow.defaults.run.working-directory`.
- Explicit `cd`, heredoc and dynamic directories are marked unresolved rather than positively overlapping.
- Producer artifact steps with a missing/empty required `path` are not treated as available uploads.
- Preserved cross-run origin, artifact identity and declared token-scope evidence.

## Real hosted test evidence
1. V5 runner test: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38134709460 — **79 tests passed**, V4 and V5 CLI self-scans succeeded.
2. V5 falsification benchmark: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38134794765 — **79 tests passed**; 22 author-designed structural cases: V4 matched 9/22 expected labels and V5 matched 22/22.
3. Harmless *actual GitHub-hosted artifact operation* probe: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38134709503 — upload successful; unnamed download created name subdirectory; named download extracted directly into configured target; relative step CWD assertion passed; a provably disabled step was skipped. Job permissions: `contents: read`.
4. Independent zizmor v1.30.1 security analyzer: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38134872060 — **11 raw findings** on the current repo's workflows (8 `unpinned-uses`, 1 `artipacked`, 1 `dangerous-triggers`, 1 `obfuscation`). Findings are *not* independently adjudicated.
5. Independent local Python sandbox V5 candidate: **80/80** local assertions passed; that prototype includes an extra V4 test and is not claimed to be byte-identical to the GitHub candidate.

Initial Github PR run https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38134619026 **failed during collection** due to a syntax error while transcribing tests into the GitHub branch. This was corrected; subsequent hosted runs passed. Failed runs have not been excluded from the study record.

## Reproduction
```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.compare --assert-results
python -m benchmarks.v5_delta --assert-results
python -m ci_trace.scanner_v5 .github/workflows
```
The artifact layout probe and pinned zizmor baseline are GitHub Actions workflows in `.github/workflows/` and require no repo-write permissions.

## Methodology warnings
- The benchmark labels were deliberately authored around 22 structural cases; they are not an external ground-truth vulnerability corpus, so 22/22 is **not a real-world precision/recall estimate**.
- Cross-tool raw finding counts are not directly comparable. zizmor scans for many other security issues; CI-TRACE is narrow artifact-to-execution structural triage. No per-rule equivalence is assumed.
- Neither a successful shell test of innocuous files nor a static finding establishes an exploitable cross-run attack path.
- Missing dynamic paths, reusable/composite actions, branch protection, cross-repository authentication, runtime conditions and effective token defaults are still open research problems.
- A known GitHub Actions limitation: `workflow_run` consumers require workflows on the default branch to trigger; the harmless integration probe instead tests artifact layout on PR runners, *not* a full cross-run exploit.

## Primary external documentation
- https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
- https://github.com/actions/upload-artifact/blob/main/docs/MIGRATION.md
- https://github.com/actions/download-artifact
- https://docs.zizmor.sh/usage/
- https://docs.zizmor.sh/installation/

## Next rigorous experiment
Freeze an independently labeled corpus from permitted real-world workflows (including unknown labels), annotate artifact producer/consumer provenance and effective privileges, and compare aligned security categories with version-pinned zizmor and Poutine. Report abstention and unresolved cases separately.
