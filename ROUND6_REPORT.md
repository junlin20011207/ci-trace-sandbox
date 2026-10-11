# CI-TRACE V6 — Adversarial falsification and evidence quality

Research date: 2026-10-11. Repository: `junlin20011207/ci-trace-sandbox`.

## Research goal and bounded semantics

Reduce unsound claims from artifact-to-execution heuristics. **Never equate a static candidate with an exploitable vulnerability.** V6 extends V5 using a narrowly recognized subset of GitHub Actions condition syntax and an explicit three-state evidence model:

- `candidate` / `review_required`: static cross-run, artifact identity and execution-path cues align; attacker control and exploitability unproven.
- `unresolved` / `needs_resolution`: a relevant path could not be established or disproved with supported semantics.
- `excluded` / `informational`: evidence under the supported model contradicts the candidate hypothesis (e.g. disjoint literal paths or mutually exclusive run-conclusion guards).

### Concrete additions

1. Recognize only literal conjunctions comparing `github.event.workflow_run.conclusion` to enumerated outcomes using `==` or `!=`. If a recognized conjunction is contradictory across downloader and executor, remove the purported edge.
2. Decline to deduce falsehood from arbitrary expressions (including `||`, `contains`, `env.*`, or arbitrary code).
3. Downgrade opaque multi-line quotations, backticks and shell command substitution from definite path overlap to unresolved evidence.
4. Preserve a triage edge for indirect commands like `bash $TARGET` or `bash "$TARGET"` when they follow a cross-run download, subject to literal artifact-identity mismatch and contradictory-guard checks.
5. Preserve versioned V3–V5 analyzers as a baseline. V6 remains an independent draft branch.

## Explicit failed-fix cycle

A preliminary GitHub Actions run **failed during Python test collection** due to a malformed dictionary in the uploaded V6 test fixture: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38136737748. It was fixed before measuring hosted assertions.

- First corrected run: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38136781829 — **100 tests passed**, V6 synthetic 12-case expected-label matching 12/12, V5 matching 5/12. These are **author-defined structural labels**, not external vulnerability ground truth.
- Three further falsifying test cases found unsupported indirect-command behavior and led to additional patches.
- Latest full hosted run: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38136911825 — **103 tests passed**; 12-case V6 benchmark still **12/12**, V5 **5/12**.
- Same commit's harmless read-only Artifact layout probe succeeded: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38136911819. The step guarded by `if: false` was skipped.
- Independently pinned `zizmor==1.30.1` scan passed: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38136911828 and reported **11 raw findings** across several categories. These are **not** benchmark-comparable to CI-TRACE candidates.

GitHub V6 PR: https://github.com/junlin20011207/ci-trace-sandbox/pull/3 (draft, targeting unmerged V5 branch).

## Reproduce on the V6 branch

```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.compare --assert-results
python -m benchmarks.v5_delta --assert-results
python -m benchmarks.v6_delta --assert-results
python -m ci_trace.scanner_v6 .github/workflows
```

The 12-case generated corpus has fixed expected *structural classifications*. The author's own assumptions define labels. Do **not** claim 100% real-world detection accuracy, precision or recall.

## Limitations and open proof obligations

- The tool does not prove artifact bytes are derived from attacker-controlled content or are actually executed.
- `workflow_run` cross-run execution, secrets scope, and effective job permissions require runtime investigation; GitHub-hosted probe tested inert same-run artifact layout only.
- Shell parsing is heuristic. Composite/reusable actions, nested substitutions, environment-dependent paths, symlinks, pipelines, scripts generated at runtime, and alternate interpreters are not fully modeled.
- Even `excluded` is **relative to the stated finite static model**, not a general guarantee of repository safety.
- GitHub Actions condition syntax includes status functions, implicit `success()` and complex expressions beyond this bounded grammar; none are evaluated by V6.
- No third-party adjudicated vulnerability corpus and no same-taxonomy quantitative comparison with zizmor/Poutine have been completed.
- Local independent sandbox test count can differ from GitHub hosted count due to retained older prototype test files; hosted execution results are the source of record.

## Documentation sources

- https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
- https://docs.github.com/en/actions/reference/workflows-and-actions/expressions
- https://github.com/actions/download-artifact
- https://docs.zizmor.sh/usage/
