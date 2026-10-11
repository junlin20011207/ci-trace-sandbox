# CI-TRACE V8: guarded provenance proof and retrospective evidence audit

Date: 2026-10-11. Draft PR: https://github.com/junlin20011207/ci-trace-sandbox/pull/6

## Root-cause analysis

V3–V6 primarily focused on syntactic downloaded-file execution and largely author-labeled regression fixtures. V7 improved structural source-to-sink evidence on two published historical advisory cases but its detection of a supposedly protective source-repository condition was only substring matching.

This can make the analysis *unsound* for a job condition that merely mentions the check but does not logically require it. For example, a job conditional that allows execution if the repository matches **or** an unrelated clause passes is not a provenance proof.

## Hypothesis and intervention

H1: a restrictive, allowlisted AND-only grammar can prove that a specific origin-equality condition is structurally required, without executing or interpreting arbitrary GitHub Actions expressions. Anything outside this grammar remains unknown. The grammar returns `origin_guard_proved=False` for unknown expressions; False is NOT evidence that the job is exploitable.

H2: a provably disabled artifact metadata reader cannot establish that a downstream privileged operation consumed data from that reader. V8 excludes this impossible edge.

Code:
- `ci_trace/guard_proof.py`: narrow source-repository equality proof with bounded conjunction grammar.
- `ci_trace/scanner_v8.py`: V7 source-to-sink rules with origin-guard proof and disabled-reader exclusion.
- `tests/test_scanner_v8.py`: 15 regression and retrospective assertions.

## Verified measurements

- GitHub Actions: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38141152557 — **133 tests passed**, all prior benchmarks also completed in the same workflow.
- Harmless actual Artifact layout probe: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38141152601 — success.
- Pinned zizmor external baseline: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38141152539 — success.
- Earlier V7 comparison on two unique public GitHub Security Lab issues plus their post-fix snapshots: 4/4 source-state matches; V6 2/4. This tiny retrospectively selected corpus does not measure real-world precision/recall.
- No new independent incidents were found or confirmed by V8. The measured contribution is **semantic reliability against additional adversarial counterexamples**, not higher detection recall.

## Prior art and 2026 context

- GHSL-2026-204, artifact overlay in SPIRE: https://securitylab.github.com/advisories/GHSL-2026-204_spiffe_spire_repository/
- GHSL-2026-225, untrusted metadata controlling a privileged Git branch in actions/attest: https://securitylab.github.com/advisories/GHSL-2026-225_actions_attest/
- GHSL-2026-226, authorization/TOCTOU flaw in marimo CI: https://securitylab.github.com/advisories/
- GitHub Actions supply-chain scanners are already mature; e.g., pinned zizmor and Poutine. Rule additions do not automatically amount to a unique research contribution.

## How to reproduce

```sh
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.public_cases_v7 --assert-results
python -m ci_trace.scanner_v8 .github/workflows
```

## Open questions and critical limitations

1. `origin_guard_proved` supports only a deliberately restricted subset; parentheses, OR, negation, function expressions and dynamic access are classified as not proved, not parsed as full boolean AST.
2. V8 is **not** a general-purpose interprocedural taint engine. Intermediate Artifact bytes, shell environment, reusable Actions, dynamic paths, symlinks and file overwrites have not been formally modeled.
3. Historical cases were publicly known and small: two distinct vulnerabilities plus paired later fixed snapshots. The detection rules were developed with knowledge of the historical cases, so evaluation is not blind.
4. There is no demonstrated end-to-end cross-run exploitation of a user-owned intentionally vulnerable workflow. Hosted integration used innocuous artifacts only.
5. A universal claim of novelty, verified zero false positives, or contest award suitability would not be supported by available evidence.
6. A truly competitive innovation requires formal provenance rules or a constraint/dataflow intermediate representation, blind labeling, multi-repository evaluation and an independent baseline with aligned classes.

## Technical direction

Keep the V7/V8 mechanism as a reusable, auditable artifact-to-sensitive-sink evidence layer and prioritize a structured expression AST with explicit trust assumptions, propagation edges and source proof obligations. Reject any correctness claim until it is falsifiable on a frozen external corpus and exercised in a non-privileged, controlled cross-run demonstration.
