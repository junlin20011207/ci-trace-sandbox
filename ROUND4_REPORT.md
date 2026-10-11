# CI-TRACE — Round 4 research record (2026-10-11)

## Objective
Distinguish a **cross-run** artifact trust-boundary candidate from an ordinary artifact download and reduce unsupported inferences about executable code.

## Why V4 was necessary
`actions/download-artifact@v4` normally targets the **current workflow run**, not the workflow that triggered a `workflow_run` consumer. For cross-run downloads, the action documents `run-id` and `github-token` inputs. A prior heuristic detected execution after `download-artifact` in any `workflow_run` consumer, leading to structural false positives.

References:
- https://github.com/actions/download-artifact
- https://github.com/actions/upload-artifact
- https://docs.github.com/en/actions/reference/security/secure-use

## Source, identity, and path constraints
A **review_required** candidate requires all of:
1. Producer workflow includes a `pull_request` or `pull_request_target` trigger, uploads an artifact, and is linked to the consumer by `workflow_run.workflows`.
2. Consumer's known downloader explicitly addresses `github.event.workflow_run.id` and has a `github-token` (where required by `actions/download-artifact`).
3. Selected artifact name (or static selection pattern) is compatible with a named producer artifact.
4. The download and command appear in that order within the same job.
5. A *literal direct-execution command target* lies inside the modeled extraction destination.
6. Dynamic/unsupported inputs remain unresolved, rather than silently treated as confirmed evidence.

The access-context report includes **declared** job/workflow write scopes; absent scopes never imply safe defaults.

## Hosted evidence
- Existing third-round CI: run https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38133495914 (22/22 tests passed).
- First V4 run https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38133990165 (44 passed, 12 failed). Root cause: the generated fixture lost a left brace in GitHub expressions, producing invalid runtime selectors.
- V4 corrected CI https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38134040054 (56/56 tests passed).
- Benchmark CI https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38134126715 (56 tests passed, benchmark passed, V4 self-scan passed).
- The **20 synthetic, author-labeled** structural candidate fixtures matched 13/20 expected labels under the legacy heuristic and 20/20 with V4.
- The 57-test separate local sandbox prototype is not byte-identical to the GitHub V4 candidate, so its 57/57 result is not a hosted CI claim.

## Reproduction
```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.compare --assert-results
python -m ci_trace.scanner_v4 .github/workflows
```

## Non-claims / weaknesses
- These tests do NOT measure real-world vulnerability precision, recall, false-positive rate, or generalization. The synthetic expected labels were designed around specified behavior.
- A GitHub Actions CI pass demonstrates the scanner and tests executed, not that a vulnerable PR artifact was safely exploited. No real attack chain has been executed.
- Runtime artifact identity and run provenance are NOT established solely from YAML syntax. Composite/reusable actions, runtime expressions, command aliases, environment variables, checkout mutations, path symbolic links, quoted multiline shells, shell control flow, and artifact ID-based selection need deeper treatment.
- Untrusted control of artifact content is NOT proven. Job conditions, branch filters, downstream extraction, and default credentials/secrets access are context-dependent.
- No zizmor/Poutine same-corpus empirical comparison has been completed.
- A write-scope declaration increases investigation priority but does not independently prove privilege access at runtime.

## Next falsification tasks
1. Build an independently adjudicated real-workflow corpus with dynamic/unknown labels.
2. Trace artifact contents through extraction, working directories, and interpreter invocations with a formal intermediate representation.
3. Restrict output severity according to access controls and negative trust-provenance evidence; make conditional execution explicit.
4. Compare version-pinned tools on the **same** frozen corpus, respecting different finding taxonomies.
5. Use unprivileged, no-secret workflow examples for end-to-end reproduction. Never run untrusted PR payloads in privileged hosted jobs.
