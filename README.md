# CI-TRACE — GitHub Actions cross-workflow artifact trust-boundary research

Experimental, **defensive static-analysis** research for the network security innovation contest. A reported path is a **review candidate**, never proof that attacker-controlled data can be executed or that a vulnerability is exploitable.

## Research components

- `ci_trace/scanner.py`: preserved legacy structural heuristic, for before/after comparison.
- `ci_trace/scanner_v4.py`: provenance-aware V4 candidate that models the triggering run, artifact selection, extraction destination, execution ordering, and declared write scopes.
- `tests/test_scanner.py` and `tests/test_scanner_v4.py`: independent regression suites.
- `benchmarks/compare.py`: 20 synthetic author-labeled fixtures contrasting legacy and V4.
- `ROUND4_REPORT.md`: actual GitHub Actions logs, assumptions, controls, and remaining research limitations.

## Run locally

```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.compare --assert-results
python -m ci_trace.scanner_v4 .github/workflows
```

Use `--fail-on-review` to exit 1 when a V4 review-required candidate is found (exit 2 on YAML parsing error). Input is a directory containing YAML GitHub Actions workflow files.

## Verified on GitHub hosted runners

- <https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38134040054> — 56 tests passed.
- <https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38134126715> — 56 tests, synthetic benchmark and V4 self-scan succeeded.
- Synthetic comparison: legacy expected-label matches **13/20**, V4 **20/20**. This is **not** a real-world detection rate.

## Scope and safety

No attack against third-party systems, no privileged run of an untrusted PR artifact, and no security secrets required for scanning. Cross-run source and file-path analyses are limited to explicit, statically recognized patterns; uncertainty must not be equated with safety or exploitability.
