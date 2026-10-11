# CI-TRACE V7: bounded exact planning and live repository preflight

**2026-10-11 | Defensive CI/CD research only. Do not merge into a production workflow without review.**

## Actual verified GitHub metadata

- Repository: [junlin20011207/ci-trace-sandbox](https://github.com/junlin20011207/ci-trace-sandbox)
- Default branch: `main`
- `GET /repos/junlin20011207/ci-trace-sandbox/branches/main`: **protected = false**
- `GET /repos/junlin20011207/ci-trace-sandbox/rulesets`: 0 visible repository rulesets
- Branch-protection-details API: **403 Resource not accessible by integration**
- Therefore V5's “release on protected main” assumption is **not fulfilled** in this test repository. V7 deliberately returns **REFUSED**, rather than treating a hypothetical branch control as a deployed guarantee.
- These are time-scoped read-only API results, not an assurance about all inherited/org-level policies.

## Newly deposited actual source

- [Scalable MILP planner](./scalable_cut_v7.py): SciPy/HiGHS, bounded maximum 200 risk paths and 150 candidate mitigations. Only certifies a minimal model cost if the solver reports zero MIP gap, and excludes any mitigation shown to break a required release path. Otherwise returns UNKNOWN/UNSAT/REFUSED.
- [Policy deployment gate](./deployment_gate_v7.py): conservatively rejects absent or unverifiable protected-main preconditions.
- The source code's Git object hashes have been cross-checked with the offline research code used by the 59-test pytest suite.

## Reproducible experimental results (offline synthetic, NOT hosted Runner)

- V6 retained: 47 regression/independent evidence tests.
- V7: 6 scalable optimization tests, including 220 small independent brute-force cross-check cases; 6 policy fail-closed tests.
- **59/59 offline pytest cases passed.**
- 600 independent synthetic large graphs with 45 risk paths and 80 mitigation actions each: optimal model cost below greedy in **358**, equal in **242**; aggregate exact model cost **3657** vs greedy **4148** (11.8% relative synthetic-cost reduction).
- Median MILP solve time **29.018 ms**, p95 **122.945 ms** on this sandbox.
- Model assumes risks/candidate effect/cost data are already verified. It is *not* a complete implementation of all GitHub Actions semantics or a real labor-time benchmark.

## Real-world Runner evidence and scope

Existing read-only `CI-TRACE Lab Producer` and `CI-TRACE Lab Consumer` workflows were already observed successfully delivering artifacts in three complete rounds; see [V6 live evidence](./V6_LIVE_EVIDENCE.md). V7 commits trigger *additional benign positive-path Runner regressions*, not runtime negative-condition scans of the MILP solver.

No available executable for **zizmor** or **Poutine** was installed, and no scan from either is presented here. zizmor's published `dangerous-triggers` audit already recognizes `workflow_run`; **do not claim novel discovery of this existing security pattern**.

All live original workflow definitions and actual GitHub artifacts, V7 Python tests, machine-readable benchmark results, and the dated Chinese audit are supplied in the current ChatGPT research archive. This branch is a testbed; PR #1 remains DRAFT, unmerged.