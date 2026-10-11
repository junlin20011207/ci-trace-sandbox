# CI-TRACE V5: offline evidence and bounded repair optimization

This folder includes an executable Python reference (`min_cut.py`), one greedy-suboptimal risk-graph example, and measured aggregate statistics from a separate local benchmark. Example: `python research/min_cut.py research/cases/greedy_counterexample.json` selects B and C, preserving `main-release` at total cost 4. A greedy coverage/cost heuristic selects A first and then both B,C at cost 6.

**Security scope:** input attack paths and candidate mitigation effects MUST first be established by a conservative workflow analyzer or human verification. The solver does not interpret GitHub Actions semantics, execute workflows, write to production, or prove a real GitHub vulnerability. With incomplete provenance it returns UNKNOWN. A valid optimization result is not itself proof of live deployment safety.

**Actual deployment status:** research-branch file commits are verified. The connector blocked creating the GitHub Actions consumer workflow on the default branch. Hosted-runner test count in this repository remains zero; no bypass attempted. Full V5 local test archive is available separately in the conversation.
