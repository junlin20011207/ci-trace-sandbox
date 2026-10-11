# CI-TRACE V8: confirmed evidence-validity correction (2026-10-11)

## Critical correction

The previous V7 320-case **synthetic** matrix had **204** YAML consumers with an invalid GitHub Actions token expression: `${{{{ secrets.GITHUB_TOKEN }}}}`. Eight of these were labeled positive and incorrectly reported as confirmed syntactic trust paths in the legacy detector. Correct GitHub expression syntax is `${{ secrets.GITHUB_TOKEN }}`. GitHub documents this grammar at https://docs.github.com/en/actions/concepts/workflows-and-actions/expressions.

**Independent V7/V8 differential:**
- Old invalid cases: 204; legacy confirmed-path findings from these cases: 8.
- New analyzer on the **unchanged invalid** cases: **0** confirmed findings; ambiguous cases are marked UNKNOWN.
- After correcting all 204 invalid expressions: V8 identifies 8 bounded syntactic risks; 320/320 synthetic labels match, with 174 unresolved/unknown observations in the whole corrected matrix.
- This is not real-world vulnerability recall or a demonstrated exploit. The original malformed and corrected matrices are both included in the reproducible V8 archive.
- Local standalone regression suite: **85/85 tests passed**, including 19 new adversarial tests.

## Source and actual tools

[Strict provenance checking source in this branch](./v8_expression_contract.py) independently verifies **exact** named official artifact action refs, whole run-id expressions, and whole token expressions; unknown variants abstain. GitHub blob SHA: `cced25237b5abc387563c327293e345eaf8c68d6`, byte-for-byte equal to the tested local module. Complete V8 analyzer/fixtures/reproduction available in the conversation archive.

I attempted to install/run official zizmor v1.30.1 inside the local sandbox via `uvx`; DNS resolution prevented installation. **No local zizmor/Poutine scan was executed on our own workflows.**

Real external **zizmor v1.30.1** hosted execution independently observed in its *own* repository:
https://github.com/zizmorcore/zizmor/actions/runs/37723533205
job 113136380837, repo commit 7ee88b504e400997876d88bf782ade1dd3869e32.
The actual public Runner log shows zizmor scanned `./.github/` and emitted SARIF `results: []` with exit code 0. **This is a different input corpus and does not provide an apples-to-apples performance/detection comparison with CI-TRACE.**

## Safe release boundaries

Historical positive-path GitHub workflows in this testbed use fixed benign artifacts and read-only tokens; no workflow YAML was modified. Public branch API presently shows `main` has `protected:false`; this does not satisfy any protected-main-based automated repair proof. No unknown attacker-controlled artifact path or credential attack was deployed. All risk labels in V8 tests are scoped static labels, not real exploits.

This file is documentation and will trigger only the owner's preexisting read-only lab producer/consumer regression. Draft PR #1 remains unmerged.
