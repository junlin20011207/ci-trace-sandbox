# CI-TRACE CTA001 — round 2 research record

## Hypothesis
A PR-triggered producer may upload an artifact later downloaded by a workflow_run consumer. The boundary deserves review when the consumer appears to execute a file under the extraction destination.

## Reproducible checks
Run `python -m pytest -q`, then `python -m ci_trace.scanner .github/workflows`.
The suite now includes 19 tests: 11 baseline cases and 8 path/order regressions. GitHub Actions initially verified 11 baseline tests on run 38132587950. The expanded suite still requires a separate successful GitHub-hosted run.

## What the second iteration changed
* Download and execution must occur in the same job, in that order.
* Simple literal extraction paths are compared against literal command paths by prefix, not substring.
* Dynamic and unsafe path values remain unresolved rather than being represented as confirmed overlaps.
* The result records candidate edges and other ordered edges for auditability.

## Key limitations
* A dot/default extraction path is broad and can still produce false positives.
* Artifact name, run ID, uploaded path and extracted content are NOT traced end-to-end.
* Regex command matching is not shell parsing or dynamic taint analysis.
* Effective GitHub token permissions, secrets, repository trust and attacker control are not yet assessed.
* A 'review_required' outcome is not evidence of exploitable vulnerability.

## Next validation protocol
1. Freeze and publish a labeled corpus of both positive and negative synthetic workflow pairs.
2. Record expected outcomes separately for structural alerts and actually demonstrable attacker-to-execution reachability.
3. Run zizmor and Poutine on the same corpus and compare with consistent definitions of recall, precision and unknown classification.
4. Implement artifact selection constraints and branch/repository provenance.
5. Avoid running attacker-controlled code in privileged GitHub hosted workflows; use isolated non-secret test environments.
