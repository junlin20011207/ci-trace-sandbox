# CI-TRACE Round 16 — Third-party public workflow evidence and detector-bias audit

Study date: 2026-10-12. Research Draft PR #19. All third-party repository access in this study was **read-only**; their workflows were never executed, mutated or activated.

## Core correction to the research methodology

V3–V15 predominantly measured author-constructed properties, incident-aware retrospectives and controlled runtime defenses. Those are valuable unit/fault results, **not independent evidence that CI-TRACE can find general CI/CD vulnerabilities**. V7's static detector has exactly two specialized families: `ARTIFACT_OVERLAY_IMPORT` and `ARTIFACT_METADATA_REF_WRITE`. The runtime V9–V15 enforcement components do **not** magically turn V7 into a broad vulnerability scanner.

V16 freezes a 10-repository historical/public pilot and runs three programs against the same retrieved YAML: CI-TRACE V7, `zizmor==1.30.1`, `Poutine v1.1.6`. Separate Zenodo repository metadata samples are selected with seed `20261012`, with repository-level deduplication and no security-negative labels.

## Measured source acquisition and scanner outputs

The successful read-only GitHub-hosted experiment is [Run #?](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38254777897), with its machine-readable evidence downloadable as the workflow artifact `ci-trace-v16-external-evidence`.

| Corpus | Repository snapshots acquired / attempted | Workflow YAML files retrieved | V7 scoped candidates | zizmor raw findings | Poutine raw findings |
|---|---:|---:|---:|---:|---:|
| Curated public GHSL + tool repos + GHALogs example | 9 / 10 | 93 | 2 | 552 | 146 |
| GHALogs MSR'25, publisher-MD5-verified metadata, 15 sampled selected repositories | 15 / 15 | 49 | 0 | 382 | 67 |
| Public MSR'24 histories **2026-05-22 update**, publisher-MD5-verified repository metadata, 15 sampled repositories | 15 / 15 | 51 | 0 | 501 | 74 |
| **Total sampled** | **39 / 40** | **193** | **2** | **1435** | **287** |

**Critical note:** The numbers 2, 1435 and 287 are **NOT comparable true positive counts**. zizmor, Poutine and CI-TRACE have very different rule scopes; tool findings were never treated as human-reviewed ground truth. These are raw outputs across 193 YAML files and selected repository snapshots, not 193 verified security-safe/unsafe outcomes. One of the 15 GHALogs repo scans returned no parseable zizmor JSON; its scanner result remains **missing**, not zero findings. Other parsers completed with zero V7 parse errors on included workflow files.

### Provenance and reproducibility

Every successfully retrieved public repository has an exact **resolved 40-digit commit SHA**, and every YAML file has SHA-256, size, GitHub blob ID and relative path preserved in the JSON artifacts. Any repo with missing/archived workflow paths is marked as `collection_error`; the rejected source is never silently replaced by another project. No private code, private Actions artifacts or GitHub secrets were accessed.

1. Curated historical GHSL cases use disclosed vulnerable commit refs, including: `nf-core/tools@75e643ad2c62cdc8ecd39aa56c0c314efd4b13e4`, `DataDog/trivy@7acb5f6f095a11cb9911af5a0bc03aecc7c88f8f`, `marimo-team/marimo@b4181abaf6bd896b6b0dac5490c9cf08269b590c`, `spiffe/spire@ef8527ec91013c6c1b4741e0f6ac0786576e620e`, `actions/attest@60c80190bb1a4fb35e5724ede753db5656412b68`, and `jupyterlab/maintainer-tools@b48fcdb87e70c45789abd80d4042b06641e47b46`.
2. GHALogs version 1.0.1 (`https://zenodo.org/records/14796970`): verified `repositories.json.gz` MD5 `a44ed2c635348ecc8641f966748e32d2`, actual download **69,208,463 bytes**. The metadata contains **28,301 unique qualifying selected repositories with workflow records**; a seeded 15-repository sample yielded 49 accessible workflow files. The huge ~142 GB run logs were NOT downloaded.
3. Cardoen et al., workflow histories 2026-05-22 (`https://zenodo.org/records/20340547`): verified `repositories.csv.gz` MD5 `a345384e924083ae4da327e4fdf3af74`, metadata included **54,758 unique eligible repository-name entries**; seeded 15-repository sample yielded 51 workflow YAML. The multi-gigabyte workflow-history archive was NOT downloaded.

**Data correction history:** The first GHALogs iteration sampled the full 240k+ candidate metadata pool, rather than the publisher's selected workflow-bearing repositories. That was a population bias. The sampling algorithm was corrected to require `selected==true`, `nb_workflows>0`, and unique repository names *before* sampling; tests were added. The 2026 dataset initially failed with an invalid `utf8-sig` decoder name, then passed after a corrected `utf-8-sig` decode. A GHALogs companion repo was incorrectly requested at `main` instead of `master`; the error remained recorded rather than interpreted as a safe workflow.

## Historical vulnerability family coverage, not aggregate recall

Independent public GHSL disclosures identify 6 historically affected repositories in the curated group:

- **Already targeted and used during earlier V7 development (NOT blind):** GHSL-2026-204 SPIRE artifact overlay; GHSL-2026-225 actions/attest artifact metadata branch write. V7 identified candidate evidence for both in authentic historical commits.
- **Outside V7's implemented detector families (NOT valid general negative labels):** GHSL-2025-080 nf-core/tools privileged PR code checkout; GHSL-2026-199 DataDog/trivy privileged local composite action; GHSL-2026-226 marimo approval-to-checkout TOCTOU; GHSL-2026-203 jupyterlab/maintainer-tools composite action TOCTOU. V7 produces no family-specific evidence for these categories. A narrow V7 detector must not be described as discovering or resolving them.

`jupyterlab/maintainer-tools` specifically involves vulnerable `.github/actions/update-snapshots-checkout/action.yml` code; scanning only `.github/workflows/*.yml` cannot cover that root cause. This is an *ingestion/data-modeling* limitation as well as a rule-scope limitation.

A legitimate next benchmark should label concrete (repository, commit, workflow path, risk family, source-to-sink witness) tuples and include reviewer-verifiable fixed versions. The unit of ground truth must be precise, not “the repository is vulnerable” and not “a third-party tool emitted an alert.”

## Baseline comparison and processing time

- The curated set's Poutine output includes `untrusted_checkout_exec`, `injection`, `default_permissions_on_risky_events` and other families not implemented by V7; zizmor emits `template-injection`, `artipacked`, `excessive-permissions`, etc.
- Observed scanner wall-clock time summed over 39 successfully processed repo snapshots: V7 **~0.99 s**, zizmor **~43.24 s**, Poutine **~6.90 s**. These timings include process setup for external scanners and incomparable analysis scopes; **DO NOT report a speedup or superior security accuracy**.
- The test project’s existing V15 unit and signed real Artifact integration workflows also continued to pass independently. The V16 cross-runner test adds postcommit-ACK-loss fault injection on the third runner after genuine asynchronous GitHub Artifacts were received, but this is **not live inter-host mTLS**.

## How to reproduce

```bash
python -m pip install -r requirements.txt pytest
python -m pip install zizmor==1.30.1
# Install Poutine v1.1.6 from release and VERIFY its official SHA-256 checksums.
python -m benchmarks.v16_public_eval
python -m benchmarks.v16_ghalogs
python -m benchmarks.v16_histories
python -m pytest -q tests/test_v16_public_sampling.py
```

Use `.github/workflows/v16-external.yml` for a reproducible read-only hosted experiment. The `results/v16_*.json` files attached to its workflow artifact contain exact source commits, file hashes, scanner version-controlled outputs and missingness. The source tarball in the newer workflow artifact includes code and manifests **but not third-party raw YAML**, reducing redistribution/PII risks. Consult dataset and repository licenses before redistributing source or logs. The optional Zenodo steps explicitly record fetch errors and do not synthesize fallback data.

## Evidence limits and next defensible research target

1. 193 sampled public YAMLs from 39 repository snapshots is a **real pilot**, not a statistically validated representative sample of the millions of historical GitHub Actions workflows. Many GHALogs commits are historical and may no longer exist; inaccessible sources are excluded with count disclosure.
2. There are **zero independently verified safe/negative labels**. We cannot estimate false-positive rate, precision, recall or comparative superiority. The six GHSL labels are published historical positives by attack family, and two were used to construct V7.
3. The selected 10-repository advisory cohort is *purposive*, and the 15-repo metadata draws from each dataset are deterministic researcher samples; no externally held-out blind labeling team was used.
4. Poutine/zizmor output categories are not the same target as CI-TRACE V7 or V15 runtime enforcement. The large third-party totals should not be presented as more security vulnerabilities, or reduced to a false precision/recall metric.
5. This does not deploy a protected real-human approval authority, execute third-party vulnerable workflows, prove live two-machine TLS, demonstrate real unauthorized access, or validate business impact in production.
6. **Best engineering investment:** add trust-provenance source/consumer graph ingestion beyond `workflow_run`, especially `pull_request_target` local actions and authorization/checkout TOCTOU, then freeze a fresh GHSL holdout to test it. Do not tune detectors on the current reporting cohort while also claiming blind evaluation.

## Independently published sources
- GHALogs MSR 2025 and official examples: https://zenodo.org/records/14796970 / https://github.com/D2KLab/gha-dataset
- 2026 workflow histories release: https://zenodo.org/records/20340547
- GHSL 2026 advisory index: https://securitylab.github.com/advisories/
- zizmor JSON/SARIF usage: https://docs.zizmor.sh/usage/
- Poutine v1.1.6 source and Apache 2 license: https://github.com/boostsecurityio/poutine
