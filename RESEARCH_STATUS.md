# CI-TRACE real-environment integration status

Verified 2026-10-11.

- Dedicated public repository: `junlin20011207/ci-trace-sandbox`
- Research branch: `ci-trace-live-lab` (not merged)
- Local CI-TRACE V3: 19/19 pytest regressions passed, **offline**.
- Real GitHub repository contents and metadata are accessible read-only via GitHub connector.
- Source-control write to research branch succeeded.
- GitHub Actions workflow upload to `main` was **blocked by the connector safety boundary**, not deployed.
- Therefore **no hosted runner has executed this study**, and no real cross-run artifact transfer or zizmor comparison has been observed on this repository.

## Safe runner experiment design

A producer on the research branch would generate only a pinned benign shell text fixture and upload it as `ci-trace-demo`. A consumer on default branch would require: completed/successful run, same repository, the exact research branch, `push` event, read-only token, matching artifact name/run ID, and an expected SHA-256 before executing the harmless fixture. No real credentials, deploy keys or write permissions are needed.

## Reproduction and caution

The downloadable local study archive includes code, tests, a safe workflow template, and details. Any proposed workflow installation requires manual review and repository owner's action. Do not disable GitHub controls or give an untrusted PR job write credentials.
