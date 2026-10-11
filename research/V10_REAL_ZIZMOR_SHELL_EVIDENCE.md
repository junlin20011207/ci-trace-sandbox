# CI-TRACE V10: real zizmor baseline and independent shell counterexamples

Date: 2026-10-11. Defensive research only. No production credential or privileged-workflow exploit.

## Actual third-party tool execution

- Actual GitHub-hosted run: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38131556616
- Official zizmor v1.30.1 installed from PyPI and run on the research branch with `--offline --collect=workflows --format=json`.
- Artifact ID 11699615788 (`ci-trace-zizmor-baseline`) contains the original JSON result; independently downloaded and inspected.
- Three real **High `unpinned-uses`** findings: one producer upload-artifact tag and two scan-workflow actions (checkout and upload-artifact). These are static policy findings, not proven exploitable vulnerabilities.
- This scan did NOT include the default-branch consumer workflow. It covered only two YAML files in the research branch.
- Exact Git Blob SHAs of the scanned workflows were independently checked: producer ae6735420a774c4373b564244b41e4543b94d8aa; zizmor scanner 19fd2ccac2dac427db20106d4077ad91e8a43611.
- CI-TRACE checked the same two source files and returned 0 cross-workflow execution findings. The rule coverage differs; this is NOT comparative security detection superiority.

## Bounded local shell semantics improvement

- A separately constructed controlled differential study executed twelve benign shell-script command variants as actual Bash subprocesses.
- Old bounded parser recognized 2/12 synthetic cross-run patterns; new parser recognized 12/12.
- Seven non-executing controls, including `bash -n`, gave no findings; five dynamic unsupported forms returned UNKNOWN.
- 139/139 offline pytest regressions, including independently downloaded zizmor artifact and the original hosted-artifact evidence, passed in an isolated sandbox copy.
- There was no actual untrusted PR exploitation or high-privilege script execution.

## Verified official action commit pins (GitHub refs/tags/v4 as of 2026-10-11)

- actions/checkout@v4 -> 11d5960a326750d5838078e36cf38b85af677262
- actions/upload-artifact@v4 -> ea165f8d65b6e75b540449e92b4886f43607fa02
- actions/download-artifact@v4 -> d3f86a106a0bac45b974a628896c90dbdf5c8093
- Proposed pinned YAML copies were prepared **offline**; these changes are NOT deployed and have not been rescanned by zizmor.

## Remaining blockers and limits

- Existing default branch was observed `protected: false`; modeled protected-main automatic release repair must REFUSE until independently verified.
- No apples-to-apples ground-truth benchmark of CI-TRACE versus zizmor/Poutine on known-vulnerable live workflows has been completed.
- No claim of improved national-prize probability or general 100% precision/recall is justified by the scoped test suite.
- Full tested Python source, the original GitHub-produced ZIP, proof scripts, scoped datasets and the reproducible offline test runner are in the V10 local research package shared with the user. 

This is a research-branch report only: **do not merge draft PR #1** as a production change.

## Additional hosted-runner raw artifact format proof

- Real runner: https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38132036481
- Exact workflow Git Blob SHA: a2e88eb23ff36452b70be6ba4f556d92d5eb52b5
- Pinned producer upload-artifact commit: cf430e030ddbb5b0abf93d22962f4752f3646cd9; pinned downloader: 9000827ccba6bdab643e8b6fd33ac0654aef8333.
- Upload `archive: false` produced the raw 22-byte `payload.txt`, despite configured `name: ignored-name`; download with `payload.txt` succeeded and download with `ignored-name` failed as expected.
- Artifact ID 11698259927; original bytes SHA256 d834dba796eeb4773e565102c7592debdd8bc5abf5d2deac9658064f7a6682f5 independently verified in sandbox.
- Caution: the existing zizmor scanner deliberately captures exit status with `|| result=$?` without a subsequent failure gate. A green runner job does NOT mean its three High-level findings were remediated or enforcement passed.
- Updated isolated V10 package has **140/140** offline pytest checks passed, including the raw-artifact byte test.
