# CI-TRACE V15 — Two-role approvals and crash-reconcilable business effects

Research date: 2026-10-12. Status: independent research Draft PR #16, not merged.

## Research decision

V13 guarantees at-most-one delivery authorization, V14 adds signed authorization and a durable `uncertain` state. However, if the server executed a business operation and its response was lost, the client has no safe way to know whether to perform the operation again. We also lack a production approval authority and protected workload key storage, and earlier “dual-host” proof consisted only of localhost/TLS.

V15 addresses *two narrower, falsifiable problems*: (1) cryptographic agreement by two independently pinned approval roles over a completely specified artifact and business subject; (2) durable and idempotent **single-SQLite-resource business effects** whose original receipt can be recovered after an acknowledgement is lost. It also tests different UID key custody and asynchronous exchange across separate GitHub runner VMs.

## Implemented security model

- `ci_trace/quorum_effect_v15.py`: require distinct `security_approver` and `release_approver` Ed25519 public keys and separate key IDs. Both must sign the exact same canonical, domain-separated subject: operation ID, repository, run ID, artifact ID, commit SHA, payload SHA-256, receiver SPIFFE-style URI, effect name/value and policy epoch.
- Approver trust map and exact expected subject can be loaded from protected, non-workspace configuration with the `execute_with_protected_roots` entry point. **The production application must choose and protect that path**; this example does not implement a complete key vault or policy signing authority.
- `AtomicEffectSink`: a protected SQLite sink, with `BEGIN IMMEDIATE`, `operation_id` PRIMARY KEY, one update to an *inert integer counter*, and the corresponding re-readable receipt inserted **in the same transaction**.
- A retry with the same operation returns its existing receipt without re-executing the effect. A policy epoch change prevents **new** previously authorized operations; it cannot reverse effects already committed.
- There is **no permission to execute arbitrary CI artifacts, Git push, publish packages, move funds, call arbitrary third-party APIs or release credentials.**

## Counterfactual and failure-driven experiments

1. **V14 vs V15, same lost ACK condition:** V14 reserves a one-use grant, persists `uncertain` and denies a second redeem; it does not know whether the business operation occurred. V15 commits the business increment and receipt atomically; after a lost ACK, a retry retrieves the committed receipt and total increments remain 1.
2. **Before and after commit real child failures:** a separate subprocess is killed after committing the V15 effect; new process sees exactly one committed effect and existing receipt. Another child terminates with an open pre-commit SQLite transaction; the transaction rolls back and a retry can safely commit.
3. **100 concurrent same-operation retries:** all receive an identical receipt, only one SQL effect.
4. **Single approver compromise:** changing the expected artifact and re-signing with only one of two test keys is rejected. Approver key IDs must be distinct **and public bytes must also differ**; two labels for the same public key do not constitute quorum.
5. **Trust-root substitution:** caller-presented keys are not accepted by the protected-root execution entry point. Same-UID writable trust directories and checkout-held policy are outside the trust model.
6. **Key custody across Linux identities:** actual unprivileged processes with UID 1 and UID 65534 can each read their own ephemeral test signer key in protected 0700/0600 directories and cannot read the other key. A same-UID process *can* read an ordinary 0600 key owned by that UID. This negative control disproves any blanket same-UID key-theft resistance.
7. **Host identity falsification and correction:** first three-runner GitHub test failed because cloned runner images reported an identical `hostname`, not necessarily the same VM. Replaced the incorrect hostname criterion with kernel `/proc/sys/kernel/random/boot_id` hashes and reran. Three distinct kernel-boot hashes were observed.
8. **Preexisting negative REST test instability:** a V8/V9 historical Artifact workflow intermittently failed on a redundant second remote metadata request whose error was redirected. Replaced that negative with a deterministic wrong-SHA falsification against already API-authenticated evidence from the preceding successful step; it no longer treats transient API errors as a wrong-SHA rejection.

## Real GitHub-hosted result — latest verified commit

- [Unit tests + 300-event fault benchmark #280](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38249800679): **279 passed, 3 skipped** in ordinary nonroot phase; **4 separate root-run UID tests passed**. The third skip is V15 signer custody in nonroot phase; it runs explicitly with sudo in its own phase.
- [Three distinct GitHub runner boot instances #5](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38249799806): two ephemeral role-signing jobs generated signatures; GitHub upload/download Artifact delivered them to a third job; the verifier established three **different kernel boot instance hashes** and accepted the two signatures. Thirty repeats of the inert SQL operation generated exactly one committed effect.
- [Existing real GitHub authenticated Artifact integration #65](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38249799933): success. This is the retained V13/V14 baseline, not a protected real-human V15 authorization.
- [Artifact layout #92](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38249799763) and [zizmor baseline #82](https://github.com/junlin20011207/ci-trace-sandbox/actions/runs/38249799751) successful; zizmor addresses different threat classes.

### 300 controlled failure scenarios

| Experiment class | Operations | Effects recovered |
|---|---:|---:|
| Failure before transaction commit | 100 | 100 effects after safe retry |
| Lost ACK after database commit | 100 | 100 existing receipts, no duplicate effects |
| Normal delivery | 100 | 100 commits |
| **Total** | **300** | **300 unique effects, 0 duplicate effects, 300 re-readable receipts** |

All these events were **designed and labeled by the research**, so they are NOT an estimate of protection against randomly encountered business failures. The hosted failure benchmark explicitly asserts all counts.

### Local sandbox baseline

- 97 passing Python tests from V10–V15, including real transient child-process termination and distinct Linux UID key custody.
- A second local 300-case run produced 300 unique effects / 0 duplicates, median complete-case time **1.342 ms**, p95 **2.244 ms**, on the sandbox host. Times do not include GitHub API, production databases, human approval or networking.
- The complete local package is `ci_trace_round15_package.zip`, available separately.

## Six originally open limitations — evidence-based assessment

| Gap | Newly demonstrated | NOT solved |
|---|---|---|
| Production approval | 2-of-2 verifiable Ed25519 quorum and pre-pinned expected subject; different ephemeral role signers on independent GitHub runner boots | **No trusted human approval, protected GitHub environment / HSM / signer service, production policy ownership, or proof that PR authors cannot control both test role jobs.** The multirunner demo bundles self-asserted public keys with signatures. |
| Exactly-once effect | SQLite counter + durable receipt committed atomically, recoverable after lost ACK/kill | **Only one SQL resource**, not exactly-once external Git push, payments, registry releases, messages or cross-database transactions. |
| Same-UID theft | Actual distinct UID signer key custody in protected directories; role public keys must differ | Same UID apps can read each other's ordinary 0600 keys. Need workload isolation / SPIRE plus kernel or hardware secret protection; no HSM. |
| Multi-host | Three distinct Linux kernel boot instances used in real GitHub-hosted jobs; signed test artifacts cross jobs asynchronously | Not a live two-host mutually authenticated TCP/mTLS service or two independently administered organizations. |
| Business value at scale | 100 identical concurrent calls and 300 different faults in reproducible local/hosted SQLite demos | No independent business client, real permission to publish, prospective blind labeling, actual ROI or measured production throughput. |
| Contest originality | New prototype-specific counterexample and V14/V15 delta with source-linked CI receipts | Ed25519 quorum, SQL idempotency, SLSA, SPIFFE and GitHub protected deployments have extensive prior art; no unbiased head-to-head claim of novelty or prize potential. |

## Reproduction

```bash
python -m pip install -r requirements.txt pytest
python -m pytest -q
python -m benchmarks.v15_faults --cases 300
python -m benchmarks.v15_v14_delta
```

Cross-host execution isolation: `.github/workflows/v15-cross-runner.yml`. It is a three-runner **artifact exchange** with ephemeral test role keys; it does not establish independent production signers. The workflow is internal-PR gated, with no checkout credentials persisted and read-only `GITHUB_TOKEN`.

## Literature and baseline

- SLSA verifier expectations, trusted builder and independent expected values: https://github.com/slsa-framework/slsa/blob/main/spec/verifying-artifacts.md
- SPIFFE Workload API and caller attestation limits: https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/
- GitHub protected environments, required reviewers and prevention of self-review: https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments
- GitHub-hosted runners: https://docs.github.com/en/actions/concepts/runners/github-hosted-runners
- SQLite transaction guarantees: https://www.sqlite.org/lang_transaction.html

**Research direction:** maintain V15 as a proof-of-concept **approval-quorum + atomic sink effect** layer. The next meaningful validation must use independent real reviewers with protected signers, a controlled real business sink capable of idempotent operations, and truly independently hosted two-party services before calling these research gaps “solved”.
