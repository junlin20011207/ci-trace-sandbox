# CI-TRACE R25: Actual Git server-side authorization, local isolated research

This is a **working disposable LOCAL Git server experiment**. It is **not Gitee**. It does not use a Gitee access token, or a live Gitee protected branch.

## Why this experiment exists

Prior rounds verified the publisher could decline unauthorized pushes before sending them. But if the developer edits the build workflow and attempts to push directly, publisher-local checks are insufficient. R25 adds an independently controlled receiver-side check in the actual `git receive-pack` path using a server-owned `pre-receive` hook, plus a UNIX peer credential check.

The issuer lab key is held by the root-controlled laboratory; not an actual independent organization. A hosted Gitee SaaS user cannot assume they can install custom Git server hooks, so this implementation is a **self-hosted control-plane research reference** rather than a drop-in Gitee feature.

## How to reproduce (isolated disposable Linux root namespace)

Requires Linux, Python >=3.10, Git, OpenSSL 3.0+ supporting SM2/SM3. Runs as root in an isolated disposable VM/container because `SO_PEERCRED` / separate UIDs are part of the test.

```
python3 git_gate_lab.py setup
python3 git_gate_lab.py server & SERVER_PID=$!
python3 git_gate_lab.py test
kill "$SERVER_PID"
```

The program intentionally uses only `/tmp/ci_trace_r25` and refuses operation without its local-only sentinel `CI_TRACE_R25_LOCAL_ONLY`. No remote Gitee repo URL or credential handling exists in this program. For actual Gitee integration, use Gitee's server-side protected branch rules and a trusted publisher identity, not Gitee server hooks.

## Verified outcomes

The current run uses an actual Git receiver, actual Git object pack upload, server-enforced identities, server-side SM2+SM3 signed grant, single-consumption SQLite ledger, Git create-only update, and offline check of exact remote-retrieved grant bytes. Eight attempts: only the valid first push succeeds. The rest are expected rejections: disallowed UID, wrong recipient, swapped artifact, modified signature, expired grant, repeated operation on new branch, and second write to existing ref.

## Boundaries

- No Gitee remote write, no protected `master` branch, and no real CodeArts/Gitee Go official pipeline invocation. The last public audit found `liljunlin/test` master `protected:false`.
- Root still controls server, lab signer and both UIDs; not organizational independence. The test labels are research-generated, not a third-party blind dataset.
- Git service-side hook uses a reserve-before-update SQLite entry: if downstream Git fails after a successful pre-receive check, a grant may be consumed without ref creation (safe but potentially unavailable). Further recovery must consult the actual remote ref and never infer success solely from the ledger.
- A server with custom pre-receive hooks differs from Gitee SaaS, which requires actual protected-branch configuration and authenticated allowlist checks.
- SM2/SM3 primitives are not certified as commercial cryptography compliant merely by execution in OpenSSL.

## Security / honest evidence

`results.json` is produced by an actual run and is the authoritative local experiment result. The scripts and report intentionally contain no private tokens and no real Gitee write capability. The ephemeral SM2 private key stays in `/tmp/ci_trace_r25/secret.key` and is not packaged.
