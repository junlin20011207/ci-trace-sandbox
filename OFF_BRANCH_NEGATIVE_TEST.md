# Real negative push-branch filter probe (2026-10-11)

This benign commit is intentionally pushed to `ci-trace-negative-event-probe-v7`, outside the existing producer workflow's configured `on.push.branches: [ci-trace-live-lab]` allowlist.

Expected GitHub-side behavior: the named producer workflow should not start for this commit, so no related `workflow_run` consumer should start. The entire configuration was copied from the known working lab branch; the existing workflow YAML is unmodified.

This proves the producer's branch trigger filter for **this one event** only, not the consumer's rejection of malicious artifacts, code execution, or privileged behavior. No secrets or changes to main.
