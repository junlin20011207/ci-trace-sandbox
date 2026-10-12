# CI-TRACE Round 18 — Cross-platform verification boundary

This research-only manifest contains no credentials, secret keys, production policies or executable workflow changes. **Do not merge this Draft PR without independent security review.**

## Sandbox evidence (2026-10-12)
- Signed-policy custodian UID 65531, grant issuer UID 65534, publisher UID 65533; different local Linux users; not independent legal organizations.
- Local authority integration: 24/24 specific checks, 64 concurrent same-ticket requests consistent, 250 mutated subjects denied.
- OpenFGA `openfga/sample-stores` external author-labeled sample assertions: 68/68 match (39 positive / 29 negative) with manually transcribed public fixture subset. These are **not** independently adjudicated production delivery events.
- Local Git bare remotes emulating GitHub/Gitee policy enforcement: candidate-only publishing and authorized alternative remote succeed; restricted upstream branch creation denied.
- Attempt to access https://gitee.com/liljunlin/test.git from this sandbox returned `Could not resolve host: gitee.com`; no real Gitee clone, push or CI run occurred. Offline replay scripts are supplied separately.

## Not proven
- Independent institution actually possessing policy-signing keys or acting as approver.
- Real Gitee required approval/branch protection controls.
- Production blind-label sensitivity/specificity or meaningful security improvement against an optimally configured native baseline.
- Cross-machine exactly-once external side effects or production safety SLO.

Do not claim these are complete deployment or business blind-trial results. `main` and all existing workflow files remain unchanged by this manifest.
