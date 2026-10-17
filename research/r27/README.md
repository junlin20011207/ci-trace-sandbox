# CI-TRACE R27 offline evidence bundle

Start with `R27_REPORT.md`. The `proposal/` directory reproduces the public R26 signed lab bundle; the new `proof/` directory contains raw Git objects from real read-only Gitee fetch, and `snapshots/` contains the archived public Gitee API responses. `r27_receipt.json` signs a SHA-256 commitment to those additional bytes with the same ephemeral LAB key. No private key or platform credential is included.

Offline historical validation:

```sh
python3 verify_deep.py --bundle . --trusted-public-sha256 8c648b361866cc1144788f7ff1317420e683a8ba3c819427dc45697877edd45d
```

Optional read-only current-state check:

```sh
python3 verify_live_ref.py --bundle . --trusted-public-sha256 8c648b361866cc1144788f7ff1317420e683a8ba3c819427dc45697877edd45d
```

The key fingerprint must come from a separately retained trusted source. A successful historical check is a LAB observation of a real Web merge; it is not a vendor attestation, organizational approval, Git CLI push result, or guarantee of current remote state.
