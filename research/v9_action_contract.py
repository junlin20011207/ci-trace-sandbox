"""Release-linked, *bounded* GitHub Actions artifact contract.

These pins and tag SHAs were read 2026-10-11 via authenticated GitHub
connector. A pinned historical action is admitted only where its action.yml
Git blob matched the cited official major release's action.yml Git blob.
This metadata does not establish that all action runtime code is identical.
"""
from __future__ import annotations
from dataclasses import dataclass
from research.v8_expression_contract import exact_github_expression, exact_token

@dataclass(frozen=True)
class ActionRef:
    kind: str
    version: int
    ref: str
    evidence: str

# Version-ref and code metadata are explicit, independently auditable inputs.
# V7 upload has a new optional archive:false; V8 download handles non-ZIP.
KNOWN = {
    ('upload-artifact','v4'):(4,'major version v4; live Runner observed commit ea165f8d...'),
    ('download-artifact','v4'):(4,'major version v4; live Runner observed commit d3f86a10...'),
    ('upload-artifact','v7'):(7,'git tag v7 = cf430e030ddbb5b0abf93d22962f4752f3646cd9'),
    ('download-artifact','v8'):(8,'git tag v8 = 9000827ccba6bdab643e8b6fd33ac0654aef8333'),
    ('upload-artifact','cf430e030ddbb5b0abf93d22962f4752f3646cd9'):(7,'tagged commit; action.yml blob 7cb4d1e81db55320b41217e1a78a1a46e3d2baef'),
    ('download-artifact','9000827ccba6bdab643e8b6fd33ac0654aef8333'):(8,'tagged commit; action.yml blob 8b8c65029ccad20750a29fecb438eca5a607fc57'),
    ('upload-artifact','043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'):(7,'GitHub repository commit; action.yml blob identical to v7'),
    ('download-artifact','3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c'):(8,'GitHub repository commit; action.yml blob identical to v8'),
    ('upload-artifact','ea165f8d65b6e75b540449e92b4886f43607fa02'):(4,'GitHub v4.6.2 release commit'),
    ('download-artifact','d3f86a106a0bac45b974a628896c90dbdf5c8093'):(4,'GitHub v4.3.0 release commit'),
}

def resolve_action(uses, kind):
    u=str(uses).strip()
    prefix=f'actions/{kind}@'
    if not u.startswith(prefix):
        return None
    ref=u[len(prefix):]
    if (kind,ref) not in KNOWN:
        return None
    ver,evidence=KNOWN[(kind,ref)]
    return ActionRef(kind,ver,ref,evidence)

def official_action(uses,kind):
    return resolve_action(uses,kind) is not None

def artifact_mode(upload_version, raw_archive):
    """Return (archive format, supported) from effective action.yml semantics."""
    if upload_version == 7:
        raw='' if raw_archive is None else str(raw_archive).strip().lower()
        if raw in ('','true'):return 'zip',True
        if raw=='false':return 'single-file',True
        return 'unknown',False
    if upload_version == 4:
        if raw_archive is None:return 'zip',True
        return 'unknown',False
    return 'unknown',False

def compatible(mode,down_version):
    return mode=='zip' and down_version in (4,8) or mode=='single-file' and down_version==8
