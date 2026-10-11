"""V8 falsification tests grounded in historical public workflows."""
import pytest
from pathlib import Path
from ci_trace.guard_proof import origin_guard_proved
from ci_trace.scanner_v8 import analyze
from ci_trace.scanner_v7 import read
ROOT=Path(__file__).resolve().parents[1]/"research_corpus"
@pytest.mark.parametrize("condition,expected",[
 ("github.event.workflow_run.head_repository.full_name == github.repository",True),
 ("${{ github.event.workflow_run.head_repository.full_name == github.repository }}",True),
 ("github.event.workflow_run.head_repository.full_name == github.repository && github.event.workflow_run.conclusion == 'success'",True),
 ("github.event.workflow_run.head_repository.full_name == github.repository || always()",False),
 ("(github.event.workflow_run.head_repository.full_name == github.repository)",False),
 ("github.event.workflow_run.head_repository.full_name == github.repository || (false && true)",False),
 ("! (github.event.workflow_run.head_repository.full_name != github.repository)",False),
 ("github.event.workflow_run.head_repository.full_name != github.repository",False),
 ("always()",False),
 ("github.event.workflow_run.head_repository.full_name == github.repository && (always())",False),
])
def test_guard_proof(condition,expected):
    assert origin_guard_proved(condition) is expected

@pytest.mark.parametrize("source,destination,target,expected",[
 ("spire_capture_vuln.yml","spire_apply_vuln.yml","ARTIFACT_OVERLAY_IMPORT",True),
 ("spire_capture_vuln.yml","spire_apply_fixed.yml","ARTIFACT_OVERLAY_IMPORT",False),
 ("attest_rebuild_vuln.yml","attest_commit_vuln.yml","ARTIFACT_METADATA_REF_WRITE",True),
 ("attest_rebuild_vuln.yml","attest_commit_fixed.yml","ARTIFACT_METADATA_REF_WRITE",False),
])
def test_historical_cases(source,destination,target,expected):
    found=analyze(source,read(ROOT/source),destination,read(ROOT/destination))
    assert any(f["rule"]==target for f in found) is expected

def test_disabled_reader_excluded():
    src=read(ROOT/"attest_rebuild_vuln.yml")
    dst=read(ROOT/"attest_commit_vuln.yml")
    job=dst["jobs"]["commit"]
    assert any(f["rule"]=="ARTIFACT_METADATA_REF_WRITE" for f in analyze("src",src,"dst",dst))
    for step in job["steps"]:
        if step.get("id")=="check":step["if"]="false"
    assert not any(f["rule"]=="ARTIFACT_METADATA_REF_WRITE" for f in analyze("src",src,"dst",dst))
