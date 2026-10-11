"""V7 defensive regressions; all artifacts are inert test data."""
import io
import subprocess
import zipfile
from pathlib import Path
import pytest
from ci_trace.scanner_v7 import analyze

RUN="${{ github.event.workflow_run.id }}"
TOKEN="${{ github.token }}"

def pair():
    p={"name":"capture","on":{"pull_request_review":{"types":["submitted"]}},
       "jobs":{"build":{"steps":[{"uses":"actions/upload-artifact@v4",
                                     "with":{"name":"bundle","path":"data.json"}}]}}}
    c={"name":"apply","on":{"workflow_run":{"workflows":["capture"]}},
       "jobs":{"apply":{"permissions":{"issues":"write"},"steps":[
       {"uses":"actions/checkout@v4","with":{"sparse-checkout":".github/workflows/scripts"}},
       {"uses":"actions/download-artifact@v4",
        "with":{"name":"bundle","run-id":RUN,"github-token":TOKEN}},
       {"uses":"actions/github-script@v7",
        "with":{"script":"const lib=require('./.github/workflows/scripts/helper.js');"}}]}}}
    return p,c

def classify(edit=None):
    p,c=pair()
    if edit:edit(p,c)
    return analyze("p.yml",p,"c.yml",c)

def test_overlay_positive():
    rows=classify()
    assert len(rows)==1
    assert rows[0]["rule"]=="ARTIFACT_OVERLAY_IMPORT"
    assert rows[0]["declared_write_scopes"]==["issues"]

@pytest.mark.parametrize("mutate",[
 lambda p,c:c["jobs"]["apply"]["steps"][1]["with"].update({"path":"${{ runner.temp }}/isolated"}),
 lambda p,c:c["jobs"]["apply"]["steps"][1]["with"].update({"path":"isolated"}),
 lambda p,c:c["jobs"]["apply"]["steps"][1]["with"].update({"name":"not-bundle"}),
 lambda p,c:c["jobs"]["apply"]["steps"][1]["with"].update({"run-id":"${{ github.run_id }}"}),
 lambda p,c:c["jobs"]["apply"]["steps"][0]["with"].update({"sparse-checkout":"not/scripts"}),
 lambda p,c:c["jobs"]["apply"]["steps"][2].update({"if":"false"}),
 lambda p,c:c["jobs"]["apply"]["steps"].reverse(),
 lambda p,c:c.update({"on":{"workflow_dispatch":None}}),
 lambda p,c:p.update({"on":{"workflow_dispatch":None}}),
])
def test_disjoint_evidence_mutations(mutate):
    assert classify(mutate)==[]

def test_metadata_sink_positive():
    p,c=pair()
    c["jobs"]["apply"]["permissions"]={"contents":"write"}
    ss=c["jobs"]["apply"]["steps"]
    ss[1]["with"]["path"]="${{ runner.temp }}/incoming"
    ss[2]={"id":"check","run":'head_ref="$(cat incoming/dist-meta/head-ref)"; echo "head-ref=$head_ref" >> "$GITHUB_OUTPUT"'}
    ss.extend([
      {"uses":"actions/checkout@v7","with":{"ref":"${{ steps.check.outputs.head-ref }}"}},
      {"run":"git push origin HEAD:${{ steps.check.outputs.head-ref }}"}])
    findings=analyze("p.yml",p,"c.yml",c)
    assert len(findings)==1
    assert findings[0]["rule"]=="ARTIFACT_METADATA_REF_WRITE"

def test_inert_overlay_and_isolation(tmp_path):
    workspace=tmp_path/"ws";helper=workspace/".github/workflows/scripts/helper.js"
    helper.parent.mkdir(parents=True)
    helper.write_text("module.exports=()=> 'TRUSTED';\n")
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,"w") as z:
        z.writestr(".github/workflows/scripts/helper.js","module.exports=()=> 'OVERLAID';\n")
    buf.seek(0)
    with zipfile.ZipFile(buf) as z:z.extractall(workspace)
    result=subprocess.run(["node","-e","console.log(require('./.github/workflows/scripts/helper.js')())"],
                          cwd=workspace,text=True,capture_output=True,check=True)
    assert result.stdout.strip()=="OVERLAID"
    helper.write_text("module.exports=()=> 'TRUSTED';\n")
    isolated=tmp_path/"isolated"
    buf.seek(0)
    with zipfile.ZipFile(buf) as z:z.extractall(isolated)
    result=subprocess.run(["node","-e","console.log(require('./.github/workflows/scripts/helper.js')())"],
                          cwd=workspace,text=True,capture_output=True,check=True)
    assert result.stdout.strip()=="TRUSTED"

@pytest.mark.parametrize("guard,expected", [
 ("github.event.workflow_run.head_repository.full_name == github.repository", False),
 ("github.event.workflow_run.head_repository.full_name == github.repository && github.event.workflow_run.conclusion == 'success'", False),
 ("github.event.workflow_run.head_repository.full_name == github.repository || always()", True),
])
def test_provenance_gate_cannot_be_bypassed_by_or(guard,expected):
    p,c=pair()
    job=c["jobs"]["apply"]
    job["permissions"]={"contents":"write"}
    job["if"]=guard
    ss=job["steps"]
    ss[1]["with"]["path"]="${{ runner.temp }}/incoming"
    ss[2]={"id":"check","run":'head_ref="$(cat incoming/dist-meta/head-ref)"; echo "head-ref=$head_ref" >> "$GITHUB_OUTPUT"'}
    ss.append({"run":"git push origin HEAD:${{ steps.check.outputs.head-ref }}"})
    result=analyze("p.yml",p,"c.yml",c)
    assert any(f["rule"]=="ARTIFACT_METADATA_REF_WRITE" for f in result)==expected
