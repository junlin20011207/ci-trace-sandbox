"""V16 immutable-by-commit PUBLIC workflow evaluation, not a vulnerability oracle.

Public GitHub REST read-only. Never executes downloaded workflow code.
Reports coverage, parser errors, V7 targeted matches and available independent
scanner findings without mixing taxonomies or treating unlabeled files as safe.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from urllib.request import Request,urlopen
from urllib.error import HTTPError,URLError
from ci_trace.scanner_v7 import scan as v7_scan

API="https://api.github.com"
TIMEOUT=35

def api_get(path, token):
    headers={"Accept":"application/vnd.github+json",
             "User-Agent":"ci-trace-v16-public-research",
             "X-GitHub-Api-Version":"2022-11-28"}
    if token:headers["Authorization"]="Bearer "+token
    request=Request(API+path,headers=headers)
    with urlopen(request,timeout=TIMEOUT) as response:
        return json.load(response)

def fetch_repo(repo,ref,required,maximum,token,root):
    owner,name=repo.split("/")
    base=f"/repos/{owner}/{name}"
    if ref=="DEFAULT":
        ref=api_get(base,token)["default_branch"]
    c=api_get(base+"/commits/"+ref,token)
    commit=c["sha"]
    items=api_get(base+"/contents/.github/workflows?ref="+commit,token)
    if not isinstance(items,list):raise ValueError("workflow directory is not an array")
    candidates=[it["path"] for it in items if isinstance(it,dict) and it.get("type")=="file"
                and it.get("path","").endswith((".yml",".yaml"))]
    selected=sorted(candidates,key=lambda p:(hashlib.sha256(
        ("ci-trace-v16-seed:20261012:"+repo+":"+p).encode()).hexdigest(),p))[:maximum]
    for path in required:
        if path in candidates and path not in selected:selected.append(path)
    root.mkdir(parents=True,exist_ok=True)
    files=[]
    for p in sorted(selected):
        item=api_get(base+"/contents/"+p+"?ref="+commit,token)
        if item.get("encoding")!="base64":raise ValueError("expected base64 contents")
        data=base64.b64decode(item["content"])
        if len(data)>400000:continue
        target=root/Path(p).name
        target.write_bytes(data)
        files.append({"path":p,"raw_sha256":hashlib.sha256(data).hexdigest(),
                      "bytes":len(data),"github_blob_sha":item.get("sha")})
    return {"repo":repo,"resolved_commit_sha":commit,"at_reference":ref,
            "workflow_candidates":len(candidates),"workflow_sampled":len(files),
            "required_paths":required,"required_present":all(p in candidates for p in required),
            "files":files}

def tool_scan(command,cwd,timeout=90):
    t=time.monotonic()
    try:
        run=subprocess.run(command,cwd=cwd,text=True,capture_output=True,timeout=timeout)
        output=run.stdout
        try:
            obj=json.loads(output)
        except (ValueError,TypeError):
            obj=None
        entries=(obj if isinstance(obj,list) else
                 obj.get("findings",[]) if isinstance(obj,dict) else [])
        findings=len(entries) if isinstance(entries,list) else None
        rule_counts={}
        for item in entries if isinstance(entries,list) else []:
            if not isinstance(item,dict):continue
            ident=item.get("ident") or item.get("rule_id") or item.get("rule")
            if isinstance(ident,dict):ident=ident.get("id")
            if isinstance(ident,str):
                rule_counts[ident]=rule_counts.get(ident,0)+1
        return {"available":True,"returncode":run.returncode,
          "seconds":round(time.monotonic()-t,4),"parsed_json":obj is not None,
          "finding_count":findings,"rule_counts":dict(sorted(rule_counts.items())),
          "stdout_sha256":hashlib.sha256(output.encode()).hexdigest(),
          "stdout_excerpt":output[:250],"stderr_excerpt":run.stderr[:250]}
    except (FileNotFoundError,subprocess.TimeoutExpired) as e:
        return {"available":False,"error":str(e)[:200],
                "seconds":round(time.monotonic()-t,4)}

def evaluate(manifest, output, token):
    summary={"schema_version":1,"selection":manifest["selection"],
      "github_dataset":"GHALogs public repository example only, NOT full Zenodo metadata",
      "source_manifest_sha256":hashlib.sha256(json.dumps(
          manifest,sort_keys=True).encode()).hexdigest(),
      "scope":"read-only external workflow metadata; not vulnerability labeling",
      "repositories":[]}
    with tempfile.TemporaryDirectory(prefix="ci-trace-v16-") as base:
        for ix,entry in enumerate(manifest["sources"]):
            repo=entry["repo"];root=Path(base)/str(ix)
            rec={"repo":repo,"advisory":entry.get("advisory"),
                 "disclosure_class":entry["class"],
                 "label":"published_disclosure" if entry.get("advisory") else "UNLABELED"}
            try:
                snap=fetch_repo(repo,entry["ref"],entry.get("required",[]),
                        manifest["max_workflows_per_repo"],token,root/".github/workflows")
                rec["snapshot"]=snap
                t=time.monotonic()
                v7=v7_scan(root/".github/workflows")
                rec["ci_trace_v7"]={"findings":len(v7["findings"]),
                  "rules":sorted(set(x["rule"] for x in v7["findings"])),
                  "parse_errors":v7["parse_errors"],
                  "seconds":round(time.monotonic()-t,4)}
                rec["zizmor"]=tool_scan(["zizmor","--format=json-v1",
                  "--no-progress",".github/workflows"],root)
                rec["poutine"]=tool_scan(["poutine","analyze_local",".",
                  "--format","json","--disable-version-check"],root)
            except (HTTPError,URLError,ValueError,KeyError,OSError) as e:
                rec["collection_error"]=str(e)[:350]
            summary["repositories"].append(rec)
            print("CASE "+json.dumps({"repo":repo,"sample":rec.get("snapshot",{}).get(
                "workflow_sampled",0),"v7":rec.get("ci_trace_v7",{}).get("findings"),
                "error":rec.get("collection_error"),"zizmor_available":
                rec.get("zizmor",{}).get("available"),"poutine_available":
                rec.get("poutine",{}).get("available")}),flush=True)
    rows=summary["repositories"]
    summary["metrics"]={
       "repository_attempted":len(rows),
       "repository_fetched":sum("snapshot" in x for x in rows),
       "workflow_files_fetched":sum(x.get("snapshot",{}).get("workflow_sampled",0) for x in rows),
       "v7_candidates":sum(x.get("ci_trace_v7",{}).get("findings",0) for x in rows),
       "v7_parse_errors":sum(len(x.get("ci_trace_v7",{}).get("parse_errors",[])) for x in rows),
       "zizmor_completed":sum(bool(x.get("zizmor",{}).get("parsed_json")) for x in rows),
       "poutine_completed":sum(bool(x.get("poutine",{}).get("parsed_json")) for x in rows),
       "advisory_labeled_repositories":sum(bool(x.get("advisory")) for x in rows),
       "verified_unaffected_labels":0
    }
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(summary,sort_keys=True,indent=2)+"\n")
    print("SUMMARY "+json.dumps(summary["metrics"],sort_keys=True))
    # An unavailable repository or baseline MUST remain visible as missing,
    # never be counted as negative or as a tool returning zero findings.
    return 0 if summary["metrics"]["repository_fetched"]>=4 else 2

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--manifest",default="research_corpus/v16_external_manifest.json")
    p.add_argument("--out",default="results/v16_external_result.json")
    args=p.parse_args()
    manifest=json.loads(Path(args.manifest).read_text())
    return evaluate(manifest,Path(args.out),
                    os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN",""))

if __name__=="__main__":
    raise SystemExit(main())
