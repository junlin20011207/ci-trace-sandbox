"""CI-TRACE V7: bounded, retrospective cross-workflow trust-path evidence."""
import argparse,json,re,posixpath
from pathlib import Path
import yaml

class Loader(yaml.SafeLoader): pass
Loader.yaml_implicit_resolvers={k:[(t,p) for t,p in v if t!="tag:yaml.org,2002:bool"]
                                 for k,v in yaml.SafeLoader.yaml_implicit_resolvers.items()}
RISK={"pull_request","pull_request_review","pull_request_target"}
IMPORT=re.compile(r"""require\s*\(\s*['"](\./[^'"]+\.js)['"]\s*\)""")

def read(path):
    d=yaml.load(Path(path).read_text(encoding="utf-8"),Loader=Loader)
    if not isinstance(d,dict):raise ValueError("Expected workflow mapping")
    return d
def on(w):
    e=w.get("on")
    return set(e) if isinstance(e,(dict,list)) else {e} if isinstance(e,str) else set()
def triggered(w):
    e=w.get("on")
    if not isinstance(e,dict):return set()
    wr=e.get("workflow_run")
    if not isinstance(wr,dict):return set()
    n=wr.get("workflows",[])
    return {n} if isinstance(n,str) else set(n)
def jobs(w):
    for k,v in (w.get("jobs") or {}).items():
        if isinstance(v,dict):yield k,v
def steps(job):
    for i,s in enumerate(job.get("steps") or []):
        if isinstance(s,dict):yield i,s
def p(s):
    v=s.get("with")
    return v if isinstance(v,dict) else {}
def use(s,a):return str(s.get("uses","")).startswith(a+"@")
def disabled(s):return str(s.get("if","")).strip().lower() in ("false","${{ false }}","${{false}}")
def produced(w):
    names=set()
    for _,j in jobs(w):
        for _,s in steps(j):
            if use(s,"actions/upload-artifact"):
                n=p(s).get("name","artifact")
                if isinstance(n,str) and "${{" not in n:names.add(n)
    return names
def linked(d,names):
    z=p(d)
    return use(d,"actions/download-artifact") and isinstance(z.get("name"),str) and z["name"] in names and bool(z.get("github-token")) and bool(re.fullmatch(r"\$\{\{\s*github\.event\.workflow_run\.id\s*\}\}",str(z.get("run-id",""))))
def writes(w,j):
    x=j.get("permissions",w.get("permissions"))
    if x=="write-all":return ["*"]
    return sorted(k for k,v in x.items() if str(v).lower()=="write") if isinstance(x,dict) else []
def rel(path):
    if not isinstance(path,str) or "${{" in path or path.startswith("/"):return None
    x=posixpath.normpath(path)
    return None if x==".." or x.startswith("../") else x.removeprefix("./")
def checked(checkouts,module):
    for s in checkouts:
        z=p(s);root=rel(z.get("path","."))
        if root is None:continue
        sub=module
        if root!=".":
            if not sub.startswith(root+"/"):continue
            sub=sub[len(root)+1:]
        sparse=z.get("sparse-checkout")
        if sparse:
            folders=[rel(v.strip()) for v in str(sparse).splitlines() if v.strip()]
            if not any(f and (sub==f or sub.startswith(f+"/")) for f in folders):continue
        return True
    return False
def overlay_path(d,module):
    dest=p(d).get("path",".")
    if isinstance(dest,str) and "runner.temp" in dest:return False
    root=rel(dest)
    return root is not None and (root=="." or module==root or module.startswith(root+"/"))
def analyze(producer_file,producer,consumer_file,consumer):
    if not (on(producer)&RISK):return []
    if str(producer.get("name") or Path(producer_file).stem) not in triggered(consumer):return []
    names=produced(producer)
    result=[]
    for job_name,job in jobs(consumer):
        if disabled(job):continue
        permits=writes(consumer,job)
        prior=[];downloaded=[]
        seq=list(steps(job))
        for i,s in seq:
            if disabled(s):continue
            if use(s,"actions/checkout"):prior.append((i,s))
            if linked(s,names):downloaded.append((i,s))
            script=p(s).get("script","") if use(s,"actions/github-script") else s.get("run","")
            if not isinstance(script,str):continue
            for match in IMPORT.finditer(script):
                module=rel(match.group(1))
                if not module:continue
                for di,dl in downloaded:
                    if di>=i:continue
                    if not checked([x for ci,x in prior if ci<di],module):continue
                    if not overlay_path(dl,module):continue
                    result.append({"rule":"ARTIFACT_OVERLAY_IMPORT","producer":producer_file,
                      "consumer":consumer_file,"job":job_name,"module":module,
                      "download_step":di,"import_step":i,"declared_write_scopes":permits,
                      "status":"candidate","evidence":["linked_producer","cross_run_download",
                         "trusted_checkout_before_download","workspace_overlay",
                         "module_import_after_download"]})
        if "contents" not in permits and "*" not in permits:continue
        guard=str(job.get("if",""))
        if re.search(r"github\.event\.workflow_run\.head_repository\.full_name\s*==\s*github\.repository",guard):continue
        for ri,reader in seq:
            body=str(reader.get("run",""))
            key=reader.get("id")
            if not (key and "head-ref" in body and "GITHUB_OUTPUT" in body):continue
            marker="steps."+key+".outputs.head-ref"
            for di,d in downloaded:
                if di>=ri:continue
                sinks=[]
                for idx,s in seq:
                    if idx<=ri or disabled(s):continue
                    if use(s,"actions/checkout") and marker in str(p(s).get("ref","")):
                        sinks.append({"kind":"checkout_ref","step":idx})
                    if marker in str(s.get("run","")) and re.search(r"\bgit\s+push\b",str(s.get("run",""))):
                        sinks.append({"kind":"git_push","step":idx})
                if sinks:
                    result.append({"rule":"ARTIFACT_METADATA_REF_WRITE",
                     "producer":producer_file,"consumer":consumer_file,"job":job_name,
                     "source":"artifact/head-ref -> GITHUB_OUTPUT -> "+marker,
                     "sinks":sinks,"status":"candidate","declared_write_scopes":permits,
                     "evidence":["linked_producer","cross_run_download","artifact_metadata_read",
                                 "output_binding","privileged_ref_sink"]})
    return result

def scan(folder):
    files=sorted(set(Path(folder).glob("*.yml"))|set(Path(folder).glob("*.yaml")))
    wf=[];errors=[]
    for file in files:
        try:wf.append((file.name,read(file)))
        except (ValueError,UnicodeError,yaml.YAMLError) as e:errors.append({"file":file.name,"error":str(e)})
    found=[]
    for pn,producer in wf:
        for cn,consumer in wf:found.extend(analyze(pn,producer,cn,consumer))
    return {"schema_version":7,"findings":found,"parse_errors":errors}

def main():
    a=argparse.ArgumentParser()
    a.add_argument("dir",nargs="?",default=".github/workflows")
    a.add_argument("--fail-on-candidate",action="store_true")
    q=a.parse_args();data=scan(q.dir)
    print(json.dumps(data,indent=2,ensure_ascii=False))
    return 2 if data["parse_errors"] else int(q.fail_on_candidate and bool(data["findings"]))
if __name__=="__main__":raise SystemExit(main())
