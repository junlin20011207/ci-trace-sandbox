"""Conservative structural triage for GitHub Actions artifact trust boundaries."""
import argparse
import json
import re
from pathlib import Path
import yaml

class ActionsLoader(yaml.SafeLoader):
    pass
ActionsLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in entries if tag != "tag:yaml.org,2002:bool"]
    for key, entries in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
EXEC_RE = re.compile(r"(?:^|[;&|\n])\s*(?:\./|bash\s+|sh\s+|python(?:3)?\s+|node\s+|source\s+|\.\s+|chmod\s+\+x\s+|npm\s+(?:ci|install|run)\s+|make(?:\s|$))", re.I)

def event_names(data):
    events = data.get("on", {})
    if isinstance(events, str): return {events}
    if isinstance(events, list): return set(map(str, events))
    return set(events) if isinstance(events, dict) else set()

def steps(data):
    for job in (data.get("jobs") or {}).values():
        if isinstance(job, dict):
            for step in job.get("steps") or []:
                if isinstance(step, dict): yield step

def uploads(data):
    return [s for s in steps(data) if str(s.get("uses", "")).startswith("actions/upload-artifact@")]

def downloads(data):
    return [s for s in steps(data) if str(s.get("uses", "")).startswith(("actions/download-artifact@", "dawidd6/action-download-artifact@")) or re.search(r"\bgh\s+run\s+download\b", str(s.get("run", "")))]

def consumer_names(data):
    events = data.get("on")
    trigger = events.get("workflow_run") if isinstance(events, dict) else None
    names = trigger.get("workflows", []) if isinstance(trigger, dict) else []
    return {names} if isinstance(names, str) else set(map(str, names))

def literal_path(value):
    if not isinstance(value, str) or not value or "${{" in value or "*" in value:
        return None
    path = value.strip().strip('"').strip("'").replace("\\", "/").removeprefix("./")
    if path.startswith("/") or ".." in path.split("/"):
        return None
    return path.rstrip("/") or "."

def downloaded_path(step):
    if str(step.get("uses", "")).startswith(("actions/download-artifact@", "dawidd6/action-download-artifact@")):
        return literal_path((step.get("with") or {}).get("path", "."))
    return None

def ordered_execution_edges(data):
    edges = []
    for job_name, job in (data.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        seen = []
        for index, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            if str(step.get("uses", "")).startswith(("actions/download-artifact@", "dawidd6/action-download-artifact@")) or re.search(r"\bgh\s+run\s+download\b", str(step.get("run", ""))):
                seen.append((index, downloaded_path(step)))
                continue
            command = str(step.get("run", ""))
            if not EXEC_RE.search(command):
                continue
            paths = [literal_path(raw) for raw in re.findall(r"(?<![\w./])(?:\./)?[\w.-]+(?:/[\w.-]+)+(?![\w./])", command)]
            paths = [p for p in paths if p]
            for source_index, folder in seen:
                if folder is None or not paths:
                    overlap = None
                elif folder == ".":
                    overlap = True
                else:
                    overlap = any(p == folder or p.startswith(folder + "/") for p in paths)
                edges.append({"job": str(job_name), "download_step": source_index,
                              "execution_step": index, "download_path": folder,
                              "execution_paths": paths, "path_overlap": overlap})
    return edges

def artifact_names(steps_list):
    names = set()
    for step in steps_list:
        value = (step.get("with") or {}).get("name") if isinstance(step.get("with"), dict) else None
        if isinstance(value, str) and value and "${{" not in value:
            names.add(value)
    return names

def artifact_identity_relation(producer, consumer):
    produced = artifact_names(uploads(producer))
    received = artifact_names([s for s in downloads(consumer)
                               if str(s.get("uses", "")).startswith("actions/download-artifact@")])
    # Without complete literal names, identity remains unresolved.
    if produced and received:
        return "matched" if produced & received else "mismatched"
    return "unknown"

def scan(folder):
    paths = sorted(Path(folder).glob("*.yml")) + sorted(Path(folder).glob("*.yaml"))
    workflows, errors, findings = [], [], []
    for path in paths:
        try:
            data = yaml.load(path.read_text(encoding="utf-8"), Loader=ActionsLoader)
            if not isinstance(data, dict): raise ValueError("workflow must be a mapping")
            workflows.append((path.name, data))
        except (yaml.YAMLError, UnicodeError, ValueError) as error:
            errors.append({"file": path.name, "error": str(error)})
    for producer_file, producer in workflows:
        if not event_names(producer).intersection({"pull_request", "pull_request_target"}): continue
        if not uploads(producer): continue
        name = str(producer.get("name") or Path(producer_file).stem)
        for consumer_file, consumer in workflows:
            if name not in consumer_names(consumer) or not downloads(consumer): continue
            edges = ordered_execution_edges(consumer)
            identity = artifact_identity_relation(producer, consumer)
            candidates = [e for e in edges if e["path_overlap"] is True and identity != "mismatched"]
            potential_exec = len(edges)
            findings.append({
                "id": "CTA001", "producer": producer_file, "consumer": consumer_file,
                "producer_name": name, "artifact_identity": identity,
                "severity": "review_required" if candidates else "informational",
                "evidence": {"upload_steps": len(uploads(producer)),
                             "download_steps": len(downloads(consumer)),
                             "potential_execution_steps": potential_exec,
                             "candidate_edges": candidates,
                             "other_ordered_edges": [e for e in edges if e["path_overlap"] is not True]},
                "limitations": "Structural path overlap only. Artifact identity, attacker control, privileges and exploitability NOT established"
            })
    return {"schema_version": 3, "workflow_count": len(workflows),
            "findings": findings, "parse_errors": errors}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("workflow_dir", nargs="?", default=".github/workflows")
    parser.add_argument("--fail-on-review", action="store_true")
    args = parser.parse_args()
    result = scan(args.workflow_dir)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result["parse_errors"]: return 2
    return int(args.fail_on_review and any(f["severity"] == "review_required" for f in result["findings"]))

if __name__ == "__main__":
    raise SystemExit(main())
