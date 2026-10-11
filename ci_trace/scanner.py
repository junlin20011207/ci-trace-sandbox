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
            potential_exec = sum(bool(EXEC_RE.search(str(s.get("run", "")))) for s in steps(consumer))
            findings.append({
                "id": "CTA001", "producer": producer_file, "consumer": consumer_file,
                "producer_name": name,
                "severity": "review_required" if potential_exec else "informational",
                "evidence": {"upload_steps": len(uploads(producer)),
                             "download_steps": len(downloads(consumer)),
                             "potential_execution_steps": potential_exec},
                "limitations": "Artifact-to-execution dataflow and attacker control NOT established"
            })
    return {"schema_version": 1, "workflow_count": len(workflows),
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
