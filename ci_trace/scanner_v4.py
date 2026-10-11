"""CI-TRACE v4: cross-run artifact provenance and cautious executable-path triage.

Static heuristics only. A candidate never establishes exploitability.
"""
import argparse
from fnmatch import fnmatchcase
import json
import re
from pathlib import Path
import yaml
from .scanner import ActionsLoader, event_names, uploads, downloads, consumer_names, literal_path

TRIGGER_RUN = re.compile(r'\$\{\{\s*github\.event\.workflow_run\.id\s*\}\}', re.I)
GH_RUN = re.compile(r'\bgh\s+run\s+download\b', re.I)
DIRECT_EXEC = re.compile(
    r'(?:^|[;&|\n])\s*(?:'
    r'(?:bash|sh|python3?|node|source)\s+(?:-[\w]+\s+)*'
    r'|\.\s+|(?=\./))'
    r'(?P<path>\.?/?[\w.-]+(?:/[\w.-]+)+)', re.I
)

def params(step):
    value = step.get('with')
    return value if isinstance(value, dict) else {}

def static(value):
    return isinstance(value, str) and bool(value.strip()) and '${{' not in value

def names(producer):
    result = []
    for step in uploads(producer):
        result.append(params(step).get('name', 'artifact'))
    return result

def identity(produced, download):
    p = params(download)
    if p.get('artifact-ids') is not None:
        return 'unknown', []
    named = p.get('name')
    pattern = p.get('pattern')
    known = [n for n in produced if static(n)]
    uncertain = len(known) != len(produced)
    if named is not None:
        if not static(named):
            return 'unknown', []
        return ('matched', [named]) if named in known else (('unknown', []) if uncertain else ('mismatched', []))
    if pattern is not None:
        if not static(pattern):
            return 'unknown', []
        matching = [n for n in known if fnmatchcase(n, pattern)]
        return ('matched', matching) if matching else (('unknown', []) if uncertain else ('mismatched', []))
    return ('unknown' if uncertain else 'matched'), known

def run_origin(step):
    uses = str(step.get('uses', ''))
    p = params(step)
    if uses.startswith('actions/download-artifact@'):
        run_id = p.get('run-id')
        if run_id is None:
            return 'current_run'
        if not TRIGGER_RUN.fullmatch(str(run_id).strip()):
            return 'unknown_run'
        if not p.get('github-token'):
            return 'missing_token'
        repo = p.get('repository')
        if repo and str(repo).replace(' ', '') != '${{github.repository}}':
            return 'unknown_repository'
        return 'triggering_run'
    if uses.startswith('dawidd6/action-download-artifact@'):
        run_id = p.get('run_id')
        return 'triggering_run' if run_id and TRIGGER_RUN.fullmatch(str(run_id).strip()) else 'unknown_run'
    command = str(step.get('run', ''))
    return 'triggering_run' if GH_RUN.search(command) and TRIGGER_RUN.search(command) else 'unknown_run'

def extract_dirs(step, matched_names):
    if not str(step.get('uses', '')).startswith('actions/download-artifact@'):
        return None
    p = params(step)
    base = literal_path(p.get('path', '.'))
    if base is None:
        return None
    if p.get('name') is not None or str(p.get('merge-multiple', 'false')).lower() == 'true':
        return [base]
    if not matched_names:
        return None
    return [n if base == '.' else base + '/' + n for n in matched_names]

def exec_paths(script):
    return sorted({p for m in DIRECT_EXEC.finditer(script)
                   if (p := literal_path(m.group('path'))) is not None})

def granted_access(workflow, job):
    p = job.get('permissions', workflow.get('permissions'))
    if isinstance(p, dict):
        return {'explicit_write_scopes': sorted(k for k, v in p.items() if str(v).lower() == 'write'),
                'known': True}
    if isinstance(p, str) and p in ('read-all', 'write-all'):
        return {'explicit_write_scopes': ['*'] if p == 'write-all' else [], 'known': True}
    return {'explicit_write_scopes': [], 'known': False}

def steps(data):
    for job_id, job in (data.get('jobs') or {}).items():
        if not isinstance(job, dict):
            continue
        for index, step in enumerate(job.get('steps') or []):
            if isinstance(step, dict):
                yield str(job_id), job, index, step

def analyze(src_file, src, dst_file, dst):
    ud = uploads(src)
    dd = [(j, job, idx, step) for j, job, idx, step in steps(dst)
          if step in downloads(dst)]
    if not ud or not dd:
        return None
    all_edges = []
    for j, job, idx, download in dd:
        origin = run_origin(download)
        relation, selected = identity(names(src), download)
        dirs = extract_dirs(download, selected)
        for next_j, _, next_idx, execute_step in steps(dst):
            if next_j != j or next_idx <= idx:
                continue
            cmd = execute_step.get('run')
            target_paths = exec_paths(cmd) if isinstance(cmd, str) else []
            if not target_paths:
                continue
            overlap = None if dirs is None else any(
                path == directory or directory == '.' or path.startswith(directory + '/')
                for path in target_paths for directory in dirs)
            ok = origin == 'triggering_run' and relation == 'matched' and overlap is True
            all_edges.append({'job': j, 'download_step': idx, 'execution_step': next_idx,
                              'run_origin': origin, 'artifact_identity': relation,
                              'extraction_dirs': dirs, 'execution_paths': target_paths,
                              'path_overlap': overlap, 'candidate': ok,
                              'permissions': granted_access(dst, job)})
    valid = [e for e in all_edges if e['candidate']]
    return {'id': 'CTA001', 'producer': src_file, 'consumer': dst_file,
            'producer_name': str(src.get('name') or Path(src_file).stem),
            'severity': 'review_required' if valid else 'informational',
            'evidence': {'uploads': len(ud), 'downloads': len(dd),
                         'candidate_edges': valid, 'examined_edges': all_edges},
            'limitations': 'Structural triage only: no runtime identity, trust or exploit proof.'}

def scan(folder):
    files = sorted(set(Path(folder).glob('*.yml')) | set(Path(folder).glob('*.yaml')))
    workflows, errors = [], []
    for path in files:
        try:
            data = yaml.load(path.read_text(encoding='utf-8'), Loader=ActionsLoader)
            if not isinstance(data, dict):
                raise ValueError('workflow must be mapping')
            workflows.append((path.name, data))
        except (yaml.YAMLError, ValueError, UnicodeError) as exc:
            errors.append({'file': path.name, 'error': str(exc)})
    findings = []
    for src_file, src in workflows:
        if not event_names(src).intersection({'pull_request', 'pull_request_target'}):
            continue
        name = str(src.get('name') or Path(src_file).stem)
        for dst_file, dst in workflows:
            if name not in consumer_names(dst):
                continue
            finding = analyze(src_file, src, dst_file, dst)
            if finding is not None:
                findings.append(finding)
    return {'schema_version': 4, 'workflow_count': len(workflows),
            'findings': findings, 'parse_errors': errors}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('workflow_dir', nargs='?', default='.github/workflows')
    parser.add_argument('--fail-on-review', action='store_true')
    args = parser.parse_args()
    report = scan(args.workflow_dir)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if report['parse_errors']:
        return 2
    return int(args.fail_on_review and any(x['severity'] == 'review_required' for x in report['findings']))

if __name__ == '__main__':
    raise SystemExit(main())
