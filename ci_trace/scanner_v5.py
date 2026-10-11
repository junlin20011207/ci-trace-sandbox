"""CI-TRACE V5: condition and working-directory-aware artifact trust-boundary triage.

Only static candidates are reported; no exploitation or effective privilege is proven.
"""
import argparse
import json
import re
from pathlib import Path
import yaml
from . import scanner_v4 as v4

def gate(value):
    """Three-valued condition: disabled, enabled, conditional."""
    if value is False:
        return 'disabled'
    if value is True or value is None:
        return 'enabled'
    text = str(value).strip().lower()
    if text in ('false', '${{ false }}', '${{false}}'):
        return 'disabled'
    if text in ('true', '${{ true }}', '${{true}}'):
        return 'enabled'
    return 'conditional'

def active_steps(workflow):
    for job_id, job, index, step in v4.steps(workflow):
        if gate(job.get('if')) == 'disabled' or gate(step.get('if')) == 'disabled':
            continue
        yield job_id, job, index, step

def normalized_workdir(workflow, job, step):
    """Step > job > workflow defaults for run working-directory."""
    wf = workflow.get('defaults') if isinstance(workflow.get('defaults'), dict) else {}
    jb = job.get('defaults') if isinstance(job.get('defaults'), dict) else {}
    wf_run = wf.get('run') if isinstance(wf.get('run'), dict) else {}
    jb_run = jb.get('run') if isinstance(jb.get('run'), dict) else {}
    raw = step.get('working-directory', jb_run.get('working-directory', wf_run.get('working-directory', '.')))
    return v4.literal_path(raw)

def paths_with_cwd(command, cwd):
    """Do not infer paths across chdir, heredocs or unresolved working dirs."""
    if cwd is None or re.search(r'(?m)(?:^|[;&|\n])\s*cd\s+', command) or '<<' in command:
        return None
    paths = v4.exec_paths(command)
    if not paths:
        return []
    return sorted({path if cwd == '.' else cwd + '/' + path for path in paths})

def analyze(producer_file, producer, consumer_file, consumer):
    uploads = [(jid, job, i, step) for jid, job, i, step in active_steps(producer)
               if str(step.get('uses', '')).startswith('actions/upload-artifact@')
               and bool(v4.params(step).get('path'))]
    downloads = [(jid, job, i, step) for jid, job, i, step in active_steps(consumer)
                 if (str(step.get('uses', '')).startswith(('actions/download-artifact@', 'dawidd6/action-download-artifact@'))
                     or v4.GH_RUN.search(str(step.get('run', ''))))]
    if not uploads or not downloads:
        return None
    names = [v4.params(step).get('name', 'artifact') for _, _, _, step in uploads]
    producer_conditional = any(
        gate(job.get('if')) == 'conditional' or gate(step.get('if')) == 'conditional'
        for _, job, _, step in uploads
    )
    edges = []
    enabled = list(active_steps(consumer))
    for jid, job, d_idx, download in downloads:
        source = v4.run_origin(download)
        identity, selected = v4.identity(names, download)
        dirs = v4.extract_dirs(download, selected)
        for next_jid, _, e_idx, step in enabled:
            if next_jid != jid or e_idx <= d_idx:
                continue
            command = step.get('run')
            if not isinstance(command, str):
                continue
            cwd = normalized_workdir(consumer, job, step)
            resolved = paths_with_cwd(command, cwd)
            if resolved == []:
                continue
            overlap = None if dirs is None or resolved is None else any(
                folder == '.' or target == folder or target.startswith(folder + '/')
                for folder in dirs for target in resolved
            )
            candidate = source == 'triggering_run' and identity == 'matched' and overlap is True
            conditions = 'conditional' if producer_conditional or any(
                gate(x) == 'conditional' for x in (job.get('if'), download.get('if'), step.get('if'))
            ) else 'enabled'
            edges.append({
                'job': jid, 'download_step': d_idx, 'execution_step': e_idx,
                'run_origin': source, 'artifact_identity': identity,
                'download_dirs': dirs, 'working_directory': cwd,
                'execution_paths': resolved, 'path_overlap': overlap,
                'conditions': conditions, 'candidate': candidate,
                'permissions': v4.granted_access(consumer, job)
            })
    return {
        'id': 'CTA001', 'producer': producer_file, 'consumer': consumer_file,
        'producer_name': str(producer.get('name') or Path(producer_file).stem),
        'severity': 'review_required' if any(e['candidate'] for e in edges) else 'informational',
        'evidence': {
            'upload_steps': len(uploads), 'download_steps': len(downloads),
            'candidate_edges': [e for e in edges if e['candidate']],
            'examined_edges': edges
        },
        'limitations': ('Static candidate only; dynamic conditions, artifact contents, '
                        'runtime privileges and attacker control unproven.')
    }

def scan(folder):
    paths = sorted(set(Path(folder).glob('*.yml')) | set(Path(folder).glob('*.yaml')))
    workflows, errors = [], []
    for path in paths:
        try:
            obj = yaml.load(path.read_text(encoding='utf-8'), Loader=v4.ActionsLoader)
            if not isinstance(obj, dict):
                raise ValueError('Workflow must be a mapping')
            workflows.append((path.name, obj))
        except (yaml.YAMLError, UnicodeError, ValueError) as error:
            errors.append({'file': path.name, 'error': str(error)})
    findings = []
    for src_file, producer in workflows:
        if not v4.event_names(producer).intersection({'pull_request', 'pull_request_target'}):
            continue
        name = str(producer.get('name') or Path(src_file).stem)
        for dst_file, consumer in workflows:
            if name not in v4.consumer_names(consumer):
                continue
            finding = analyze(src_file, producer, dst_file, consumer)
            if finding is not None:
                findings.append(finding)
    return {'schema_version': 5, 'workflow_count': len(workflows),
            'findings': findings, 'parse_errors': errors}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('workflow_dir', nargs='?', default='.github/workflows')
    parser.add_argument('--fail-on-review', action='store_true')
    args = parser.parse_args()
    report = scan(args.workflow_dir)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report['parse_errors']:
        return 2
    return int(args.fail_on_review and any(x['severity'] == 'review_required' for x in report['findings']))

if __name__ == '__main__':
    raise SystemExit(main())
