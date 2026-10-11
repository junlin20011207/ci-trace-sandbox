"""CI-TRACE V6: bounded logical falsification and explicit uncertainty.

Never executes workflow commands. The word 'candidate' is a static triage
classification, NOT a claim of attacker control or exploitability.
"""
import argparse
import json
import re
from pathlib import Path
import yaml
from . import scanner_v5 as v5

# Deliberately narrow subset of GitHub expression syntax. Never attempt to
# evaluate arbitrary expressions or use eval().
ATOM = re.compile(
    r"^github\.event\.workflow_run\.conclusion\s*(==|!=)\s*(['\"])(success|failure|cancelled|skipped|timed_out|action_required|neutral)\2$",
    re.IGNORECASE,
)


def literal_constraints(value):
    """Return simple (operator, outcome) clauses, or None for unknown syntax."""
    if value is None or value is True or str(value).strip().lower() in (
        'true', '${{ true }}', '${{true}}', 'success()'
    ):
        return []
    text = str(value).strip()
    if text.startswith('${{') and text.endswith('}}'):
        text = text[3:-2].strip()
    # Never reason from OR or more complicated expressions.
    if '||' in text or '!' in text and '!=' not in text:
        return None
    clauses = []
    for piece in text.split('&&'):
        m = ATOM.fullmatch(piece.strip())
        if not m:
            return None
        clauses.append((m.group(1), m.group(3).lower()))
    return clauses


def incompatible_conditions(*values):
    """Return True only when explicitly recognized conjunction is unsatisfiable."""
    clauses = []
    for value in values:
        result = literal_constraints(value)
        if result is None:
            return False
        clauses.extend(result)
    required = {value for op, value in clauses if op == '=='}
    excluded = {value for op, value in clauses if op == '!='}
    # The conclusion has one value in one workflow run.
    return len(required) > 1 or bool(required & excluded)


def shell_ambiguity(script, step):
    """Do not assert a direct-execution path inside opaque Shell constructs."""
    if not isinstance(script, str):
        return False
    shell = str(step.get('shell', 'bash')).strip().lower()
    if shell not in ('bash', 'sh', ''):
        return True
    if '`' in script or '$(' in script or '\\\n' in script:
        return True
    # A quoted string spans a line boundary; regex line matching is unreliable.
    for quote in ("'", '"'):
        active = False
        for line in script.splitlines():
            for i, c in enumerate(line):
                if c == quote and (i == 0 or line[i - 1] != '\\'):
                    active = not active
            if active:
                return True
    return False


def annotate(working_dir, report):
    """Revisit V5 edges and distinguish contradicted vs unknown evidence."""
    folder = Path(working_dir)
    cache = {}
    for finding in report['findings']:
        consumer_file = finding['consumer']
        if consumer_file not in cache:
            cache[consumer_file] = yaml.load(
                (folder / consumer_file).read_text(encoding='utf-8'),
                Loader=v5.v4.ActionsLoader,
            )
        workflow = cache[consumer_file]
        # V5 suppresses edges when regex extraction finds no literal path.
        # Preserve plausible indirect interpreter invocations as unresolved.
        examined = finding['evidence']['examined_edges']
        steps = list(v5.active_steps(workflow))
        for jid, job, down_idx, down in steps:
            if not (str(down.get('uses', '')).startswith('actions/download-artifact@')
                    and v5.v4.run_origin(down) == 'triggering_run'):
                continue
            for ejid, _, exec_idx, execution in steps:
                if ejid != jid or exec_idx <= down_idx:
                    continue
                script = execution.get('run', '')
                if not isinstance(script, str) or not re.search(
                    r'(?:^|[;&|\n])\s*(?:bash|sh|python3?|node|source)\s+\$[({A-Za-z_]',
                    script, flags=re.I,
                ):
                    continue
                if any(e['job'] == jid and e['download_step'] == down_idx
                       and e['execution_step'] == exec_idx for e in examined):
                    continue
                examined.append({
                    'job': jid, 'download_step': down_idx, 'execution_step': exec_idx,
                    'run_origin': 'triggering_run', 'artifact_identity': 'unknown',
                    'download_dirs': None, 'working_directory': None,
                    'execution_paths': None, 'path_overlap': None,
                    'conditions': 'conditional', 'candidate': False,
                    'permissions': v5.v4.granted_access(workflow, job),
                    'v6_indirect_target': True,
                })
        for edge in finding['evidence']['examined_edges']:
            job = workflow['jobs'][edge['job']]
            down = job['steps'][edge['download_step']]
            execution = job['steps'][edge['execution_step']]
            contradiction = incompatible_conditions(job.get('if'), down.get('if'), execution.get('if'))
            ambiguity = shell_ambiguity(execution.get('run'), execution)
            if edge.get('v6_indirect_target'):
                status, reason = 'unresolved', 'indirect_execution_target'
            elif contradiction:
                status, reason = 'excluded', 'incompatible_step_conditions'
            elif edge['candidate'] and ambiguity:
                status, reason = 'unresolved', 'opaque_shell_syntax'
            elif edge['candidate']:
                status, reason = 'candidate', 'bounded_static_path_overlap'
            elif edge['run_origin'] not in ('triggering_run', 'current_run'):
                status, reason = 'unresolved', 'unverified_run_origin'
            elif edge['artifact_identity'] == 'unknown':
                status, reason = 'unresolved', 'unknown_artifact_identity'
            elif edge['path_overlap'] is None:
                status, reason = 'unresolved', 'unknown_execution_or_extraction_path'
            else:
                status, reason = 'excluded', 'known_structural_disjunction'
            edge['v6_status'] = status
            edge['v6_reason'] = reason
            edge['conditional'] = edge['conditions'] == 'conditional'
            edge['candidate'] = status == 'candidate'
        all_edges = finding['evidence']['examined_edges']
        finding['evidence']['candidate_edges'] = [e for e in all_edges if e['v6_status'] == 'candidate']
        finding['evidence']['unresolved_edges'] = [e for e in all_edges if e['v6_status'] == 'unresolved']
        finding['evidence']['excluded_edges'] = [e for e in all_edges if e['v6_status'] == 'excluded']
        finding['severity'] = ('review_required' if finding['evidence']['candidate_edges']
                               else 'needs_resolution' if finding['evidence']['unresolved_edges']
                               else 'informational')
        finding['limitations'] = (
            'V6 static candidate only. Conditions are partially modeled. '
            'No artifact byte provenance, runtime control, effective privileges, '
            'or exploitability established.'
        )
    report['schema_version'] = 6
    report['semantics'] = 'candidate / unresolved / excluded; not vulnerability proof'
    return report


def scan(folder):
    return annotate(folder, v5.scan(folder))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('workflow_dir', nargs='?', default='.github/workflows')
    parser.add_argument('--fail-on-review', action='store_true')
    args = parser.parse_args()
    report = scan(args.workflow_dir)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if report['parse_errors']:
        return 2
    return int(args.fail_on_review and any(f['severity'] == 'review_required' for f in report['findings']))


if __name__ == '__main__':
    raise SystemExit(main())
