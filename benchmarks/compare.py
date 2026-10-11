"""Controlled structural regression benchmark, not a real-world exploit dataset.

Each label answers ONLY: should a cross-run artifact-to-direct-execution
candidate be reported under the scanner's explicitly limited static semantics?
"""
import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml
from ci_trace.scanner import scan as legacy_scan
from ci_trace.scanner_v4 import scan as v4_scan

UPSTREAM = '${{ github.event.workflow_run.id }}'
TOKEN = '${{ secrets.GITHUB_TOKEN }}'

CASES = [
    ('triggering_run_named', True, {}),
    ('current_run_default', False, {'run_id': None}),
    ('wrong_run_id', False, {'run_id': '123'}),
    ('missing_cross_run_token', False, {'token': None}),
    ('different_artifact_name', False, {'name': 'other'}),
    ('unknown_dynamic_name', False, {'name': '${{ env.NAME }}'}),
    ('different_extraction_folder', False, {'folder': 'staging'}),
    ('path_prefix_not_substring', False, {'folder': 'di'}),
    ('execution_only_echoed', False, {'command': 'echo bash ./dist/release.sh'}),
    ('permissions_not_execution', False, {'command': 'chmod +x ./dist/release.sh'}),
    ('dynamic_extract_path', False, {'folder': '${{ env.DIR }}'}),
    ('direct_shell_execution', True, {'command': 'sh ./dist/release.sh'}),
    ('download_all_separate_dirs', False, {'name': None}),
    ('download_all_nested_execution', True, {'name': None, 'command': 'bash ./dist/bundle/release.sh'}),
    ('download_all_merge', True, {'name': None, 'merge': True}),
    ('pattern_restricts_name', False, {'name': None, 'pattern': 'other-*'}),
    ('pattern_matching', True, {'name': None, 'pattern': 'bund*',
                                'command': 'bash ./dist/bundle/release.sh'}),
    ('executed_before_download', False, {'reverse': True}),
    ('separate_execution_job', False, {'separate_job': True}),
    ('pr_target_source', True, {'trigger': 'pull_request_target'}),
]

def sample(opts):
    p = {'name': 'PR Build', 'on': [opts.get('trigger', 'pull_request')], 'jobs': {
         'build': {'runs-on': 'ubuntu-latest',
                   'steps': [{'uses': 'actions/upload-artifact@v4',
                              'with': {'name': 'bundle', 'path': 'out/'}}]}}}
    x = {'path': opts.get('folder', 'dist')}
    name = opts.get('name', 'bundle')
    if name is not None:
        x['name'] = name
    if opts.get('run_id', UPSTREAM) is not None:
        x['run-id'] = opts.get('run_id', UPSTREAM)
    if opts.get('token', TOKEN) is not None:
        x['github-token'] = opts.get('token', TOKEN)
    if opts.get('merge'):
        x['merge-multiple'] = True
    if opts.get('pattern') is not None:
        x['pattern'] = opts['pattern']
    steps = [{'uses': 'actions/download-artifact@v4', 'with': x},
             {'run': opts.get('command', 'bash ./dist/release.sh')}]
    if opts.get('reverse'):
        steps.reverse()
    jobs = {'release': {'runs-on': 'ubuntu-latest', 'steps': steps}}
    if opts.get('separate_job'):
        jobs['release']['steps'] = steps[:1]
        jobs['other'] = {'runs-on': 'ubuntu-latest', 'steps': steps[1:]}
    c = {'name': 'Release', 'on': {'workflow_run': {'workflows': ['PR Build'],
         'types': ['completed']}}, 'jobs': jobs}
    return p, c

def evaluate():
    rows = []
    with TemporaryDirectory(prefix='ci-trace-benchmark-') as tmp:
        root = Path(tmp)
        for label, expected, opts in CASES:
            producer, consumer = sample(opts)
            (root / 'producer.yml').write_text(yaml.safe_dump(producer), encoding='utf-8')
            (root / 'consumer.yml').write_text(yaml.safe_dump(consumer), encoding='utf-8')
            before = legacy_scan(root)
            after = v4_scan(root)
            old = any(f['severity'] == 'review_required' for f in before['findings'])
            new = any(f['severity'] == 'review_required' for f in after['findings'])
            rows.append({'case': label, 'expected_structural_candidate': expected,
                         'legacy_alert': old, 'v4_alert': new})
    return rows

def main():
    cli = argparse.ArgumentParser()
    cli.add_argument('--assert-results', action='store_true')
    args = cli.parse_args()
    rows = evaluate()
    correct = sum(r['expected_structural_candidate'] == r['v4_alert'] for r in rows)
    legacy = sum(r['expected_structural_candidate'] == r['legacy_alert'] for r in rows)
    summary = {'dataset': 'synthetic, author-labeled, structural candidates only',
               'total': len(rows), 'legacy_matches': legacy, 'v4_matches': correct,
               'cases': rows}
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if args.assert_results and correct != len(rows):
        return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
