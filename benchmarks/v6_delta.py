"""Adversarial synthetic label agreement; no exploit/real-world accuracy claims."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import yaml
from ci_trace.scanner_v5 import scan as v5_scan
from ci_trace.scanner_v6 import scan as v6_scan

RUN = '${{ github.event.workflow_run.id }}'
TOKEN = '${{ secrets.GITHUB_TOKEN }}'
CASES = [
    ('baseline', 'review_required'),
    ('mutually_exclusive_equality', 'informational'),
    ('equality_versus_inequality', 'informational'),
    ('matching_conditions', 'review_required'),
    ('unparsed_or_conditions', 'review_required'),
    ('dynamic_download_path', 'needs_resolution'),
    ('dynamic_name', 'needs_resolution'),
    ('unknown_run_id', 'needs_resolution'),
    ('opaque_multiline_quotes', 'needs_resolution'),
    ('opaque_command_substitution', 'needs_resolution'),
    ('disjoint_literal_path', 'informational'),
    ('known_current_run', 'informational'),
]


def workflows(label):
    producer = {'name': 'Build', 'on': ['pull_request'], 'jobs': {'build': {
        'runs-on': 'ubuntu-latest', 'steps': [
            {'uses': 'actions/upload-artifact@v4', 'with': {'name': 'bundle', 'path': 'dist/'}}]}}}
    down = {'uses': 'actions/download-artifact@v4', 'with': {
        'name': 'bundle', 'path': 'dist', 'run-id': RUN, 'github-token': TOKEN}}
    exe = {'run': 'bash ./dist/release.sh'}
    if label == 'mutually_exclusive_equality':
        down['if'] = "github.event.workflow_run.conclusion == 'success'"
        exe['if'] = "github.event.workflow_run.conclusion == 'failure'"
    if label == 'equality_versus_inequality':
        down['if'] = "github.event.workflow_run.conclusion == 'success'"
        exe['if'] = "github.event.workflow_run.conclusion != 'success'"
    if label == 'matching_conditions':
        down['if'] = "github.event.workflow_run.conclusion == 'success'"
        exe['if'] = "github.event.workflow_run.conclusion != 'failure'"
    if label == 'unparsed_or_conditions':
        down['if'] = "github.event.workflow_run.conclusion == 'success' || always()"
        exe['if'] = "github.event.workflow_run.conclusion == 'failure'"
    if label == 'dynamic_download_path':
        down['with']['path'] = '${{ env.OUTPUT_DIR }}'
    if label == 'dynamic_name':
        down['with']['name'] = '${{ env.ARTIFACT }}'
    if label == 'unknown_run_id':
        down['with']['run-id'] = '${{ env.RUN_ID }}'
    if label == 'opaque_multiline_quotes':
        exe['run'] = 'echo "start\nbash ./dist/release.sh\nend"'
    if label == 'opaque_command_substitution':
        exe['run'] = 'bash $(printf ./dist/release.sh)'
    if label == 'disjoint_literal_path':
        down['with']['path'] = 'other'
    if label == 'known_current_run':
        del down['with']['run-id']
    consumer = {'name': 'Release', 'on': {'workflow_run': {'workflows': ['Build'],
        'types': ['completed']}}, 'jobs': {'release': {
        'runs-on': 'ubuntu-latest', 'steps': [down, exe]}}}
    return producer, consumer


def evaluate():
    result = []
    with TemporaryDirectory(prefix='ci-trace-v6-') as tmp:
        folder = Path(tmp)
        for label, expected in CASES:
            producer, consumer = workflows(label)
            (folder / 'producer.yml').write_text(yaml.safe_dump(producer), encoding='utf-8')
            (folder / 'consumer.yml').write_text(yaml.safe_dump(consumer), encoding='utf-8')
            old = v5_scan(folder)['findings'][0]['severity']
            new = v6_scan(folder)['findings'][0]['severity']
            result.append({'case': label, 'expected': expected, 'v5': old, 'v6': new})
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--assert-results', action='store_true')
    args = parser.parse_args()
    rows = evaluate()
    matches = sum(x['expected'] == x['v6'] for x in rows)
    previous = sum(x['expected'] == x['v5'] for x in rows)
    print(json.dumps({'data_kind': 'author-designed synthetic structural labels',
                      'total': len(rows), 'v5_matches': previous,
                      'v6_matches': matches, 'cases': rows}, indent=2))
    return int(args.assert_results and matches != len(rows))


if __name__ == '__main__':
    raise SystemExit(main())
