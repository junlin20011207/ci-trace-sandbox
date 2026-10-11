"""Adversarial static fixtures, not an external vulnerability benchmark."""
import pytest
import yaml
from ci_trace.scanner_v6 import scan, literal_constraints, incompatible_conditions, shell_ambiguity

RUN = '${{ github.event.workflow_run.id }}'
TOKEN = '${{ secrets.GITHUB_TOKEN }}'


def case(tmp_path, *, download_if=None, exec_if=None, job_if=None,
         command='bash ./dist/release.sh', downloader=None, folder='dist', exec_shell=None):
    producer = {'name': 'Build', 'on': ['pull_request'], 'jobs': {'build': {
        'runs-on': 'ubuntu-latest', 'steps': [
            {'uses': 'actions/upload-artifact@v4', 'with': {'name': 'bundle', 'path': 'dist/'}}
        ]}}}
    down = {'uses': 'actions/download-artifact@v4', 'with': {
        'name': 'bundle', 'path': folder, 'run-id': RUN, 'github-token': TOKEN}}
    if downloader:
        down['with'].update(downloader)
    if download_if is not None:
        down['if'] = download_if
    execution = {'run': command}
    if exec_if is not None:
        execution['if'] = exec_if
    if exec_shell is not None:
        execution['shell'] = exec_shell
    job = {'runs-on': 'ubuntu-latest', 'steps': [down, execution]}
    if job_if is not None:
        job['if'] = job_if
    consumer = {'name': 'Release', 'on': {'workflow_run': {'workflows': ['Build'],
        'types': ['completed']}}, 'jobs': {'release': job}}
    (tmp_path / 'producer.yml').write_text(yaml.safe_dump(producer), encoding='utf-8')
    (tmp_path / 'consumer.yml').write_text(yaml.safe_dump(consumer), encoding='utf-8')
    return scan(tmp_path)['findings'][0]


@pytest.mark.parametrize('down,exe', [
    ("github.event.workflow_run.conclusion == 'success'", "github.event.workflow_run.conclusion == 'failure'"),
    ("${{ github.event.workflow_run.conclusion == 'success' }}", "github.event.workflow_run.conclusion != 'success'"),
    ("github.event.workflow_run.conclusion == 'cancelled'", "github.event.workflow_run.conclusion == 'success'"),
])
def test_exclusive_guards_are_excluded(tmp_path, down, exe):
    finding = case(tmp_path, download_if=down, exec_if=exe)
    assert finding['severity'] == 'informational'
    assert finding['evidence']['excluded_edges'][0]['v6_reason'] == 'incompatible_step_conditions'


def test_matching_guards_remain_candidates(tmp_path):
    finding = case(tmp_path, download_if="github.event.workflow_run.conclusion == 'success'",
                   exec_if="github.event.workflow_run.conclusion != 'failure'")
    assert finding['severity'] == 'review_required'
    assert finding['evidence']['candidate_edges'][0]['conditional']


@pytest.mark.parametrize('guard', [
    "github.event.workflow_run.conclusion == 'success' || always()",
    "github.event.workflow_run.conclusion == 'success' && env.FLAG == 'true'",
    "contains('success,failed', github.event.workflow_run.conclusion)",
])
def test_unsupported_conditions_not_falsified(tmp_path, guard):
    f = case(tmp_path, download_if=guard, exec_if="github.event.workflow_run.conclusion == 'failure'")
    assert f['severity'] == 'review_required'


@pytest.mark.parametrize('command', [
    'echo "Message start\nbash ./dist/release.sh\nMessage end"',
    "printf 'message start\nbash ./dist/release.sh\nmessage end'",
    'bash $(printf ./dist/release.sh)',
    'bash `printf ./dist/release.sh`',
])
def test_opaque_shell_reclassified_unknown(tmp_path, command):
    f = case(tmp_path, command=command)
    assert f['severity'] == 'needs_resolution' or f['severity'] == 'informational'
    assert not f['evidence']['candidate_edges']


@pytest.mark.parametrize('options', [
    {'folder': '${{ env.DEST }}'},
    {'downloader': {'name': '${{ env.ARTIFACT }}'}},
    {'downloader': {'run-id': '${{ github.run_id }}'}},
])
def test_unknown_provenance_not_same_as_known_safe(tmp_path, options):
    f = case(tmp_path, **options)
    assert f['severity'] == 'needs_resolution'
    assert f['evidence']['unresolved_edges']


def test_literal_mismatch_can_be_excluded(tmp_path):
    f = case(tmp_path, folder='elsewhere')
    assert f['severity'] == 'informational'
    assert f['evidence']['excluded_edges']


def test_current_run_is_not_upstream(tmp_path):
    f = case(tmp_path, downloader={'run-id': '${{ github.run_id }}'})
    assert f['severity'] == 'needs_resolution'  # explicitly unknown relative to producer


def test_direct_path_still_detectable(tmp_path):
    f = case(tmp_path)
    assert f['severity'] == 'review_required'
    assert f['evidence']['candidate_edges'][0]['v6_status'] == 'candidate'


def test_parser_cannot_eval_arbitrary_expression():
    assert literal_constraints('__import__("os").system("id")') is None
    assert not incompatible_conditions('github.event.workflow_run.conclusion == "success"',
                                       'env.UNKNOWN == "failure"')


def test_unsatisfiable_conjunction():
    assert incompatible_conditions("github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.conclusion == 'failure'")


def test_shell_substitution_is_opaque():
    assert shell_ambiguity('bash $(printf ./dist/release.sh)', {})


def test_parse_failure_retained(tmp_path):
    (tmp_path / 'broken.yml').write_text('on: [', encoding='utf-8')
    assert scan(tmp_path)['parse_errors']
