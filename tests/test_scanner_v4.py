"""Provenance-aware synthetic test suite. No secrets, exploit payloads or external targets."""
import copy
import pytest
import yaml
from ci_trace.scanner_v4 import scan

UPSTREAM = '${{ github.event.workflow_run.id }}'
TOKEN = '${ secrets.GITHUB_TOKEN }}'

def pair(tmp_path, *, origin=UPSTREAM, token=TOKEN, name='bundle', producer_name='bundle',
         folder='dist', command='bash ./dist/release.sh', selected_name=True, merge=False,
         pattern=None, switches=None):
    p = {'name': 'PR Build', 'on': ['pull_request'], 'jobs': {'build': {
        'runs-on': 'ubuntu-latest',
        'steps': [{'uses': 'actions/upload-artifact@v4',
                   'with': {'name': producer_name, 'path': 'output/'}}]}}}
    with_ = {'path': folder}
    if selected_name: with_['name'] = name
    if origin is not None: with_['run-id'] = origin
    if token is not None: with_['github-token'] = token
    if merge: with_['merge-multiple'] = True
    if pattern is not None: with_['pattern'] = pattern
    c = {'name': 'Publish', 'on': {'workflow_run': {'workflows': ['PR Build'],
           'types': ['completed']}}, 'jobs': {'pub': {'runs-on': 'ubuntu-latest',
           'steps': [{'uses': 'actions/download-artifact@v4', 'with': with_},
                     {'run': command}]}}}
    if switches:
        switches(p,c)
    (tmp_path/'pr.yml').write_text(yaml.safe_dump(p), encoding='utf-8')
    (tmp_path/'publish.yml').write_text(yaml.safe_dump(c), encoding='utf-8')
    return scan(tmp_path)

def first(tmp_path, **kwargs):
    return pair(tmp_path, **kwargs)['findings'][0]

def test_real_upstream_with_executed_path(tmp_path):
    finding = first(tmp_path)
    assert finding['severity'] == 'review_required'
    e = finding['evidence']['candidate_edges'][0]
    assert e['run_origin'] == 'triggering_run'
    assert e['artifact_identity'] == 'matched'
    assert e['execution_paths'] == ['dist/release.sh']

@pytest.mark.parametrize('origin,token,reason', [
    (None,TOKEN,'current_run'), (None,None,'current_run'),
    ('123',TOKEN,'unknown_run'), (UPSTREAM,None,'missing_token'),
    ('${{ github.run_id }}',TOKEN,'unknown_run')])
def test_origin_gating(tmp_path, origin, token, reason):
    f = first(tmp_path, origin=origin, token=token)
    assert f['severity'] == 'informational'
    assert f['evidence']['examined_edges'][0]['run_origin'] == reason

@pytest.mark.parametrize('name', ['not-bundle','${ env.PAYLOAD }}'])
def test_artifact_name_mismatch_or_unknown(tmp_path,name):
    assert first(tmp_path, name=name)['severity'] == 'informational'

@pytest.mark.parametrize('folder', ['staging','di','../dist','${ env.OUT }}'])
def test_directory_not_proven(tmp_path, folder):
    assert first(tmp_path,folder=folder)['severity'] == 'informational'

@pytest.mark.parametrize('command', ['echo bash ./dist/release.sh',
  'chmod +x ./dist/release.sh','cat ./dist/release.sh','bash $TARGET'])
def test_false_execution_does_not_promote(tmp_path,command):
    assert first(tmp_path,command=command)['severity'] == 'informational'

@pytest.mark.parametrize('command', ['bash ./dist/release.sh','sh ./dist/release.sh',
  'source ./dist/release.sh','./dist/release.sh','python3 ./dist/release.sh',
  'bash -e ./dist/release.sh'])
def test_direct_execution_forms(tmp_path,command):
    assert first(tmp_path,command=command)['severity'] == 'review_required'

def test_all_artifacts_nested_directory(tmp_path):
    assert first(tmp_path, selected_name=False)['severity'] == 'informational'
    assert first(tmp_path, selected_name=False, command='bash ./dist/bundle/release.sh')['severity'] == 'review_required'

def test_all_artifacts_merge_dir(tmp_path):
    assert first(tmp_path, selected_name=False, merge=True)['severity'] == 'review_required'

def test_pattern_matching(tmp_path):
    assert first(tmp_path, selected_name=False, pattern='bund*',
        command='bash ./dist/bundle/release.sh')['severity'] == 'review_required'
    assert first(tmp_path, selected_name=False, pattern='wrong*')['severity'] == 'informational'

def test_older_candidate_false_positive_rejected(tmp_path):
    f = first(tmp_path, origin=None)
    assert f['evidence']['candidate_edges'] == []

def test_separate_job(tmp_path):
    def alter(p,c):
        c['jobs']['pub']['steps'].pop()
        c['jobs']['other'] = {'runs-on': 'ubuntu-latest', 'steps':[{'run':'bash ./dist/release.sh'}]}
    assert first(tmp_path, switches=alter)['severity'] == 'informational'

def test_execution_order(tmp_path):
    def alter(p,c): c['jobs']['pub']['steps'].reverse()
    assert first(tmp_path,switches=alter)['severity'] == 'informational'

def test_artifact_id_unknown(tmp_path):
    def alter(p,c): c['jobs']['pub']['steps'][0]['with']['artifact-ids']='987'
    assert first(tmp_path,switches=alter)['severity'] == 'informational'

def test_permission_context(tmp_path):
    def alter(p,c): c['jobs']['pub']['permissions']={'contents':'write'}
    f = first(tmp_path,switches=alter)
    assert f['evidence']['candidate_edges'][0]['permissions']['explicit_write_scopes']==['contents']

def test_non_pr_source_excluded(tmp_path):
    def alter(p,c): p['on']=['workflow_dispatch']
    assert pair(tmp_path,switches=alter)['findings']==[]

def test_unmatched_upstream_name_excluded(tmp_path):
    def alter(p,c): c['on']['workflow_run']['workflows']=['Other']
    assert pair(tmp_path,switches=alter)['findings']==[]

def test_parse_error(tmp_path):
    (tmp_path/'broken.yml').write_text('on: [',encoding='utf-8')
    assert scan(tmp_path)['parse_errors']

def test_empty_folder(tmp_path):
    assert scan(tmp_path)['findings'] == []
