"""V5 adversarial regression fixtures; inert YAML only, no exploit payloads."""
import pytest
import yaml
from ci_trace.scanner_v5 import scan, gate, paths_with_cwd

RUN = '${{ github.event.workflow_run.id }}'
TOKEN = '${{ secrets.GITHUB_TOKEN }}'

def fixture(tmp_path, producer_adjust=None, consumer_adjust=None):
    producer = {'name':'PR Build','on':['pull_request'],'jobs':{'build':{
        'runs-on':'ubuntu-latest','steps':[{'uses':'actions/upload-artifact@v4',
        'with':{'name':'bundle','path':'dist/'}}]}}}
    consumer = {'name':'Release','on':{'workflow_run':{'workflows':['PR Build'],'types':['completed']}},
        'jobs':{'release':{'runs-on':'ubuntu-latest','steps':[
        {'uses':'actions/download-artifact@v4','with':{
            'name':'bundle','path':'dist','run-id':RUN,'github-token':TOKEN}},
        {'run':'bash ./dist/release.sh'}]}}}
    if producer_adjust: producer_adjust(producer)
    if consumer_adjust: consumer_adjust(consumer)
    (tmp_path/'pr.yml').write_text(yaml.safe_dump(producer),encoding='utf-8')
    (tmp_path/'release.yml').write_text(yaml.safe_dump(consumer),encoding='utf-8')
    return scan(tmp_path)

def verdict(tmp_path, **kw):
    report=fixture(tmp_path,**kw)
    return report['findings'][0]['severity'] if report['findings'] else 'no_finding'

def toggle_job(p): p['jobs']['build']['if']='false'
def toggle_upload(p): p['jobs']['build']['steps'][0]['if']='${{ false }}'
def missing_path(p): del p['jobs']['build']['steps'][0]['with']['path']
def no_uploaded_path(p): p['jobs']['build']['steps'][0]['with']['path']=''
def disable_download(c): c['jobs']['release']['steps'][0]['if']='false'
def disable_exec(c): c['jobs']['release']['steps'][1]['if']='false'
def disable_job(c): c['jobs']['release']['if']='${{false}}'
def cwd_different(c): c['jobs']['release']['defaults']={'run':{'working-directory':'scripts'}}
def cwd_dynamic(c): c['jobs']['release']['defaults']={'run':{'working-directory':'${{ env.WORKDIR }}'}}
def cwd_step(c): c['jobs']['release']['steps'][1]['working-directory']='scripts'
def cwd_step_override(c):
    cwd_different(c)
    c['jobs']['release']['steps'][1]['working-directory']='.'
def chdir_before(c): c['jobs']['release']['steps'][1]['run']='cd scripts && bash ./dist/release.sh'
def heredoc(c): c['jobs']['release']['steps'][1]['run']='cat <<EOF\nbash ./dist/release.sh\nEOF'
def source_current(c): del c['jobs']['release']['steps'][0]['with']['run-id']
def separate_job(c):
    c['jobs']['release']['steps'].pop()
    c['jobs']['other']={'runs-on':'ubuntu-latest','steps':[{'run':'bash ./dist/release.sh'}]}
def condition_unknown(c): c['jobs']['release']['steps'][1]['if']='github.event.workflow_run.conclusion == "success"'
def condition_unknown_prod(p): p['jobs']['build']['steps'][0]['if']='github.event.pull_request.number > 0'
def wf_default_cwd(c): c['defaults']={'run':{'working-directory':'scripts'}}
def default_changed_back(c):
    wf_default_cwd(c)
    c['jobs']['release']['defaults']={'run':{'working-directory':'.'}}

@pytest.mark.parametrize('adjust',[toggle_job,toggle_upload,missing_path,no_uploaded_path])
def test_no_valid_producer(tmp_path,adjust):
    assert verdict(tmp_path,producer_adjust=adjust)=='no_finding'

@pytest.mark.parametrize('adjust',[disable_download,disable_exec,disable_job])
def test_provably_unreachable_consumer(tmp_path,adjust):
    assert verdict(tmp_path,consumer_adjust=adjust) in ('no_finding','informational')

@pytest.mark.parametrize('adjust',[cwd_different,cwd_dynamic,cwd_step,chdir_before,heredoc,wf_default_cwd])
def test_working_directory_and_chdir(tmp_path,adjust):
    assert verdict(tmp_path,consumer_adjust=adjust)=='informational'

@pytest.mark.parametrize('adjust',[cwd_step_override,default_changed_back,condition_unknown])
def test_valid_override_or_conditional(tmp_path,adjust):
    assert verdict(tmp_path,consumer_adjust=adjust)=='review_required'

def test_dynamic_conditions_flagged_as_unknown(tmp_path):
    report=fixture(tmp_path,consumer_adjust=condition_unknown)
    assert report['findings'][0]['evidence']['candidate_edges'][0]['conditions']=='conditional'

def test_producer_conditional_recorded(tmp_path):
    report=fixture(tmp_path,producer_adjust=condition_unknown_prod)
    assert report['findings'][0]['severity']=='review_required'
    assert report['findings'][0]['evidence']['candidate_edges'][0]['conditions']=='conditional'

@pytest.mark.parametrize('adjust',[source_current,separate_job])
def test_source_and_job_boundaries(tmp_path,adjust):
    assert verdict(tmp_path,consumer_adjust=adjust)=='informational'

def test_gate_values():
    assert gate('false')=='disabled' and gate('${{false}}')=='disabled'
    assert gate('github.ref == "main"')=='conditional'
    assert gate(True)=='enabled'

def test_cwd_resolver():
    assert paths_with_cwd('bash ./dist/release.sh','scripts')==['scripts/dist/release.sh']
    assert paths_with_cwd('cd temp && bash ./dist/release.sh','.') is None

def test_parse_errors(tmp_path):
    (tmp_path/'bad.yml').write_text('on: [invalid',encoding='utf-8')
    assert scan(tmp_path)['parse_errors']
