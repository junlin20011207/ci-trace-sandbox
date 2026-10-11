"""Author-designed structural falsification corpus, NOT real-world vulnerabilities."""
import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import yaml
from ci_trace.scanner_v4 import scan as v4_scan
from ci_trace.scanner_v5 import scan as v5_scan

RUN='${{ github.event.workflow_run.id }}'
TOKEN='${{ secrets.GITHUB_TOKEN }}'

CASES = [
 ('baseline',1),('disabled_producer_job',0),('disabled_upload',0),
 ('no_upload_path',0),('empty_upload_path',0),('disabled_consumer_job',0),
 ('disabled_download',0),('disabled_execution',0),('workflow_cwd_mismatch',0),
 ('job_cwd_mismatch',0),('step_cwd_mismatch',0),('dynamic_cwd',0),
 ('chdir_before',0),('heredoc',0),('job_override_step_cwd',1),
 ('workflow_override_job_cwd',1),('conditional_execute',1),
 ('conditional_upload',1),('current_run',0),('wrong_artifact',0),
 ('wrong_path',0),('other_job',0)
]

def sample(key):
    producer={'name':'PR Build','on':['pull_request'],'jobs':{'build':{
        'runs-on':'ubuntu-latest','steps':[{'uses':'actions/upload-artifact@v4',
          'with':{'name':'bundle','path':'output/'}}]}}}
    consumer={'name':'Release','on':{'workflow_run':{'workflows':['PR Build'],'types':['completed']}},
        'jobs':{'release':{'runs-on':'ubuntu-latest','steps':[
          {'uses':'actions/download-artifact@v4','with':{
             'name':'bundle','path':'dist','run-id':RUN,'github-token':TOKEN}},
          {'run':'bash ./dist/release.sh'}]}}}
    pj=producer['jobs']['build']; cj=consumer['jobs']['release']
    up=pj['steps'][0]; down=cj['steps'][0]; exe=cj['steps'][1]
    if key=='disabled_producer_job': pj['if']='false'
    elif key=='disabled_upload': up['if']='${{ false }}'
    elif key=='no_upload_path': del up['with']['path']
    elif key=='empty_upload_path': up['with']['path']=''
    elif key=='disabled_consumer_job': cj['if']='${{false}}'
    elif key=='disabled_download': down['if']='false'
    elif key=='disabled_execution': exe['if']='${{ false }}'
    elif key=='workflow_cwd_mismatch': consumer['defaults']={'run':{'working-directory':'scripts'}}
    elif key=='job_cwd_mismatch': cj['defaults']={'run':{'working-directory':'scripts'}}
    elif key=='step_cwd_mismatch': exe['working-directory']='scripts'
    elif key=='dynamic_cwd': exe['working-directory']='${{ env.WORKDIR }}'
    elif key=='chdir_before': exe['run']='cd scripts && bash ./dist/release.sh'
    elif key=='heredoc': exe['run']='cat <<EOF\nbash ./dist/release.sh\nEOF'
    elif key=='job_override_step_cwd':
        cj['defaults']={'run':{'working-directory':'scripts'}}
        exe['working-directory']='.'
    elif key=='workflow_override_job_cwd':
        consumer['defaults']={'run':{'working-directory':'scripts'}}
        cj['defaults']={'run':{'working-directory':'.'}}
    elif key=='conditional_execute': exe['if']='github.ref == "refs/heads/main"'
    elif key=='conditional_upload': up['if']='github.event.pull_request.number > 0'
    elif key=='current_run': del down['with']['run-id']
    elif key=='wrong_artifact': down['with']['name']='other'
    elif key=='wrong_path': down['with']['path']='other'
    elif key=='other_job':
        cj['steps'].pop()
        consumer['jobs']['another']={'runs-on':'ubuntu-latest','steps':[exe]}
    return producer,consumer

def evaluate():
    rows=[]
    with TemporaryDirectory(prefix='ci-trace-v5-') as temp:
        root=Path(temp)
        for case,expected in CASES:
            src,dst=sample(case)
            (root/'p.yml').write_text(yaml.safe_dump(src),encoding='utf-8')
            (root/'c.yml').write_text(yaml.safe_dump(dst),encoding='utf-8')
            before=any(x['severity']=='review_required' for x in v4_scan(root)['findings'])
            after=any(x['severity']=='review_required' for x in v5_scan(root)['findings'])
            rows.append({'case':case,'expected':bool(expected),'v4':before,'v5':after})
    return rows

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--assert-results',action='store_true')
    args=parser.parse_args()
    rows=evaluate()
    matches=sum(r['v5']==r['expected'] for r in rows)
    earlier=sum(r['v4']==r['expected'] for r in rows)
    print(json.dumps({'dataset':'22 author-designed synthetic structural cases; NOT vulnerabilities',
                      'total':len(rows),'v4_matches':earlier,'v5_matches':matches,'cases':rows},indent=2))
    return int(args.assert_results and matches!=len(rows))

if __name__=='__main__':
    raise SystemExit(main())
