"""V16 evaluation invariants: no leakage from unlabeled repos into security negatives."""
import gzip
import json
from pathlib import Path
from benchmarks.v16_ghalogs import sample_rows
from benchmarks.v16_histories import candidates,extract_csv
from benchmarks.v16_public_eval import evaluate

def test_ghalogs_draws_only_selected_workflow_repositories(tmp_path):
    sha='a'*40
    def entry(name,selected,workflows=1):
        return {'_id':name,'selected':selected,'nb_workflows':workflows,
            'repo':{'lastCommitSHA':sha}}
    rows=[entry('alpha/one',True),entry('alpha/one',True),
          entry('beta/unselected',False),entry('gamma/empty',True,0),
          entry('delta/two',True)]
    src=tmp_path/'repositories.json.gz'
    with gzip.open(src,'wt') as f:
        for r in rows:f.write(json.dumps(r)+'\n')
    sampled,n=sample_rows(src)
    assert n==2
    assert {s['repo'] for s in sampled}=={'alpha/one','delta/two'}

def test_histories_reproducible_unique_repository_sampling():
    data='name,branch,stars\nfoo/one,main,50\nfoo/one,main,20\nbar/two,master,12\n'
    a,n,cols=candidates(extract_csv(data.encode()))
    b,m,_=candidates(extract_csv(data.encode()))
    assert a==b and n==m==2 and len(a)==2
    assert all(x['class']=='unlabeled_2026_workflow_histories' for x in a)

def test_manifest_has_no_assumed_negative_labels():
    manifest=json.loads(Path('research_corpus/v16_external_manifest.json').read_text())
    assert all(x['class']!='safe' for x in manifest['sources'])
    assert all(x.get('advisory') or x['class']=='unlabeled' for x in manifest['sources'])
