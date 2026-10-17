import json,tempfile,sys
from pathlib import Path
from fastapi.testclient import TestClient
from app import app
from demo_engine import run_scenario,SCENARIOS
from experiments.paired_baselines import experiment
from formal.exhaustive import check

def test_all_real_git_scenarios():
 for name in SCENARIOS:
  x=run_scenario(name)
  assert x['passed'],(name,x)
  assert x['environment']=='LOCAL_LAB_ONLY_NO_GITEE_WRITE'

def test_console_api():
 client=TestClient(app)
 assert client.get('/').status_code==200
 assert len(client.get('/api/status').json()['scenarios'])==9
 assert client.post('/api/run',json={'scenario':'legitimate'}).json()['passed']
 assert len(client.get('/api/history').json()['runs'])>=1
 assert client.post('/api/run',json={'scenario':'../shell'}).status_code==422
 assert client.post('/api/run',json={'scenario':'../../../../etc/passwd'}).status_code==422

def test_local_strong_baselines_actual_git_race():
 x=experiment()
 assert x['git_collision_actual']['normal_push']['unauthorized_branch_changed']
 assert not x['git_collision_actual']['create_only_lease']['unauthorized_branch_changed']
 assert x['tallies']['B']['unapproved_side_effect_cases']==1
 assert x['tallies']['C']['unapproved_side_effect_cases']==0

def test_explicit_state_space_and_counterexample():
 safe=check(False);bad=check(True)
 assert safe['invariants_hold'] and safe['states_seen']>=30
 assert bad['violation'].startswith('TOCTOU')
 assert bad['counterexample']==['online_reserve','client_checks_absence','other_actor_creates_ref','ordinary_git_push']
