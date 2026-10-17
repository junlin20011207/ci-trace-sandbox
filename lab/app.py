"""Local-only demonstration HTTP console, never a production authorization service."""
from __future__ import annotations
import json, threading,time
from pathlib import Path
from fastapi import FastAPI,HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from demo_engine import SCENARIOS,run_scenario

app=FastAPI(title='CI-TRACE LAB',description='Ephemeral local Git release laboratory; never connect real credentials')
_history=[];_lock=threading.Lock()
ROOT=Path(__file__).resolve().parent

class RunRequest(BaseModel):
 scenario:str

@app.get('/')
def page():return FileResponse(ROOT/'ui'/'index.html')

@app.get('/api/status')
def status():return {'name':'CI-TRACE','edition':'R22 - LAB-ONLY', 'real_gitee_write_enabled':False,
 'independent_approval_institution':False,'scenarios':SCENARIOS,'running_since':'on-demand'}

@app.post('/api/run')
def run(body:RunRequest):
 if body.scenario not in SCENARIOS:raise HTTPException(status_code=422,detail='scenario not on allowlist')
 result=run_scenario(body.scenario)
 with _lock:
  _history.insert(0,result)
  del _history[100:]
 return result

@app.get('/api/history')
def history():
 with _lock:return {'runs':list(_history)}

if __name__=='__main__':
 import uvicorn
 uvicorn.run(app,host='127.0.0.1',port=8765,log_level='warning')
