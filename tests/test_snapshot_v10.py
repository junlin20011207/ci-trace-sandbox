"""Deterministic V9 ZIP path replacement reproducer + V10 counterfactual."""
import base64
import hashlib
import json
import os
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ci_trace.provenance_guard import verify_and_extract as v9, Denied
from ci_trace.snapshot_guard_v10 import verify_and_extract_snapshot as v10
from ci_trace.signed_authorization import (
    payload_bytes, verify_approval_package, verify_signed_release as v9signed)
from ci_trace.signed_snapshot_v10 import verify_signed_snapshot_release as v10signed

NOW = datetime(2026,10,11,12,tzinfo=timezone.utc)
SHA = 'a'*40

def fixture(tmp_path):
    ws=tmp_path/'ws';ws.mkdir(); root=tmp_path/'root';root.mkdir()
    archive=tmp_path/'source.zip';replacement=tmp_path/'replacement.zip'
    for path,value in [(archive,'VALID'),(replacement,'FORGED')]:
        with zipfile.ZipFile(path,'w') as z:
            z.writestr('report.json',json.dumps({'payload':value}))
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    event={'repository':{'full_name':'example/demo'},'workflow_run':{
           'id':10,'head_sha':SHA,'event':'pull_request','conclusion':'success',
           'head_repository':{'full_name':'example/demo'}}}
    api={'id':77,'name':'report','expired':False,
         'workflow_run':{'id':10,'head_sha':SHA},'digest':'sha256:'+digest}
    policy={'expected_run_id':10,'repository':'example/demo','artifact_name':'report',
            'allowed_events':['pull_request'],'require_same_repo':True,
            'allow_extensions':['.json']}
    record={'repository':'example/demo','run_id':10,'artifact_name':'report',
            'commit_sha':SHA,'purpose':'artifact_release',
            'issued_at':(NOW-timedelta(minutes=1)).isoformat(),
            'expires_at':(NOW+timedelta(minutes=1)).isoformat()}
    sk=Ed25519PrivateKey.generate()
    keys={'trusted':sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex()}
    package={'key_id':'trusted','record':record,
             'signature':base64.b64encode(sk.sign(payload_bytes(record))).decode()}
    assert verify_approval_package(package,keys,now=NOW)==record
    return archive,replacement,event,api,policy,root,ws,package,keys

def run_under_swap(tmp_path, version):
    a,swap,e,api,p,out,ws,package,keys=fixture(tmp_path)
    original_zip=zipfile.ZipFile
    triggers=[]
    def intercepted(arg,*args,**kw):
        if not triggers:
            os.replace(swap,a)
            triggers.append(1)
        return original_zip(arg,*args,**kw)
    with patch.object(zipfile,'ZipFile',new=intercepted):
        result=version(a,e,api,p,out,ws)
    body=json.loads((Path(result['release_dir'])/'report.json').read_text())
    return result,body['payload'],len(triggers)

def test_v9_reopens_mutated_path_after_sha_check(tmp_path):
    result,payload,n=run_under_swap(tmp_path,v9)
    assert (result['status'],payload,n)==('approved','FORGED',1)

def test_v10_uses_same_immutable_checked_bytes(tmp_path):
    result,payload,n=run_under_swap(tmp_path,v10)
    assert (result['status'],payload,n)==('approved','VALID',1)
    assert result['file_manifest'][0]['sha256']==hashlib.sha256(b'{"payload": "VALID"}').hexdigest()

def test_v10_success_no_attack(tmp_path):
    a,swap,e,api,p,out,ws,package,keys=fixture(tmp_path)
    result=v10(a,e,api,p,out,ws)
    assert result['status']=='approved'
    assert result['snapshot_type']=='immutable_bytes'

def test_v10_rejects_tamper_before_snapshot(tmp_path):
    a,swap,e,api,p,out,ws,package,keys=fixture(tmp_path)
    os.replace(swap,a)
    with pytest.raises(Denied,match='artifact_digest_mismatch'):
        v10(a,e,api,p,out,ws)
    assert not list(out.iterdir())

def test_v10_manifest_records_postrelease_mutation(tmp_path):
    a,swap,e,api,p,out,ws,package,keys=fixture(tmp_path)
    result=v10(a,e,api,p,out,ws)
    released=Path(result['release_dir'])/'report.json'
    released.write_text('{"payload":"LATE_CHANGE"}')
    actual=hashlib.sha256(released.read_bytes()).hexdigest()
    assert actual!=result['file_manifest'][0]['sha256']

def signed_race(tmp_path,version):
    a,swap,e,api,p,out,ws,package,keys=fixture(tmp_path)
    old_zip=zipfile.ZipFile
    replaced=[]
    def trigger(arg,*args,**kw):
        if not replaced:
            os.replace(swap,a)
            replaced.append(True)
        return old_zip(arg,*args,**kw)
    with patch.object(zipfile,'ZipFile',new=trigger):
        result=version(a,e,api,p,package,keys,out,ws,now=NOW)
    assert result['approval_signature']['verified']
    return json.loads((Path(result['release_dir'])/'report.json').read_text())['payload']

def test_v9_signed_approval_does_not_eliminate_zip_race(tmp_path):
    assert signed_race(tmp_path,v9signed)=='FORGED'

def test_v10_signed_snapshot_eliminates_zip_race(tmp_path):
    assert signed_race(tmp_path,v10signed)=='VALID'

@pytest.mark.parametrize('limit',[0,-1,70*1024*1024])
def test_v10_rejects_unsafe_configured_memory_limit(tmp_path,limit):
    a,swap,e,api,p,out,ws,package,keys=fixture(tmp_path)
    p['max_archive_bytes']=limit
    with pytest.raises(Denied,match='invalid_archive_limit'):
        v10(a,e,api,p,out,ws)
