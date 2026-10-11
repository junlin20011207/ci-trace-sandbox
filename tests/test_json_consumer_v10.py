"""V10 no-persistent-path data consumer: controlled signed JSON tests."""
import base64
import hashlib
import json
import zipfile
from datetime import datetime,timedelta,timezone
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ci_trace.signed_authorization import payload_bytes
from ci_trace.json_consumer_v10 import consume_signed_json,parse_scalar_json
from ci_trace.provenance_guard import Denied

NOW=datetime(2026,10,11,tzinfo=timezone.utc)

def setup(tmp_path,data=b'{"pr_number":17}'):
    ws=tmp_path/'ws';ws.mkdir()
    out=tmp_path/'out';out.mkdir()
    archive=tmp_path/'input.zip'
    with zipfile.ZipFile(archive,'w') as z:z.writestr('data.json',data)
    sha='a'*40
    event={'repository':{'full_name':'test/demo'},'workflow_run':{
        'id':4,'event':'pull_request','conclusion':'success','head_sha':sha,
        'head_repository':{'full_name':'test/demo'}}}
    api={'id':8,'name':'data','expired':False,
         'digest':'sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest(),
         'workflow_run':{'id':4,'head_sha':sha}}
    policy={'expected_run_id':4,'repository':'test/demo','artifact_name':'data',
            'allowed_events':['pull_request'],'require_same_repo':True,
            'allow_extensions':['.json']}
    record={'repository':'test/demo','run_id':4,'artifact_name':'data','commit_sha':sha,
            'purpose':'artifact_release',
            'issued_at':(NOW-timedelta(minutes=1)).isoformat(),
            'expires_at':(NOW+timedelta(minutes=1)).isoformat()}
    sk=Ed25519PrivateKey.generate()
    keys={'key':sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex()}
    package={'key_id':'key','record':record,
             'signature':base64.b64encode(sk.sign(payload_bytes(record))).decode()}
    return archive,event,api,policy,package,keys,out,ws

def consume(tmp_path,data):
    return consume_signed_json(*setup(tmp_path,data),'data.json',
                               {'pr_number':'integer'},now=NOW)

def test_valid_data_consumed_and_no_path_exposed(tmp_path):
    result=consume(tmp_path,b'{"pr_number":17}')
    assert result['status']=='approved' and result['data']=={'pr_number':17}
    assert result['source_commit_from_signed_approval']=='a'*40
    assert result['safe_to_execute_or_publish'] is False
    assert not list((tmp_path/'out').iterdir())

@pytest.mark.parametrize('data,reason',[
 (b'{"pr_number":17,"pr_number":999}', 'duplicate_json_key'),
 (b'{"pr_number":"17"}','json_scalar_type_mismatch'),
 (b'{"pr_number":17,"head_ref":"main"}','json_schema_mismatch'),
 (b'{"pr_number":NaN}','nonfinite_json_constant'),
 (b'{"pr_number":false}','json_scalar_type_mismatch'),
 (b'not-json','invalid_json_payload'),
])
def test_malformed_data_denied_without_releasing_files(tmp_path,data,reason):
    with pytest.raises(Denied,match=reason):
        consume(tmp_path,data)
    assert not list((tmp_path/'out').iterdir())

def test_sensitive_ref_fields_not_schema_authorized():
    with pytest.raises(Denied,match='invalid_scalar_schema'):
        parse_scalar_json(b'{"branch":"main"}',{'branch':'string'})
