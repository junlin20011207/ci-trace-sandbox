"""Authenticated-origin transport tests with a mock GitHub REST endpoint."""
import io
import json
import pytest
from ci_trace.github_api_gate import load_authenticated_metadata
from ci_trace.provenance_guard import Denied

SHA='a'*40
REPO='example/demo'
RUN={'id':123,'event':'pull_request','head_sha':SHA,'conclusion':'success',
     'head_branch':'dependabot/fix','repository':{'id':24,'full_name':REPO},
     'head_repository':{'full_name':REPO}}
ART={'id':17,'name':'bundle','digest':'sha256:'+'b'*64,'expired':False,
     'workflow_run':{'id':123,'repository_id':24,'head_sha':SHA}}

class Response(io.BytesIO):
    def __enter__(self):return self
    def __exit__(self,*a):self.close()

def data(run=RUN, artifact=ART):
    calls=[]
    def fake(req,timeout):
        url=req.full_url
        calls.append((url,req.get_header('Authorization'),timeout))
        result=run if url.endswith('/actions/runs/123') else artifact
        return Response(json.dumps(result).encode())
    return fake,calls

def test_authenticated_source_success():
    fake,calls=data()
    event,artifact=load_authenticated_metadata(REPO,123,17,'test-token',opener=fake)
    assert len(calls)==2
    assert calls[0][0]=='https://api.github.com/repos/example/demo/actions/runs/123'
    assert calls[1][0]=='https://api.github.com/repos/example/demo/actions/artifacts/17'
    assert all(c[1]=='Bearer test-token' and c[2]==20 for c in calls)
    assert event['workflow_run']['head_branch']=='dependabot/fix'
    assert artifact['id']==17

@pytest.mark.parametrize('repo,run,art,token,reason',[
 ('https://evil.test/repo',123,17,'a','invalid_repo_identifier'),
 ('example/demo\nother',123,17,'a','invalid_repo_identifier'),
 ('example/demo',0,17,'a','invalid_run_identifier'),
 ('example/demo',123,0,'a','invalid_artifact_identifier'),
 ('example/demo',123,17,'','missing_github_api_token'),
])
def test_invalid_connection_args(repo,run,art,token,reason):
    fake,calls=data()
    with pytest.raises(Denied,match=reason):
        load_authenticated_metadata(repo,run,art,token,opener=fake)
    assert not calls

@pytest.mark.parametrize('bad_run,bad_art,reason',[
 ({**RUN,'id':333},ART,'github_api_run_identity_mismatch'),
 (RUN,{**ART,'id':333},'github_api_artifact_identity_mismatch'),
 ({**RUN,'repository':{'id':24,'full_name':'attacker/fork'}},ART,'github_api_repo_mismatch'),
 (RUN,{**ART,'workflow_run':{**ART['workflow_run'],'id':222}},'github_api_artifact_from_other_run'),
 (RUN,{**ART,'workflow_run':{**ART['workflow_run'],'head_sha':'b'*40}},'github_api_sha_mismatch'),
 (RUN,{**ART,'workflow_run':{**ART['workflow_run'],'repository_id':25}},'github_api_repository_id_mismatch'),
])
def test_github_api_cross_object_binding(bad_run,bad_art,reason):
    fake,calls=data(bad_run,bad_art)
    with pytest.raises(Denied,match=reason):
        load_authenticated_metadata(REPO,123,17,'token',opener=fake)

def test_api_transport_failure_denied():
    def broken(request,timeout):raise OSError('network unavailable')
    with pytest.raises(Denied,match='authenticated_github_api_request_failed'):
        load_authenticated_metadata(REPO,123,17,'token',opener=broken)
