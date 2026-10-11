import os
import json
import pytest
from test_json_consumer_v10 import setup,NOW
from ci_trace.provenance_guard import Denied
from ci_trace.sealed_signed_release_v11 import issue_sealed_member
from ci_trace.sealed_handoff_v11 import consume_authorized_sealed_fd

def test_sealed_signed_member_handoff_no_path_leaked(tmp_path):
    z,event,art,policy,approval,keys,out,ws=setup(tmp_path)
    fd,att=issue_sealed_member(z,event,art,policy,approval,keys,out,ws,
                               'data.json',now=NOW)
    try:
        assert json.loads(consume_authorized_sealed_fd(fd,att['proof'],
                trusted_expected_sha256=att['trusted_expected_sha256']))=={'pr_number':17}
        assert att['safe_to_execute_or_publish'] is False
        assert not list(out.iterdir())
    finally:os.close(fd)

def test_cannot_issue_from_tampered_signature(tmp_path):
    z,event,art,policy,approval,keys,out,ws=setup(tmp_path)
    approval['record']['commit_sha']='b'*40
    with pytest.raises(Denied,match='approval_signature_invalid'):
        issue_sealed_member(z,event,art,policy,approval,keys,out,ws,'data.json',now=NOW)
    assert not list(out.iterdir())

def test_cannot_issue_unmanifested_member(tmp_path):
    z,event,art,policy,approval,keys,out,ws=setup(tmp_path)
    with pytest.raises(Denied,match='member_not_in_verified_manifest'):
        issue_sealed_member(z,event,art,policy,approval,keys,out,ws,'no.json',now=NOW)
    assert not list(out.iterdir())
