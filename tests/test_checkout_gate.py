"""Git HEAD authorization tests using temporary non-network Git repositories."""
import base64
import subprocess
from datetime import datetime,timedelta,timezone
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from ci_trace.checkout_gate import verify_approved_checkout
from ci_trace.signed_authorization import payload_bytes
from ci_trace.provenance_guard import Denied
NOW=datetime(2026,10,11,13,tzinfo=timezone.utc)

def gitrepo(tmp_path):
    root=tmp_path/'checkout';root.mkdir()
    for a in [['init','-q'],['config','user.email','test@example.invalid'],
              ['config','user.name','test']]:
        subprocess.run(['git','-C',str(root),*a],check=True,capture_output=True)
    (root/'safe.txt').write_text('first')
    subprocess.run(['git','-C',str(root),'add','safe.txt'],check=True,capture_output=True)
    subprocess.run(['git','-C',str(root),'commit','-qm','first'],check=True,capture_output=True)
    sha=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()
    key=Ed25519PrivateKey.generate()
    pub=key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                      format=serialization.PublicFormat.Raw).hex()
    record={'repository':'example/demo','run_id':0,'artifact_name':'bundle',
            'commit_sha':sha,'purpose':'artifact_release',
            'issued_at':(NOW-timedelta(minutes=2)).isoformat(),
            'expires_at':(NOW+timedelta(minutes=5)).isoformat()}
    pack={'key_id':'test','record':record,
          'signature':base64.b64encode(key.sign(payload_bytes(record))).decode()}
    return root,sha,pack,{'test':pub}

def test_signed_exact_checkout_passes(tmp_path):
    root,sha,pack,keys=gitrepo(tmp_path)
    result=verify_approved_checkout(root,pack,keys,now=NOW)
    assert result['approved_sha']==sha
    assert not result['safe_to_execute_or_publish']

def test_changed_commit_rejected(tmp_path):
    root,sha,pack,keys=gitrepo(tmp_path)
    (root/'safe.txt').write_text('second')
    subprocess.run(['git','-C',str(root),'add','safe.txt'],check=True)
    subprocess.run(['git','-C',str(root),'commit','-qm','second'],check=True)
    with pytest.raises(Denied,match='checked_out_commit_not_approved'):
        verify_approved_checkout(root,pack,keys,now=NOW)

@pytest.mark.parametrize('kind',['dirty_tracked','untracked_script'])
def test_modified_worktree_rejected(tmp_path,kind):
    root,sha,pack,keys=gitrepo(tmp_path)
    if kind=='dirty_tracked':(root/'safe.txt').write_text('second')
    else:(root/'extra.py').write_text('pass')
    with pytest.raises(Denied,match='checkout_not_clean'):
        verify_approved_checkout(root,pack,keys,now=NOW)

def test_signed_record_tampering_rejected(tmp_path):
    root,sha,pack,keys=gitrepo(tmp_path)
    pack['record']['commit_sha']='b'*40
    with pytest.raises(Denied,match='approval_signature_invalid'):
        verify_approved_checkout(root,pack,keys,now=NOW)
