"""Demonstrate distinct UID key custody and unavoidable same-UID 0600 read exposure."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

@pytest.mark.skipif(os.geteuid()!=0,reason='disposable root runner required')
def test_two_distinct_issuer_unix_uids():
    with tempfile.TemporaryDirectory(prefix='v15-custody-',dir='/tmp') as td:
        top=Path(td);top.chmod(0o755)
        secrets={}
        for role,uid in [('security',65534),('release',1)]:
            folder=top/role;folder.mkdir(mode=0o700);os.chown(folder,uid,uid)
            key=folder/'private.pem'
            sk=Ed25519PrivateKey.generate()
            key.write_bytes(sk.private_bytes(
                serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            os.chown(key,uid,uid);key.chmod(0o600)
            secrets[role]=key
        def can_read(uid,path):
            result=subprocess.run([sys.executable,'-c',
                   'from pathlib import Path;import sys;Path(sys.argv[1]).read_bytes()',
                   str(path)],preexec_fn=lambda:(os.setgroups([]),os.setgid(uid),os.setuid(uid)),
                   capture_output=True,text=True,timeout=8)
            return result.returncode==0
        assert can_read(65534,secrets['security'])
        assert can_read(1,secrets['release'])
        assert not can_read(65534,secrets['release'])
        assert not can_read(1,secrets['security'])
        same_uid=secrets['security'].parent/'other-application.key'
        same_uid.write_bytes(b'ephemeral test material')
        os.chown(same_uid,65534,65534);same_uid.chmod(0o600)
        assert can_read(65534,same_uid) # Real same-UID key theft counterexample.
