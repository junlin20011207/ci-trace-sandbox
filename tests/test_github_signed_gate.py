"""Fail closed when policy or trust roots are inside an untrusted checkout."""
import pytest
from ci_trace.github_signed_gate import protected_config
from ci_trace.provenance_guard import Denied

def test_protected_keys_outside_checkout(tmp_path):
    workspace=tmp_path/'checkout';workspace.mkdir()
    keys=tmp_path/'keys.json';keys.write_text('{"k":"public"}')
    assert protected_config(keys,workspace)=={'k':'public'}

@pytest.mark.parametrize('deep',[False,True])
def test_reject_untrusted_workspace_configuration(tmp_path,deep):
    workspace=tmp_path/'checkout';workspace.mkdir()
    folder=workspace/'deep' if deep else workspace
    folder.mkdir(exist_ok=True)
    keys=folder/'keys.json';keys.write_text('{}')
    with pytest.raises(Denied,match='trusted_configuration_inside_workspace'):
        protected_config(keys,workspace)

def test_reject_nonfile_as_trust_config(tmp_path):
    workspace=tmp_path/'checkout';workspace.mkdir()
    config=tmp_path/'keys';config.mkdir()
    with pytest.raises(Denied,match='trusted_configuration_not_file'):
        protected_config(config,workspace)
