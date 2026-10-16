from __future__ import annotations
import base64
import importlib.util
from pathlib import Path
import pytest
SPEC=importlib.util.spec_from_file_location('bootstrap',Path(__file__).resolve().parents[1]/'scripts/init_secrets.py')
bootstrap=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(bootstrap)

def test_bootstrap_generates_independent_secrets_without_connections(tmp_path):
    bootstrap.initialize(tmp_path,True)
    assert 'LOCAL_DEV=true' in (tmp_path/'.env').read_text()
    assert 'AGENT_URL=\n' in (tmp_path/'.env').read_text()
    assert len(base64.b64decode((tmp_path/'secrets/master-key').read_text()))==32
    assert (tmp_path/'secrets/database-password').read_text()!=(tmp_path/'secrets/migration-password').read_text()
    assert not (tmp_path/'secrets/smtp-password').read_text().strip()

def test_bootstrap_refuses_overwrite(tmp_path):
    bootstrap.initialize(tmp_path,True)
    old=(tmp_path/'secrets/master-key').read_bytes()
    with pytest.raises(ValueError):bootstrap.initialize(tmp_path,True)
    assert (tmp_path/'secrets/master-key').read_bytes()==old

@pytest.mark.parametrize('origin',['http://admin.example.test','https://user:pass@example.test','https://example.test/a','https://example.test?key=a','https://example.test/#a'])
def test_production_bootstrap_rejects_unsafe_origin(tmp_path,origin):
    with pytest.raises(ValueError):bootstrap.initialize(tmp_path,False,origin)
    assert not (tmp_path/'.env').exists()
