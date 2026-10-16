from pathlib import Path
import importlib.util
import json
import os
import secrets
import subprocess
import pytest
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
ROOT=Path(__file__).resolve().parents[1]

def test_agent_examples_are_fail_closed():
    for name in ('agent.inventory.example.json','agent.managed-profile.example.json'):
        value=json.loads((ROOT/'deploy'/name).read_text())
        assert value['write_enabled'] is False and value['allow_helper'] is False
        assert value['probe_ip'] is None and value['mail_hostname'] is None
        assert value['bind']=='127.0.0.1'

def test_bootstrap_postgres_uses_private_init_copy():
    script=(ROOT/'deploy/postgres-secrets-entrypoint.sh').read_text()
    assert 'install -o postgres -g postgres -m 600' in script
    assert '/run/astrogate-init/database-password' in (ROOT/'deploy/postgres-init.sh').read_text()

def test_source_scan():
    assert subprocess.run([os.sys.executable,str(ROOT/'scripts/source_scan.py')],capture_output=True).returncode==0

def test_offline_enrollment_bundle_no_overwrite(tmp_path):
    spec=importlib.util.spec_from_file_location('pki',ROOT/'scripts/make_agent_pki.py');pki=importlib.util.module_from_spec(spec);spec.loader.exec_module(pki)
    password=secrets.token_urlsafe(32).encode();out=tmp_path/'bundle';pki.generate(out,'agent.example.test','192.0.2.20',password)
    key,cert,cas=pkcs12.load_key_and_certificates((out/'client.p12').read_bytes(),password)
    assert key is not None and cert is not None and len(cas)==1
    assert cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert (out/'OFFLINE-CA-PRIVATE.key').stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError):pki.generate(out,'agent.example.test','192.0.2.20',password)
