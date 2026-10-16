from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
import uuid
import pytest
from agent.server import Agent


@pytest.fixture
def config(tmp_path: Path):
    maps = tmp_path / "maps"
    maps.mkdir()
    for name in ("users", "recipients", "aliases"):
        (maps / name).write_text("")
    mail = tmp_path / "mail"
    mail.mkdir()
    for name in ("signing", "backup-key"):
        (tmp_path / name).write_text(base64.b64encode(os.urandom(32)).decode())
        (tmp_path / name).chmod(0o600)
    return {
        "instance_id": "lab-node-0001", "adapter": "postfix-dovecot-passwd-v1",
        "state_root": str(tmp_path / "state"), "mail_root": str(mail),
        "mailbox_file": str(maps / "users"), "recipient_map": str(maps / "recipients"), "alias_map": str(maps / "aliases"),
        "mail_uid": os.getuid(), "mail_gid": os.getgid(), "domains": ["example.test"],
        "forward_domains": [], "write_enabled": True, "allow_helper": False,
        "signing_key_file": str(tmp_path / "signing"), "backup_key_file": str(tmp_path / "backup-key"),
        "backup_root": str(tmp_path / "backups"), "drill_root": str(tmp_path / "drills"),
        "backup_sources": [{"label": "maildir", "path": str(mail)}, {"label": "maps", "path": str(maps)}],
        "max_backup_bytes": 2 * 1024 * 1024, "max_backup_files": 100, "backup_timeout_seconds": 10,
        "backup_coverage": "test_profiles_only",
    }


@pytest.fixture
def agent(config):
    instance = Agent(config, lab=True)
    yield instance
    instance.close()


@pytest.fixture
def password_hash():
    # A deliberately fictitious format-only test hash; never presented as a real mailbox password fixture.
    return "{SHA512-CRYPT}$6$rounds=100000$testfixture$" + "A" * 86


def request(agent, method, params=None, job_id=None, timestamp=None, nonce=None):
    body = {"version": 1, "jobId": job_id or str(uuid.uuid4()), "method": method, "params": params or {}}
    raw = json.dumps(body, separators=(",", ":")).encode()
    timestamp = str(timestamp if timestamp is not None else int(time.time()))
    nonce = nonce or base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")
    headers = {"X-Instance-ID": agent.config["instance_id"], "X-Timestamp": timestamp, "X-Nonce": nonce, "Content-Type": "application/json"}
    headers["X-Signature"] = hmac.new(agent.signing_key, (timestamp + "\n" + nonce + "\n" + agent.config["instance_id"] + "\n").encode() + raw, hashlib.sha256).hexdigest()
    return headers, raw


def call(agent, method, params=None, job_id=None):
    headers, raw = request(agent, method, params, job_id)
    return agent.process(headers, raw)
