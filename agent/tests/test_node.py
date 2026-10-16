from pathlib import Path
import json
import uuid
import pytest
from agent.errors import AgentError
from agent.server import Agent
from .conftest import call


def create(agent, password_hash, address="user@example.test"):
    return call(agent, "mailbox.create", {"address": address, "passwordHash": password_hash, "quotaBytes": 1048576})


def test_mailbox_lifecycle_writes_real_maps(agent, password_hash):
    result = create(agent, password_hash)
    assert result["state"] == "active"
    assert "passwordHash" not in json.dumps(result)
    assert password_hash in Path(agent.config["mailbox_file"]).read_text()
    assert "user@example.test 1" in Path(agent.config["recipient_map"]).read_text()
    data = Path(agent.config["mail_root"]) / "example.test/user/Maildir/new/message"
    data.write_text("existing-message")
    call(agent, "mailbox.disable", {"address": "user@example.test"})
    assert ":!{SHA512-CRYPT}" in Path(agent.config["mailbox_file"]).read_text()
    call(agent, "mailbox.enable", {"address": "user@example.test"})
    assert ":!{SHA512-CRYPT}" not in Path(agent.config["mailbox_file"]).read_text()
    call(agent, "mailbox.quota", {"address": "user@example.test", "quotaBytes": 2097152})
    assert "bytes=2097152" in Path(agent.config["mailbox_file"]).read_text()
    call(agent, "mailbox.soft_delete", {"address": "user@example.test"})
    assert not Path(agent.config["recipient_map"]).read_text().strip()
    assert data.read_text() == "existing-message"
    call(agent, "mailbox.enable", {"address": "user@example.test"})
    assert data.read_text() == "existing-message"


def test_idempotency_has_one_effect(agent, password_hash):
    job_id = str(uuid.uuid4())
    params = {"address": "user@example.test", "passwordHash": password_hash, "quotaBytes": 1048576}
    assert call(agent, "mailbox.create", params, job_id) == call(agent, "mailbox.create", params, job_id)
    assert agent.node.db.execute("SELECT count(*) FROM mailbox").fetchone()[0] == 1


def test_read_only_default(agent, password_hash):
    agent.config["write_enabled"] = False
    with pytest.raises(AgentError, match="NODE_READ_ONLY"):
        create(agent, password_hash)
    assert agent.node.db.execute("SELECT count(*) FROM mailbox").fetchone()[0] == 0


def test_hash_never_read_back(agent, password_hash):
    create(agent, password_hash)
    items = call(agent, "mailbox.list")
    assert "password" not in json.dumps(items).lower()
    assert "SHA512" not in json.dumps(items)
    assert items["items"][0]["usedBytes"] is None


def test_alias_one_hop_and_loop_rejection(agent, password_hash):
    create(agent, password_hash)
    call(agent, "alias.create", {"address": "support@example.test", "destination": "user@example.test"})
    with pytest.raises(AgentError, match="ALIAS_COLLISION_OR_LOOP"):
        call(agent, "alias.create", {"address": "sales@example.test", "destination": "support@example.test"})
    with pytest.raises(AgentError):
        call(agent, "alias.create", {"address": "sales@example.test", "destination": "sales@example.test"})
    call(agent, "alias.delete", {"address": "support@example.test"})
    assert Path(agent.config["alias_map"]).read_text() == ""


def test_external_map_drift_blocks_write(agent, password_hash):
    Path(agent.config["alias_map"]).write_text("unexpected@example.test other@example.test\n")
    with pytest.raises(AgentError, match="NODE_READ_ONLY"):
        create(agent, password_hash)
    assert "unexpected" in Path(agent.config["alias_map"]).read_text()


def test_partial_file_write_failure_rolls_back(agent, password_hash, monkeypatch):
    old = {key: Path(agent.config[key]).read_bytes() for key in ("mailbox_file", "recipient_map", "alias_map")}
    original = agent.node._atomic_write
    counter = [0]
    def write(path, data, mode=0o640):
        counter[0] += 1
        if counter[0] == 3:
            raise OSError("injected_write_failure")
        original(path, data, mode)
    monkeypatch.setattr(agent.node, "_atomic_write", write)
    with pytest.raises(AgentError, match="OPERATION_UNCONFIRMED"):
        create(agent, password_hash)
    assert agent.node.db.execute("SELECT count(*) FROM mailbox").fetchone()[0] == 0
    for key, expected in old.items():
        assert Path(agent.config[key]).read_bytes() == expected


def test_unknown_adapter_never_adopted(config):
    config["adapter"] = "inventory"
    a = Agent(config, lab=True)
    try:
        assert a.node.write_enabled() is False
        assert a.node.list_mailboxes()["supported"] is False
    finally:
        a.close()


def test_existing_unknown_passwd_kept_untouched(config):
    Path(config["mailbox_file"]).write_text("legacy:unrecognized\n")
    a = Agent(config, lab=True)
    try:
        assert a.node.write_enabled() is False
        assert Path(config["mailbox_file"]).read_text() == "legacy:unrecognized\n"
    finally:
        a.close()


def test_restart_reads_persisted_state(agent, password_hash):
    create(agent, password_hash)
    config = agent.config
    agent.node.close()
    replacement = Agent(config, lab=True)
    agent.node = replacement.node
    assert replacement.node.list_mailboxes()["items"][0]["address"] == "user@example.test"


def test_existing_maildir_never_overwritten(agent, password_hash):
    home = Path(agent.config["mail_root"]) / "example.test/user"
    home.mkdir(parents=True)
    (home / "valuable").write_text("preserve")
    with pytest.raises(AgentError, match="MAILBOX_HOME_ALREADY_EXISTS"):
        create(agent, password_hash)
    assert (home / "valuable").read_text() == "preserve"
