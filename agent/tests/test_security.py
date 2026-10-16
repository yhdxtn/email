import base64
import hashlib
import hmac
import json
import os
import time
import uuid
import pytest
from agent.errors import AgentError
from agent.server import make_server
from agent.schema import validate
from .conftest import request, call


def test_signature_required(agent):
    headers, raw = request(agent, "mailbox.list")
    headers["X-Signature"] = "0" * 64
    with pytest.raises(AgentError, match="TASK_SIGNATURE_INVALID"):
        agent.process(headers, raw)


@pytest.mark.parametrize("delta", [-61, 61, -3600, 3600])
def test_task_expiry(agent, delta):
    headers, raw = request(agent, "mailbox.list", timestamp=int(time.time()) + delta)
    with pytest.raises(AgentError, match="TASK_IDENTITY_OR_EXPIRY_INVALID"):
        agent.process(headers, raw)


def test_instance_binding(agent):
    headers, raw = request(agent, "mailbox.list")
    headers["X-Instance-ID"] = "different-node"
    with pytest.raises(AgentError, match="TASK_IDENTITY_OR_EXPIRY_INVALID"):
        agent.process(headers, raw)


def test_nonce_replay(agent):
    headers, raw = request(agent, "mailbox.list")
    agent.process(headers, raw)
    with pytest.raises(AgentError, match="TASK_NONCE_REPLAY"):
        agent.process(headers, raw)


@pytest.mark.parametrize("method,params", [
    ("shell.execute", {"command": "id"}),
    ("mailbox.list", {"command": "id"}),
    ("diagnostics.read", {"host": "169.254.169.254"}),
    ("backup.create", {"archiveId": str(uuid.uuid4()), "path": "/etc/shadow"}),
    ("service.reload_allowlisted", {"service": "nginx"}),
    ("service.reload_allowlisted", {"service": "postfix;id"}),
    ("mail.queue.delete_allowlisted", {"queueId": "ALL"}),
    ("mail.queue.retry_allowlisted", {"queueId": "-f;id"}),
])
def test_unknown_methods_and_arguments(agent, method, params):
    with pytest.raises(AgentError):
        call(agent, method, params)


@pytest.mark.parametrize("address", ["a@example.test;id", "../../a@example.test", "a@foreign.test", "a\n@example.test", "a..b@example.test", "a,b@example.test", "a@127.0.0.1"])
def test_address_validation(agent, password_hash, address):
    with pytest.raises(AgentError):
        call(agent, "mailbox.create", {"address": address, "passwordHash": password_hash, "quotaBytes": 1048576})


@pytest.mark.parametrize("quota", [True, 0, -1, 1048575, 2**41, "1048576"])
def test_quota_validation(agent, password_hash, quota):
    with pytest.raises(AgentError, match="INVALID_QUOTA"):
        call(agent, "mailbox.create", {"address": "a@example.test", "passwordHash": password_hash, "quotaBytes": quota})


@pytest.mark.parametrize("value", ["secret", "{PLAIN}secret", "{SHA512-CRYPT}$6$wrong", "x\ncommand"])
def test_plaintext_password_never_accepted(agent, value):
    with pytest.raises(AgentError, match="PASSWORD_HASH_FORMAT_UNSUPPORTED"):
        call(agent, "mailbox.create", {"address": "a@example.test", "passwordHash": value, "quotaBytes": 1048576})


def test_duplicate_json_keys_rejected(agent):
    headers, raw = request(agent, "mailbox.list")
    raw = raw[:-1] + b',"params":{}}'
    signed = (headers["X-Timestamp"] + "\n" + headers["X-Nonce"] + "\n" + headers["X-Instance-ID"] + "\n").encode() + raw
    headers["X-Signature"] = hmac.new(agent.signing_key, signed, hashlib.sha256).hexdigest()
    with pytest.raises(AgentError, match="DUPLICATE_JSON_KEY"):
        agent.process(headers, raw)


def test_http_cannot_bind_publicly(agent):
    with pytest.raises(AgentError, match="PLAINTEXT_AGENT_FORBIDDEN"):
        make_server(agent, ("0.0.0.0", 0), tls=False)


def test_large_payload_rejected(agent):
    with pytest.raises(AgentError, match="REQUEST_TOO_LARGE"):
        agent.process({}, b"x" * (65536 + 1))


def test_job_id_conflict(agent, password_hash):
    job_id = str(uuid.uuid4())
    p = {"address": "a@example.test", "passwordHash": password_hash, "quotaBytes": 1048576}
    call(agent, "mailbox.create", p, job_id)
    p["address"] = "b@example.test"
    with pytest.raises(AgentError, match="IDEMPOTENCY_CONFLICT"):
        call(agent, "mailbox.create", p, job_id)


def test_no_plaintext_listener_in_production(agent):
    agent.lab = False
    with pytest.raises(AgentError, match="PLAINTEXT_AGENT_FORBIDDEN"):
        make_server(agent, ("127.0.0.1", 0), tls=False)
