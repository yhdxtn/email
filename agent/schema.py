from __future__ import annotations
import re
import uuid
from typing import Any
from .errors import AgentError

MAILBOX = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}@[a-z0-9.-]+\Z")
HASH = re.compile(r"\{SHA512-CRYPT\}\$6\$rounds=100000\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{86}\Z")
METHODS: dict[str, dict[str, str]] = {
    "health.read": {}, "service.status": {}, "diagnostics.read": {}, "dns.local_preflight": {},
    "mailbox.list": {}, "mailbox.create": {"address": "email", "passwordHash": "hash", "quotaBytes": "quota"},
    "mailbox.disable": {"address": "email"}, "mailbox.enable": {"address": "email"},
    "mailbox.password_reset": {"address": "email", "passwordHash": "hash"},
    "mailbox.quota": {"address": "email", "quotaBytes": "quota"}, "mailbox.soft_delete": {"address": "email"},
    "alias.create": {"address": "email", "destination": "destination"}, "alias.delete": {"address": "email"},
    "service.reload_allowlisted": {"service": "service"}, "mail.queue.summary": {},
    "mail.queue.retry_allowlisted": {"queueId": "queue"}, "mail.queue.delete_allowlisted": {"queueId": "queue"},
    "backup.create": {"archiveId": "uuid"}, "backup.verify": {"archiveId": "uuid"},
    "backup.restore_drill": {"archiveId": "uuid", "drillId": "uuid"},
}
MUTATING = {method for method in METHODS if method.startswith(("mailbox.", "alias.", "service.reload", "mail.queue.retry", "mail.queue.delete"))} - {"mailbox.list"}


def email(value: Any, allowed_domains: set[str] | None = None) -> str:
    if not isinstance(value, str) or len(value) > 254 or not MAILBOX.fullmatch(value):
        raise AgentError("INVALID_ADDRESS")
    local, domain = value.split("@")
    if ".." in local or local.endswith(".") or "." not in domain or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")):
        raise AgentError("INVALID_ADDRESS")
    if allowed_domains is not None and domain not in allowed_domains:
        raise AgentError("DOMAIN_NOT_ALLOWED", 403)
    return value


def validate(body: Any, domains: set[str], forward_domains: set[str]) -> tuple[str, str, dict[str, Any]]:
    if not isinstance(body, dict) or set(body) != {"version", "jobId", "method", "params"} or type(body["version"]) is not int or body["version"] != 1:
        raise AgentError("INVALID_RPC_ENVELOPE")
    job_id, method, params = body["jobId"], body["method"], body["params"]
    try:
        if str(uuid.UUID(job_id)) != job_id:
            raise ValueError
    except (ValueError, AttributeError, TypeError) as exc:
        raise AgentError("INVALID_JOB_ID") from exc
    if not isinstance(method, str) or method not in METHODS:
        raise AgentError("METHOD_NOT_ALLOWED", 403)
    if not isinstance(params, dict) or set(params) != set(METHODS[method]):
        raise AgentError("PARAMETER_SCHEMA_MISMATCH")
    for key, kind in METHODS[method].items():
        value = params[key]
        if kind in {"email", "destination"}:
            email(value, domains if kind == "email" else domains | forward_domains)
        elif kind == "hash":
            if not isinstance(value, str) or not HASH.fullmatch(value):
                raise AgentError("PASSWORD_HASH_FORMAT_UNSUPPORTED")
        elif kind == "quota":
            if type(value) is not int or not 1048576 <= value <= 1099511627776:
                raise AgentError("INVALID_QUOTA")
        elif kind == "uuid":
            try:
                if str(uuid.UUID(value)) != value:
                    raise ValueError
            except (ValueError, AttributeError, TypeError) as exc:
                raise AgentError("INVALID_OBJECT_ID") from exc
        elif kind == "queue":
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9]{5,32}", value):
                raise AgentError("INVALID_QUEUE_ID")
        elif kind == "service" and value not in {"postfix", "dovecot", "opendkim"}:
            raise AgentError("SERVICE_NOT_ALLOWED", 403)
    return job_id, method, params
