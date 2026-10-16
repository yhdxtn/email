"""Read-only probes against an installation-pinned IP/hostname, never HTTP-supplied targets."""
from __future__ import annotations
import datetime as dt
import imaplib
import ipaddress
from pathlib import Path
import smtplib
import socket
import ssl
import time
from typing import Any
from .errors import AgentError


def run(config: dict[str, Any]) -> dict[str, Any]:
    hostname = config.get("mail_hostname")
    address = config.get("probe_ip")
    if not hostname or not address:
        return {"checks": [{"name": "node.network", "state": "unknown", "code": "PROBE_TARGET_NOT_CONFIGURED", "source": "agent"}]}
    ipaddress.ip_address(address)  # A single numeric IP is pinned in the root-owned config.
    checks: list[dict[str, Any]] = []
    for port in (25, 587, 993):
        start = time.monotonic()
        try:
            with socket.create_connection((address, port), timeout=3):
                pass
            state, code = "healthy", "TCP_CONNECTED"
        except OSError:
            state, code = "failed", "TCP_BLOCKED_OR_SERVICE_DOWN"
        checks.append({"name": f"tcp.{port}", "state": state, "code": code, "source": "agent_pinned_ip", "latencyMs": int((time.monotonic() - start) * 1000), "delivery": "not_tested"})
    client = None
    try:
        client = smtplib.SMTP(timeout=4)
        client.connect(address, 587)
        client.ehlo()
        client._host = hostname  # Pin IP at connect, verify configured mail hostname during STARTTLS.
        client.starttls(context=ssl.create_default_context())
        cert = client.sock.getpeercert()
        remaining = (ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400
        checks.append({"name": "smtp.starttls", "state": "healthy" if remaining > 14 else "degraded", "code": "TLS_VERIFIED", "expiresInDays": int(remaining), "source": "agent_pinned_ip", "smtpSubmission": "not_tested"})
    except ssl.SSLCertVerificationError:
        checks.append({"name": "smtp.starttls", "state": "failed", "code": "TLS_CERTIFICATE_INVALID", "source": "agent_pinned_ip"})
    except ssl.SSLError:
        checks.append({"name": "smtp.starttls", "state": "failed", "code": "TLS_NEGOTIATION_FAILED", "source": "agent_pinned_ip"})
    except (OSError, smtplib.SMTPException):
        checks.append({"name": "smtp.starttls", "state": "failed", "code": "SMTP_STARTTLS_UNAVAILABLE", "source": "agent_pinned_ip"})
    finally:
        if client:
            client.close()
    try:
        with socket.create_connection((address, 993), timeout=4) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400)
                checks.append({"name": "imap.tls", "state": "healthy" if days > 14 else "degraded", "code": "TLS_VERIFIED", "expiresInDays": days, "source": "agent_pinned_ip"})
    except ssl.SSLError:
        checks.append({"name": "imap.tls", "state": "failed", "code": "TLS_CERTIFICATE_OR_PROTOCOL_ERROR", "source": "agent_pinned_ip"})
    except OSError:
        checks.append({"name": "imap.tls", "state": "failed", "code": "IMAP_TLS_UNAVAILABLE", "source": "agent_pinned_ip"})
    # Explicitly distinguish credential-free TLS probing from an actual synthetic login.
    checks.append({"name": "imap.synthetic_login", "state": "unknown", "code": "SYNTHETIC_LOGIN_CONNECTOR_NOT_IMPLEMENTED", "source": "agent"})
    checks.append({"name": "external.inbox", "state": "unknown", "code": "MANUAL_RECIPIENT_CONFIRMATION_REQUIRED", "source": "external_observation"})
    return {"checks": checks, "checkedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "targets": "installation_pinned_only"}
