"""mTLS + HMAC instance-bound RPC, durable nonce/job ledger, fail-closed schemas."""
from __future__ import annotations
import argparse
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import ssl
import stat
import threading
import time
from typing import Any

from .backup import BackupStore, no_symlinks
from .diagnostics import run as diagnostics
from .errors import AgentError
from .node import Node, ADAPTER
from .schema import validate, MUTATING

MAX_REQUEST = 64 * 1024


def secret_file(path: str, lab: bool = False) -> bytes:
    target = no_symlinks(Path(path))
    if not target.is_file() or target.stat().st_size > 256:
        raise AgentError("SECRET_FILE_INVALID")
    if not lab and (stat.S_IMODE(target.stat().st_mode) & 0o077 or target.stat().st_uid not in {0, os.geteuid()}):
        raise AgentError("SECRET_FILE_PERMISSIONS")
    try:
        key = base64.b64decode(target.read_text().strip(), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise AgentError("SECRET_FILE_INVALID") from exc
    if len(key) != 32:
        raise AgentError("SECRET_KEY_LENGTH")
    return key


def load_config(path: str, lab: bool = False) -> dict[str, Any]:
    target = no_symlinks(Path(path))
    if not target.is_file() or target.stat().st_size > 32768:
        raise AgentError("CONFIG_MISSING_OR_TOO_LARGE")
    if not lab and (target.stat().st_uid != 0 or stat.S_IMODE(target.stat().st_mode) & 0o022):
        raise AgentError("CONFIG_MUST_BE_ROOT_OWNED")
    cfg = json.loads(target.read_text(encoding="utf-8"))
    if cfg.get("adapter") not in {"inventory", ADAPTER} or not re.fullmatch(r"[a-zA-Z0-9_-]{8,64}", cfg.get("instance_id", "")):
        raise AgentError("CONFIG_ID_OR_ADAPTER_INVALID")
    return cfg


class Agent:
    def __init__(self, config: dict[str, Any], lab: bool = False):
        self.config, self.lab = config, lab
        self.node = Node(config, lab=lab)
        self.signing_key = secret_file(config["signing_key_file"], lab=lab)
        self.lock = threading.RLock()
        self.backup: BackupStore | None = None
        if config.get("backup_key_file"):
            self.backup = BackupStore(config, secret_file(config["backup_key_file"], lab=lab))

    def close(self) -> None:
        self.node.close()

    def _authorize(self, headers: Any, raw: bytes) -> str:
        instance = headers.get("X-Instance-ID", "")
        timestamp = headers.get("X-Timestamp", "")
        nonce = headers.get("X-Nonce", "")
        signature = headers.get("X-Signature", "")
        if instance != self.config["instance_id"] or not re.fullmatch(r"[0-9]{10,12}", timestamp) or abs(int(time.time()) - int(timestamp)) > 60 or not re.fullmatch(r"[A-Za-z0-9_-]{43}", nonce):
            raise AgentError("TASK_IDENTITY_OR_EXPIRY_INVALID", 401)
        expected = hmac.new(self.signing_key, (timestamp + "\n" + nonce + "\n" + instance + "\n").encode() + raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise AgentError("TASK_SIGNATURE_INVALID", 401)
        if self.node.db.execute("SELECT 1 FROM nonces WHERE nonce=?", (nonce,)).fetchone():
            raise AgentError("TASK_NONCE_REPLAY", 409)
        with self.node.atomic():
            self.node.db.execute("DELETE FROM nonces WHERE created<?", (int(time.time()) - 180,))
            self.node.db.execute("INSERT INTO nonces(nonce,created) VALUES(?,?)", (nonce, int(time.time())))
        return nonce

    def process(self, headers: Any, raw: bytes) -> dict[str, Any]:
        if len(raw) > MAX_REQUEST:
            raise AgentError("REQUEST_TOO_LARGE", 413)
        with self.lock:
            self._authorize(headers, raw)
            try:
                # Reject duplicate JSON keys to eliminate alternate interpretation of signed parameters.
                def pairs(items):
                    result = {}
                    for key, value in items:
                        if key in result:
                            raise AgentError("DUPLICATE_JSON_KEY")
                        result[key] = value
                    return result
                body = json.loads(raw, object_pairs_hook=pairs)
            except (json.JSONDecodeError, UnicodeError) as exc:
                raise AgentError("INVALID_JSON") from exc
            job_id, method, params = validate(body, self.node.domains, set(self.config.get("forward_domains", [])))
            fingerprint = hashlib.sha256(json.dumps({"method": method, "params": params}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            old = self.node.db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
            if old:
                if not hmac.compare_digest(old["fingerprint"], fingerprint):
                    raise AgentError("IDEMPOTENCY_CONFLICT", 409)
                if old["state"] == "success":
                    return json.loads(old["result"])
                raise AgentError("PREVIOUS_JOB_" + old["state"].upper(), 409)
            if self.node.db.execute("SELECT count(*) FROM jobs").fetchone()[0] >= int(self.config.get("max_ledger_jobs", 500000)):
                raise AgentError("LEDGER_CAPACITY_REACHED", 507)
            with self.node.atomic():
                self.node.db.execute("INSERT INTO jobs(id,fingerprint,method,state,created) VALUES(?,?,?,'running',?)", (job_id, fingerprint, method, int(time.time())))
            try:
                result = self._dispatch(method, params)
                encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
                if len(encoded) > 1024 * 1024:
                    raise AgentError("RESULT_TOO_LARGE", 503)
                with self.node.atomic():
                    self.node.db.execute("UPDATE jobs SET state='success',result=? WHERE id=?", (encoded, job_id))
                return result
            except AgentError as exc:
                with self.node.atomic():
                    self.node.db.execute("UPDATE jobs SET state='failed',error=? WHERE id=?", (exc.code, job_id))
                raise
            except Exception as exc:
                with self.node.atomic():
                    self.node.db.execute("UPDATE jobs SET state='unknown',error='OPERATION_UNCONFIRMED' WHERE id=?", (job_id,))
                raise AgentError("OPERATION_UNCONFIRMED", 503) from exc

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "health.read":
            return self.node.health()
        if method == "service.status":
            return {"services": self.node.services()}
        if method == "mailbox.list":
            return self.node.list_mailboxes()
        if method in {"diagnostics.read", "dns.local_preflight"}:
            return diagnostics(self.config)
        if method == "mail.queue.summary":
            return self.node.queue()
        if method.startswith(("mail.queue.retry", "mail.queue.delete", "service.reload")):
            return self.node.helper(method, params)
        if method in MUTATING:
            return self.node.mutate(method, params)
        if method.startswith("backup."):
            if self.backup is None:
                raise AgentError("BACKUP_NOT_CONFIGURED", 409)
            if method == "backup.create":
                self.node.snapshot_state()
                result = self.backup.create(params["archiveId"])
                self.node.db.execute("INSERT INTO backups(id,result) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET result=excluded.result", (params["archiveId"], json.dumps(result)))
                return result
            if method == "backup.verify":
                result = self.backup.verify(params["archiveId"])
                self.node.db.execute("INSERT INTO backups(id,verified_at,result) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET verified_at=excluded.verified_at,result=excluded.result", (params["archiveId"], int(time.time()), json.dumps(result)))
                return result
            if method == "backup.restore_drill":
                return self.backup.restore_drill(params["archiveId"], params["drillId"])
        raise AgentError("METHOD_NOT_ALLOWED", 403)


def make_server(agent: Agent, address: tuple[str, int], tls: bool = True) -> ThreadingHTTPServer:
    if not tls and (not agent.lab or address[0] not in {"127.0.0.1", "::1", "localhost"}):
        raise AgentError("PLAINTEXT_AGENT_FORBIDDEN")

    class Handler(BaseHTTPRequestHandler):
        server_version = "AstrogateAgent/0.1"
        sys_version = ""
        protocol_version = "HTTP/1.0"

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, format, *args):
            # BaseHTTPRequestHandler default request logging is intentionally disabled.
            pass

        def send_json(self, status: int, body: dict[str, Any]):
            raw = json.dumps(body, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            self.send_json(405, {"code": "METHOD_NOT_ALLOWED"})

        def do_POST(self):
            try:
                if self.path != "/rpc/v1":
                    raise AgentError("NOT_FOUND", 404)
                if tls:
                    peer = self.connection.getpeercert(binary_form=True)
                    pin = hashlib.sha256(peer).hexdigest()
                    if not hmac.compare_digest(pin, agent.config["client_cert_sha256"]):
                        raise AgentError("CLIENT_CERT_NOT_BOUND", 403)
                if self.headers.get("Transfer-Encoding") or self.headers.get_content_type() != "application/json":
                    raise AgentError("CONTENT_TYPE_OR_TRANSFER_ENCODING_INVALID", 415)
                length = self.headers.get("Content-Length", "")
                if not length.isdigit() or not 1 <= int(length) <= MAX_REQUEST:
                    raise AgentError("REQUEST_TOO_LARGE_OR_LENGTH_MISSING", 413)
                raw = self.rfile.read(int(length))
                if len(raw) != int(length):
                    raise AgentError("REQUEST_TRUNCATED")
                result = agent.process(self.headers, raw)
                self.send_json(200, result)
            except AgentError as exc:
                self.send_json(exc.status, {"code": exc.code})
            except Exception:
                self.send_json(500, {"code": "AGENT_INTERNAL_ERROR"})

    server = ThreadingHTTPServer(address, Handler)
    server.daemon_threads = True
    if tls:
        pin = agent.config.get("client_cert_sha256", "")
        if not re.fullmatch(r"[a-f0-9]{64}", pin):
            server.server_close()
            raise AgentError("CLIENT_CERT_PIN_REQUIRED")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(agent.config["tls_cert_file"], agent.config["tls_key_file"])
        context.load_verify_locations(cafile=agent.config["tls_ca_file"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Astrogate fixed-RPC mail agent")
    parser.add_argument("--config", required=True)
    parser.add_argument("--lab", action="store_true", help="Explicit loopback-only HTTP laboratory mode; NOT production")
    parser.add_argument("--check", action="store_true", help="Read-only compatibility report; does not install or modify mail services")
    args = parser.parse_args()
    try:
        config = load_config(args.config, lab=args.lab)
        agent = Agent(config, lab=args.lab)
        if args.check:
            print(json.dumps(agent.node.health(), ensure_ascii=False, indent=2))
            agent.close()
            return
        host = config.get("bind", "127.0.0.1")
        server = make_server(agent, (host, int(config.get("port", 9089))), tls=not args.lab)
        print(json.dumps({"event": "agent.started", "version": "0.1.0", "labMode": args.lab, "defaultReadOnly": not config.get("write_enabled", False)}), flush=True)
        try:
            server.serve_forever()
        finally:
            server.server_close()
            agent.close()
    except AgentError as exc:
        raise SystemExit(exc.code) from None


if __name__ == "__main__":
    main()
