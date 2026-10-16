"""Strict Dovecot 2.3 passwd-file/Postfix texthash adapter.

Unknown mail-account implementations remain inventory-only. Existing maps are imported
only after an operator has declared the adapter and exact paths. Map drift fails closed.
"""
from __future__ import annotations
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time
from typing import Any

from .backup import no_symlinks
from .errors import AgentError
from .schema import email

ADAPTER = "postfix-dovecot-passwd-v1"


class Node:
    def __init__(self, config: dict[str, Any], lab: bool = False):
        self.config, self.lab = config, lab
        self.domains = set(config.get("domains", []))
        if not self.domains:
            raise AgentError("NO_ALLOWED_DOMAINS")
        for domain in self.domains:
            email("validation@" + domain)
        self.root = no_symlinks(Path(config["state_root"]))
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        ledger = self.root / "ledger.sqlite"
        no_symlinks(ledger)
        self.db = sqlite3.connect(ledger, check_same_thread=False, isolation_level=None)
        os.chmod(ledger, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, created INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, method TEXT NOT NULL, state TEXT NOT NULL, result TEXT, error TEXT, created INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS mailbox(address TEXT PRIMARY KEY, password_hash TEXT NOT NULL, quota INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'active');
          CREATE TABLE IF NOT EXISTS alias(address TEXT PRIMARY KEY, destination TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS backups(id TEXT PRIMARY KEY, verified_at INTEGER, result TEXT NOT NULL);
        """)
        self.db.execute("UPDATE jobs SET state='unknown',error='INTERRUPTED_REQUIRES_REVIEW' WHERE state='running'")
        self.paths: dict[str, Path] = {}
        if config.get("adapter") == ADAPTER:
            self.paths = {key: no_symlinks(Path(config[key])) for key in ("mailbox_file", "recipient_map", "alias_map")}
            if len(set(self.paths.values())) != 3:
                raise AgentError("ADAPTER_PATHS_OVERLAP")
        self.import_error: str | None = None
        if self.paths:
            try:
                self._import()
            except AgentError as exc:
                self.import_error = exc.code

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def atomic(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def _bytes(self, path: Path) -> bytes:
        no_symlinks(path)
        if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
            raise AgentError("ADAPTER_MAP_MISSING_OR_OVERSIZED", 409)
        return path.read_bytes()

    def _fingerprint(self) -> str:
        digest = hashlib.sha256()
        for label, path in sorted(self.paths.items()):
            digest.update(label.encode() + b"\0" + self._bytes(path) + b"\0")
        return digest.hexdigest()

    def _import(self) -> None:
        current = self._fingerprint()
        old = self.db.execute("SELECT value FROM meta WHERE key='map_fingerprint'").fetchone()
        if old:
            if old[0] != current:
                raise AgentError("EXTERNAL_MAP_DRIFT", 409)
            return
        users: list[tuple[str, str, int, str]] = []
        addresses: set[str] = set()
        mail_root = no_symlinks(Path(self.config["mail_root"]))
        for line in self._bytes(self.paths["mailbox_file"]).decode("utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            fields = line.split(":", 7)
            if len(fields) != 8:
                raise AgentError("PASSWD_FORMAT_UNSUPPORTED", 409)
            address, password, uid, gid, gecos, home, shell, extra = fields
            email(address, self.domains)
            local, domain = address.split("@")
            expected_home = str(mail_root / domain / local)
            if address in addresses or gecos or shell or home != expected_home or uid != str(self.config["mail_uid"]) or gid != str(self.config["mail_gid"]):
                raise AgentError("PASSWD_MAPPING_UNSUPPORTED", 409)
            quota_match = re.fullmatch(r"userdb_quota_rule=\*:bytes=([0-9]+)", extra)
            if not quota_match or not 1048576 <= int(quota_match[1]) <= 1099511627776:
                raise AgentError("QUOTA_MAPPING_UNSUPPORTED", 409)
            state = "disabled" if password.startswith("!") else "active"
            password = password.removeprefix("!")
            if not password.startswith(("{SHA512-CRYPT}$6$", "{BLF-CRYPT}$2")) or any(c in password for c in "\n\r:\x00"):
                raise AgentError("PASSWORD_SCHEME_UNSUPPORTED", 409)
            addresses.add(address)
            users.append((address, password, int(quota_match[1]), state))
        aliases = []
        for line in self._bytes(self.paths["alias_map"]).decode("utf-8").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) != 2:
                raise AgentError("ALIAS_FORMAT_UNSUPPORTED", 409)
            address, target = fields
            email(address, self.domains)
            email(target, self.domains | set(self.config.get("forward_domains", [])))
            if address == target or address in addresses:
                raise AgentError("ALIAS_MAPPING_UNSUPPORTED", 409)
            aliases.append((address, target))
        alias_names = {entry[0] for entry in aliases}
        if len(alias_names) != len(aliases) or any(target in alias_names for _, target in aliases):
            raise AgentError("ALIAS_CHAIN_UNSUPPORTED", 409)
        recipients: set[str] = set()
        for line in self._bytes(self.paths["recipient_map"]).decode("utf-8").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) != 2 or fields[1] != "1":
                raise AgentError("RECIPIENT_MAP_UNSUPPORTED", 409)
            email(fields[0], self.domains)
            recipients.add(fields[0])
        if recipients != addresses:
            raise AgentError("RECIPIENT_MAP_MISMATCH", 409)
        with self.atomic():
            self.db.executemany("INSERT INTO mailbox(address,password_hash,quota,state) VALUES(?,?,?,?)", users)
            self.db.executemany("INSERT INTO alias(address,destination) VALUES(?,?)", aliases)
            self.db.execute("INSERT INTO meta(key,value) VALUES('map_fingerprint',?)", (current,))

    def _version(self, command: list[str]) -> str | None:
        try:
            result = subprocess.run(command, shell=False, capture_output=True, text=True, timeout=4, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
            match = re.search(r"\b[0-9]+\.[0-9]+(?:\.[0-9]+)*\b", result.stdout[:200])
            return match.group(0) if result.returncode == 0 and match else None
        except (OSError, subprocess.TimeoutExpired):
            return None

    def compatible(self) -> dict[str, Any]:
        dovecot = "2.3.lab" if self.lab else self._version(["/usr/sbin/dovecot", "--version"])
        postfix = "lab" if self.lab else self._version(["/usr/sbin/postconf", "-h", "mail_version"])
        supported = self.config.get("adapter") == ADAPTER and self.import_error is None and dovecot is not None and dovecot.startswith("2.3.") and postfix is not None
        reason = self.import_error or ("SUPPORTED_DECLARED_MAPPING" if supported else "UNKNOWN_OR_UNSUPPORTED_INSTALLATION")
        if supported:
            old = self.db.execute("SELECT value FROM meta WHERE key='map_fingerprint'").fetchone()
            try:
                if not old or old[0] != self._fingerprint():
                    supported, reason = False, "EXTERNAL_MAP_DRIFT"
            except AgentError:
                supported, reason = False, "MAP_UNAVAILABLE"
        return {"supported": supported, "adapter": self.config.get("adapter", "inventory"), "dovecotVersion": dovecot, "postfixVersion": postfix, "reason": reason, "mailAccountCommand": "not_adopted", "formatScope": "Dovecot 2.3 declared passwd-file + Postfix texthash only"}

    def write_enabled(self, compatibility: dict[str, Any] | None = None) -> bool:
        compatibility = compatibility or self.compatible()
        if not compatibility["supported"] or not self.config.get("write_enabled", False):
            return False
        if self.lab:
            return True
        fresh_backup = self.db.execute("SELECT count(*) FROM backups WHERE verified_at>?", (int(time.time()) - 86400,)).fetchone()[0]
        return bool(self.config.get("approval_id")) and fresh_backup > 0 and os.geteuid() == int(self.config["mail_uid"])

    def health(self) -> dict[str, Any]:
        compatibility = self.compatible()
        disk = shutil.disk_usage(self.root)
        st = os.statvfs(self.root)
        services = self.services()
        latest = self.db.execute("SELECT id,verified_at FROM backups ORDER BY verified_at DESC LIMIT 1").fetchone()
        return {"version": "0.1.0", "instanceId": self.config["instance_id"], "compatibility": compatibility, "writeEnabled": self.write_enabled(compatibility), "services": services, "disk": {"totalBytes": disk.total, "freeBytes": disk.free, "state": "healthy" if disk.free / disk.total > 0.1 else "degraded", "freeInodes": st.f_favail, "totalInodes": st.f_files, "inodeState": "healthy" if st.f_files and st.f_favail / st.f_files > 0.1 else "unknown"}, "backup": {"state": "healthy" if latest and latest["verified_at"] and latest["verified_at"] > time.time() - 86400 else "unknown", "scope": "configured_node_profiles", "fullRecoveryAccepted": False}, "privacy": "mail bodies and credentials are never returned", "labMode": self.lab}

    def services(self) -> dict[str, str]:
        result = {}
        for service in ("postfix", "dovecot", "opendkim"):
            try:
                proc = subprocess.run(["/usr/bin/systemctl", "is-active", service], shell=False, capture_output=True, text=True, timeout=4, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
                output = proc.stdout.strip()
                result[service] = "healthy" if output == "active" else "failed" if output in {"inactive", "failed"} else "unknown"
            except (OSError, subprocess.TimeoutExpired):
                result[service] = "unknown"
        return result

    def list_mailboxes(self) -> dict[str, Any]:
        if self.import_error or not self.paths:
            return {"items": [], "supported": False, "reason": self.import_error or "INVENTORY_ONLY"}
        rows = self.db.execute("SELECT address,quota,state FROM mailbox ORDER BY address LIMIT 2000").fetchall()
        return {"items": [{"address": row["address"], "quotaBytes": row["quota"], "state": row["state"], "usedBytes": None, "lastLogin": None, "lastFailure": None} for row in rows], "supported": True, "usageTelemetry": "not_configured", "limit": 2000}

    def _atomic_write(self, path: Path, data: bytes, mode: int = 0o640) -> None:
        no_symlinks(path)
        fd, temporary = tempfile.mkstemp(prefix=".astrogate-", dir=path.parent)
        try:
            previous = path.stat() if path.exists() else None
            with os.fdopen(fd, "wb") as target:
                target.write(data)
                os.fchmod(target.fileno(), stat.S_IMODE(previous.st_mode) if previous else mode)
                if previous and os.geteuid() == 0:
                    os.fchown(target.fileno(), previous.st_uid, previous.st_gid)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def _render(self) -> None:
        passwd, recipients, aliases = [], [], []
        for row in self.db.execute("SELECT * FROM mailbox ORDER BY address"):
            local, domain = row["address"].split("@")
            home = no_symlinks(Path(self.config["mail_root"]) / domain / local)
            password = row["password_hash"] if row["state"] == "active" else "!" + row["password_hash"]
            passwd.append(f"{row['address']}:{password}:{self.config['mail_uid']}:{self.config['mail_gid']}::{home}::userdb_quota_rule=*:bytes={row['quota']}\n")
            if row["state"] != "deleted":
                recipients.append(row["address"] + " 1\n")
        for row in self.db.execute("SELECT address,destination FROM alias ORDER BY address"):
            aliases.append(row["address"] + " " + row["destination"] + "\n")
        self._atomic_write(self.paths["mailbox_file"], "".join(passwd).encode())
        self._atomic_write(self.paths["recipient_map"], "".join(recipients).encode())
        self._atomic_write(self.paths["alias_map"], "".join(aliases).encode())
        self.db.execute("UPDATE meta SET value=? WHERE key='map_fingerprint'", (self._fingerprint(),))

    def mutate(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self.write_enabled():
            raise AgentError("NODE_READ_ONLY_OR_INCOMPATIBLE", 409)
        before = {label: self._bytes(path) for label, path in self.paths.items()}
        address = params["address"]
        created_home: Path | None = None
        try:
            with self.atomic():
                if method == "mailbox.create":
                    if self.db.execute("SELECT 1 FROM mailbox WHERE address=?", (address,)).fetchone() or self.db.execute("SELECT 1 FROM alias WHERE address=?", (address,)).fetchone():
                        raise AgentError("MAILBOX_EXISTS", 409)
                    local, domain = address.split("@")
                    home = no_symlinks(Path(self.config["mail_root"]) / domain / local)
                    if home.exists():
                        raise AgentError("MAILBOX_HOME_ALREADY_EXISTS", 409)
                    home.mkdir(parents=True, mode=0o700)
                    created_home = home
                    for name in ("cur", "new", "tmp"):
                        (home / "Maildir" / name).mkdir(parents=True, mode=0o700)
                    self.db.execute("INSERT INTO mailbox(address,password_hash,quota) VALUES(?,?,?)", (address, params["passwordHash"], params["quotaBytes"]))
                elif method.startswith("mailbox."):
                    row = self.db.execute("SELECT * FROM mailbox WHERE address=?", (address,)).fetchone()
                    if row is None:
                        raise AgentError("MAILBOX_NOT_FOUND", 404)
                    if method == "mailbox.disable":
                        self.db.execute("UPDATE mailbox SET state='disabled' WHERE address=?", (address,))
                    elif method == "mailbox.enable":
                        self.db.execute("UPDATE mailbox SET state='active' WHERE address=?", (address,))
                    elif method == "mailbox.soft_delete":
                        self.db.execute("UPDATE mailbox SET state='deleted' WHERE address=?", (address,))
                    elif method == "mailbox.password_reset":
                        self.db.execute("UPDATE mailbox SET password_hash=? WHERE address=?", (params["passwordHash"], address))
                    elif method == "mailbox.quota":
                        self.db.execute("UPDATE mailbox SET quota=? WHERE address=?", (params["quotaBytes"], address))
                    else:
                        raise AgentError("METHOD_NOT_ALLOWED", 403)
                elif method == "alias.create":
                    target = params["destination"]
                    if address == target or self.db.execute("SELECT 1 FROM mailbox WHERE address=?", (address,)).fetchone() or self.db.execute("SELECT 1 FROM alias WHERE address IN (?,?)", (address, target)).fetchone():
                        raise AgentError("ALIAS_COLLISION_OR_LOOP", 409)
                    local_target = target.split("@")[1] in self.domains
                    if local_target and not self.db.execute("SELECT 1 FROM mailbox WHERE address=? AND state='active'", (target,)).fetchone():
                        raise AgentError("ALIAS_TARGET_NOT_ACTIVE", 409)
                    self.db.execute("INSERT INTO alias(address,destination) VALUES(?,?)", (address, target))
                elif method == "alias.delete":
                    self.db.execute("DELETE FROM alias WHERE address=?", (address,))
                else:
                    raise AgentError("METHOD_NOT_ALLOWED", 403)
                self._render()
        except Exception:
            # Best-effort rollback is surfaced as an error if any restore fails. Never report success after a partial write.
            for label, data in before.items():
                if self.paths[label].read_bytes() != data:
                    self._atomic_write(self.paths[label], data)
            if created_home:
                # Only remove directories created by this operation and only while empty; never remove delivered messages.
                for name in ("cur", "new", "tmp"):
                    try:
                        (created_home / "Maildir" / name).rmdir()
                    except OSError:
                        pass
                for path in (created_home / "Maildir", created_home):
                    try:
                        path.rmdir()
                    except OSError:
                        pass
            raise
        if method.startswith("mailbox."):
            row = self.db.execute("SELECT address,state,quota FROM mailbox WHERE address=?", (address,)).fetchone()
            return {"address": address, "state": row["state"], "quotaBytes": row["quota"], "maildirPreserved": True, "authenticationCache": "operator_must_configure_auth_cache_size_0"}
        return {"address": address, "state": "deleted" if method == "alias.delete" else "active"}

    def queue(self) -> dict[str, Any]:
        try:
            proc = subprocess.run(["/usr/sbin/postqueue", "-j"], shell=False, capture_output=True, text=True, timeout=8, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
            if proc.returncode != 0 or len(proc.stdout) > 1024 * 1024:
                raise AgentError("QUEUE_UNAVAILABLE", 503)
            items = []
            for line in proc.stdout.splitlines():
                row = json.loads(line)
                queue_id = row.get("queue_id", "")
                if not re.fullmatch(r"[A-Za-z0-9]{5,32}", queue_id):
                    raise AgentError("QUEUE_FORMAT_UNSUPPORTED", 409)
                # Intentionally exclude sender, recipient, headers, body and untrusted raw diagnostics.
                items.append({"queueId": queue_id, "queueName": str(row.get("queue_name", "unknown"))[:32], "arrivalTime": row.get("arrival_time"), "messageSize": row.get("message_size"), "recipientCount": len(row.get("recipients", []))})
            return {"depth": len(items), "items": items[:100], "state": "healthy" if len(items) < 100 else "degraded", "bodyAvailable": False}
        except AgentError:
            raise
        except Exception as exc:
            raise AgentError("QUEUE_UNAVAILABLE", 503) from exc

    def helper(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self.write_enabled() or not self.config.get("allow_helper", False):
            raise AgentError("HELPER_NOT_AUTHORIZED", 409)
        helper = Path("/usr/local/libexec/astrogate-mail-helper")
        no_symlinks(helper)
        if not helper.is_file() or helper.stat().st_uid != 0 or stat.S_IMODE(helper.stat().st_mode) & 0o022:
            raise AgentError("HELPER_INTEGRITY_INVALID", 409)
        if method == "service.reload_allowlisted":
            args = ["reload", params["service"]]
        else:
            summary = self.queue()
            if params["queueId"] not in {item["queueId"] for item in summary["items"]}:
                raise AgentError("QUEUE_ITEM_NOT_FOUND_OR_OUTSIDE_LIMIT", 409)
            args = ["queue-retry" if method == "mail.queue.retry_allowlisted" else "queue-delete", params["queueId"]]
        try:
            result = subprocess.run(["/usr/bin/sudo", "-n", str(helper), *args], shell=False, capture_output=True, text=True, timeout=12, check=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
            if result.returncode != 0:
                raise AgentError("HELPER_OPERATION_FAILED", 503)
            return {"state": "accepted", "method": method, "delivery": "not_confirmed"}
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AgentError("HELPER_UNAVAILABLE", 503) from exc

    def snapshot_state(self) -> None:
        directory = no_symlinks(self.root / "backup-state")
        directory.mkdir(mode=0o700, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix="snapshot-", dir=directory)
        os.close(fd)
        try:
            target = sqlite3.connect(temporary)
            try:
                self.db.backup(target)
            finally:
                target.close()
            os.replace(temporary, directory / "agent.sqlite")
        finally:
            Path(temporary).unlink(missing_ok=True)
