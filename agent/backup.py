"""Streaming AES-256-GCM backups and authenticated, bounded, isolated restore drills.

Archive keys and allowed source roots are local installation configuration, never RPC parameters.
No production restore capability is exposed. No plaintext archive is written during backup creation.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import struct
import tarfile
import tempfile
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .errors import AgentError

MAGIC = b"AGMAILBK\x01"
MAX_HEADER = 4096
CHUNK = 1024 * 1024


def safe_id(value: str) -> str:
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, TypeError, AttributeError) as exc:
        raise AgentError("INVALID_ARCHIVE_ID") from exc
    return value


def no_symlinks(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    for item in [path, *path.parents]:
        if item.is_symlink():
            raise AgentError("SYMLINK_PATH_FORBIDDEN")
    return path


class EncryptedSink:
    def __init__(self, destination: io.BufferedWriter, encryptor: Any):
        self.destination = destination
        self.encryptor = encryptor
        self.position = 0

    def write(self, data: bytes) -> int:
        self.destination.write(self.encryptor.update(data))
        self.position += len(data)
        return len(data)

    def tell(self) -> int:
        return self.position

    def flush(self) -> None:
        self.destination.flush()


class BackupStore:
    def __init__(self, config: dict[str, Any], key: bytes):
        if len(key) != 32:
            raise AgentError("BACKUP_KEY_INVALID")
        self.config = config
        self.key = key
        self.instance = config["instance_id"]
        self.root = no_symlinks(Path(config["backup_root"]))
        self.drill_root = no_symlinks(Path(config["drill_root"]))
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.drill_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.limit = int(config.get("max_backup_bytes", 256 * 1024 * 1024))
        self.file_limit = int(config.get("max_backup_files", 20000))
        self.seconds = int(config.get("backup_timeout_seconds", 80))
        if not 1024 <= self.limit <= 2**40 or not 1 <= self.file_limit <= 2000000:
            raise AgentError("BACKUP_LIMIT_INVALID")

    def archive_path(self, archive_id: str) -> Path:
        return no_symlinks(self.root / (safe_id(archive_id) + ".agbackup"))

    def _sources(self) -> list[tuple[str, Path]]:
        sources: list[tuple[str, Path]] = []
        profiles = self.config.get("backup_sources", [])
        if not profiles:
            raise AgentError("BACKUP_SOURCES_NOT_CONFIGURED", 409)
        labels: set[str] = set()
        for profile in profiles:
            label = profile["label"]
            if not isinstance(label, str) or not label.replace("-", "").replace("_", "").isalnum() or label in labels:
                raise AgentError("BACKUP_PROFILE_INVALID")
            labels.add(label)
            source = no_symlinks(Path(profile["path"]))
            if not source.exists():
                raise AgentError("BACKUP_REQUIRED_SOURCE_MISSING", 409)
            if source == self.root or source in self.root.parents or source == self.drill_root or source in self.drill_root.parents:
                raise AgentError("BACKUP_RECURSIVE_SOURCE_FORBIDDEN")
            sources.append((label, source))
        return sources

    def create(self, archive_id: str) -> dict[str, Any]:
        destination = self.archive_path(archive_id)
        if destination.exists():
            return self.verify(archive_id)
        started = time.monotonic()
        manifest: dict[str, Any] = {"version": 1, "instanceId": self.instance, "adapter": self.config["adapter"], "createdAt": int(time.time()), "files": [], "sources": [], "coverage": self.config.get("backup_coverage", "partial_node_profiles")}
        header = {"version": 1, "instanceId": self.instance, "algorithm": "AES-256-GCM", "keyId": self.config.get("backup_key_id", "operator-managed-v1")}
        header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        aad = MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + nonce
        encryptor = Cipher(algorithms.AES(self.key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(aad)
        fd, temporary = tempfile.mkstemp(prefix=".writing-", dir=self.root)
        total = 0
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(aad)
                sink = EncryptedSink(output, encryptor)
                with tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                    for label, root in self._sources():
                        manifest["sources"].append(label)
                        entries = [root] if root.is_file() else sorted(root.rglob("*"))
                        for path in entries:
                            if time.monotonic() - started > self.seconds:
                                raise AgentError("BACKUP_TIME_LIMIT", 409)
                            no_symlinks(path)
                            st = path.lstat()
                            if stat.S_ISDIR(st.st_mode):
                                continue
                            if not stat.S_ISREG(st.st_mode):
                                raise AgentError("BACKUP_SPECIAL_FILE_FORBIDDEN")
                            total += st.st_size
                            if total > self.limit or len(manifest["files"]) >= self.file_limit:
                                raise AgentError("BACKUP_SIZE_LIMIT", 409)
                            relative = path.name if root.is_file() else path.relative_to(root).as_posix()
                            name = label + "/" + relative
                            # Explicitly reject unstable files rather than silently claiming a coherent database dump.
                            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                            with os.fdopen(descriptor, "rb") as source:
                                digest = hashlib.file_digest(source, "sha256").hexdigest()
                                source.seek(0)
                                info = tarfile.TarInfo(name)
                                info.size = st.st_size
                                info.uid, info.gid, info.mode, info.mtime = st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), int(st.st_mtime)
                                archive.addfile(info, source)
                            end = path.stat()
                            if (end.st_size, end.st_mtime_ns, end.st_ino) != (st.st_size, st.st_mtime_ns, st.st_ino):
                                raise AgentError("SOURCE_CHANGED_DURING_BACKUP", 409)
                            manifest["files"].append({"name": name, "size": st.st_size, "sha256": digest, "uid": st.st_uid, "gid": st.st_gid, "mode": stat.S_IMODE(st.st_mode)})
                    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
                    if len(payload) > 32 * 1024 * 1024:
                        raise AgentError("MANIFEST_TOO_LARGE")
                    info = tarfile.TarInfo("manifest.json")
                    info.size, info.mode = len(payload), 0o600
                    archive.addfile(info, io.BytesIO(payload))
                output.write(encryptor.finalize())
                output.write(encryptor.tag)
                output.flush()
                os.fsync(output.fileno())
            # Creation is serialized by the Agent. Exclusive link prevents overwriting an existing archive.
            os.link(temporary, destination)
            os.unlink(temporary)
            return {"archiveId": archive_id, "status": "encrypted", "algorithm": "AES-256-GCM", "files": len(manifest["files"]), "sourceBytes": total, "archiveBytes": destination.stat().st_size, "coverage": manifest["coverage"], "scope": manifest["sources"], "sha256": self._digest(destination), "verified": False, "productionRestore": "not_performed"}
        except Exception:
            Path(temporary).unlink(missing_ok=True)
            raise

    def _digest(self, path: Path) -> str:
        with path.open("rb") as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()

    def _decrypt(self, archive_id: str):
        """Returns an authenticated private temporary tar, never partially authenticated content."""
        path = self.archive_path(archive_id)
        if not path.is_file() or path.stat().st_size > self.limit + self.file_limit * 4096 + 40 * 1024 * 1024:
            raise AgentError("ARCHIVE_MISSING_OR_TOO_LARGE", 409)
        temporary = tempfile.TemporaryFile(mode="w+b", dir=self.root)
        try:
            with path.open("rb") as source:
                if source.read(len(MAGIC)) != MAGIC:
                    raise AgentError("ARCHIVE_VERSION_INVALID", 409)
                encoded_length = source.read(4)
                if len(encoded_length) != 4:
                    raise AgentError("ARCHIVE_TRUNCATED", 409)
                size = struct.unpack(">I", encoded_length)[0]
                if not 1 <= size <= MAX_HEADER:
                    raise AgentError("ARCHIVE_HEADER_INVALID", 409)
                header_bytes = source.read(size)
                header = json.loads(header_bytes)
                nonce = source.read(12)
                if len(nonce) != 12 or header.get("version") != 1 or header.get("algorithm") != "AES-256-GCM" or header.get("instanceId") != self.instance:
                    raise AgentError("ARCHIVE_INSTANCE_OR_VERSION_MISMATCH", 409)
                start = source.tell()
                source.seek(-16, os.SEEK_END)
                tag = source.read(16)
                remaining = source.tell() - 16 - start
                if remaining < 0:
                    raise AgentError("ARCHIVE_TRUNCATED", 409)
                decryptor = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag)).decryptor()
                decryptor.authenticate_additional_data(MAGIC + encoded_length + header_bytes + nonce)
                source.seek(start)
                while remaining:
                    block = source.read(min(CHUNK, remaining))
                    if not block:
                        raise AgentError("ARCHIVE_TRUNCATED", 409)
                    temporary.write(decryptor.update(block))
                    remaining -= len(block)
                temporary.write(decryptor.finalize())
            temporary.seek(0)
            return temporary
        except Exception as exc:
            temporary.close()
            if isinstance(exc, AgentError):
                raise
            raise AgentError("ARCHIVE_AUTHENTICATION_FAILED", 409) from exc

    def _inspect(self, temporary) -> tuple[dict[str, Any], list[tarfile.TarInfo]]:
        total = 0
        names: set[str] = set()
        members: list[tarfile.TarInfo] = []
        try:
            with tarfile.open(fileobj=temporary, mode="r:") as archive:
                for info in archive:
                    name = PurePosixPath(info.name)
                    if not info.isfile() or name.is_absolute() or ".." in name.parts or "\\" in info.name or "\x00" in info.name or info.name in names or info.size < 0:
                        raise AgentError("UNSAFE_ARCHIVE_MEMBER", 409)
                    if str(name) != info.name or len(info.name) > 512:
                        raise AgentError("UNSAFE_ARCHIVE_MEMBER", 409)
                    names.add(info.name)
                    total += info.size
                    if total > self.limit + 32 * 1024 * 1024 or len(names) > self.file_limit + 1:
                        raise AgentError("ARCHIVE_EXPANSION_LIMIT", 409)
                    members.append(info)
                meta = archive.getmember("manifest.json")
                if meta.size > 32 * 1024 * 1024:
                    raise AgentError("MANIFEST_TOO_LARGE", 409)
                manifest = json.load(archive.extractfile(meta))
                if manifest.get("version") != 1 or manifest.get("adapter") != self.config["adapter"] or manifest.get("instanceId") != self.instance:
                    raise AgentError("RESTORE_COMPATIBILITY_FAILED", 409)
                entries = manifest["files"]
                if len(entries) != len(names) - 1 or {entry["name"] for entry in entries} != names - {"manifest.json"}:
                    raise AgentError("MANIFEST_CONTENT_MISMATCH", 409)
                for entry in entries:
                    info = archive.getmember(entry["name"])
                    if (info.size, info.uid, info.gid, info.mode) != (entry["size"], entry["uid"], entry["gid"], entry["mode"]):
                        raise AgentError("MANIFEST_METADATA_MISMATCH", 409)
                    with archive.extractfile(info) as content:
                        if hashlib.file_digest(content, "sha256").hexdigest() != entry["sha256"]:
                            raise AgentError("ARCHIVE_CHECKSUM_FAILED", 409)
                return manifest, members
        except AgentError:
            raise
        except Exception as exc:
            raise AgentError("ARCHIVE_MANIFEST_INVALID", 409) from exc
        finally:
            temporary.seek(0)

    def verify(self, archive_id: str) -> dict[str, Any]:
        with self._decrypt(archive_id) as temporary:
            manifest, _ = self._inspect(temporary)
        return {"archiveId": archive_id, "verified": True, "status": "verified", "files": len(manifest["files"]), "scope": manifest["sources"], "coverage": manifest["coverage"], "sha256": self._digest(self.archive_path(archive_id)), "productionRestore": "not_performed"}

    def restore_drill(self, archive_id: str, drill_id: str) -> dict[str, Any]:
        safe_id(drill_id)
        destination = no_symlinks(self.drill_root / drill_id)
        if destination.exists():
            raise AgentError("DRILL_DESTINATION_EXISTS", 409)
        # Authentication, manifest and all checksums must pass before any extraction begins.
        with self._decrypt(archive_id) as temporary:
            manifest, _ = self._inspect(temporary)
            destination.mkdir(mode=0o700)
            try:
                with tarfile.open(fileobj=temporary, mode="r:") as archive:
                    for entry in manifest["files"]:
                        target = destination.joinpath(*PurePosixPath(entry["name"]).parts)
                        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                        with os.fdopen(descriptor, "wb") as out, archive.extractfile(entry["name"]) as content:
                            shutil.copyfileobj(content, out, CHUNK)
                    report = {"archiveId": archive_id, "drillId": drill_id, "status": "verified_isolated_files", "files": len(manifest["files"]), "uidGidInventory": sorted({(e["uid"], e["gid"]) for e in manifest["files"]}), "sourceUntouched": True, "servicesRestarted": False, "dnsChanged": False, "databaseMigrationsTested": False, "certificateRenewalTested": False, "dkimSigningTested": False, "coverage": manifest["coverage"], "warning": "This is file integrity/extraction validation, NOT a full mail-service recovery acceptance test."}
                    (destination / "drill-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
                return report
            except Exception:
                shutil.rmtree(destination)
                raise
