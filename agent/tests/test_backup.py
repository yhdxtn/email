import io
import json
import os
from pathlib import Path
import struct
import tarfile
import uuid
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from agent.backup import BackupStore, MAGIC
from agent.errors import AgentError
from .conftest import call


def sample(agent):
    data = Path(agent.config["mail_root"]) / "a-message"
    data.write_text("private-example-mail-content-123456")
    archive_id = str(uuid.uuid4())
    result = call(agent, "backup.create", {"archiveId": archive_id})
    return data, archive_id, result


def test_encryption_verify_and_isolated_restore(agent):
    data, archive_id, result = sample(agent)
    path = agent.backup.archive_path(archive_id)
    assert data.read_bytes() not in path.read_bytes()
    assert b"manifest.json" not in path.read_bytes()
    assert result["verified"] is False
    verified = call(agent, "backup.verify", {"archiveId": archive_id})
    assert verified["verified"] is True
    drill = str(uuid.uuid4())
    result = call(agent, "backup.restore_drill", {"archiveId": archive_id, "drillId": drill})
    assert result["sourceUntouched"] is True
    assert result["databaseMigrationsTested"] is False
    restored = Path(agent.config["drill_root"]) / drill / "maildir/a-message"
    assert restored.read_bytes() == data.read_bytes()
    assert data.read_text() == "private-example-mail-content-123456"


@pytest.mark.parametrize("offset", [-1, -20, 100])
def test_corrupted_archive_rejected_before_extract(agent, offset):
    _, archive_id, _ = sample(agent)
    path = agent.backup.archive_path(archive_id)
    raw = bytearray(path.read_bytes())
    raw[offset] ^= 1
    path.write_bytes(raw)
    drill = str(uuid.uuid4())
    with pytest.raises(AgentError):
        call(agent, "backup.restore_drill", {"archiveId": archive_id, "drillId": drill})
    assert not (Path(agent.config["drill_root"]) / drill).exists()


def test_wrong_key_rejected(agent):
    _, archive_id, _ = sample(agent)
    store = BackupStore(agent.config, os.urandom(32))
    with pytest.raises(AgentError, match="ARCHIVE_AUTHENTICATION_FAILED"):
        store.verify(archive_id)


def test_archive_id_is_not_path(agent):
    with pytest.raises(AgentError, match="INVALID_ARCHIVE_ID"):
        agent.backup.archive_path("../../etc/shadow")


def test_backup_source_symlink_rejected(agent, tmp_path):
    (Path(agent.config["mail_root"]) / "symlink").symlink_to(tmp_path / "secret-outside")
    with pytest.raises(AgentError, match="SYMLINK"):
        call(agent, "backup.create", {"archiveId": str(uuid.uuid4())})


def test_limits_enforced(agent):
    agent.backup.limit = 1024
    (Path(agent.config["mail_root"]) / "large").write_bytes(b"x" * 2048)
    with pytest.raises(AgentError, match="BACKUP_SIZE_LIMIT"):
        call(agent, "backup.create", {"archiveId": str(uuid.uuid4())})
    assert not list(Path(agent.config["backup_root"]).glob("*.agbackup"))


def test_drill_refuses_existing_destination(agent):
    _, archive_id, _ = sample(agent)
    drill = str(uuid.uuid4())
    directory = Path(agent.config["drill_root"]) / drill
    directory.mkdir()
    with pytest.raises(AgentError, match="DRILL_DESTINATION_EXISTS"):
        agent.backup.restore_drill(archive_id, drill)


def encrypted_tar(agent, archive_id, members):
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode="w") as tar:
        for info, content in members:
            tar.addfile(info, io.BytesIO(content) if content is not None else None)
    header = json.dumps({"version": 1, "instanceId": agent.config["instance_id"], "algorithm": "AES-256-GCM"}).encode()
    nonce = os.urandom(12)
    aad = MAGIC + struct.pack(">I", len(header)) + header + nonce
    encryptor = Cipher(algorithms.AES(agent.backup.key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(aad)
    cipher = encryptor.update(raw_tar.getvalue()) + encryptor.finalize()
    agent.backup.archive_path(archive_id).write_bytes(aad + cipher + encryptor.tag)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "x/../../escape", "x\\escape", "./a"])
def test_authenticated_path_traversal_rejected(agent, name):
    info = tarfile.TarInfo(name)
    info.size = 1
    archive_id = str(uuid.uuid4())
    encrypted_tar(agent, archive_id, [(info, b"x")])
    with pytest.raises(AgentError, match="UNSAFE_ARCHIVE_MEMBER"):
        agent.backup.restore_drill(archive_id, str(uuid.uuid4()))


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE])
def test_authenticated_special_files_rejected(agent, kind):
    info = tarfile.TarInfo("unsafe")
    info.type, info.linkname = kind, "../../outside"
    archive_id = str(uuid.uuid4())
    encrypted_tar(agent, archive_id, [(info, None)])
    with pytest.raises(AgentError, match="UNSAFE_ARCHIVE_MEMBER"):
        agent.backup.verify(archive_id)
