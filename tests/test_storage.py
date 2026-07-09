from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cfdi_vault.storage import LocalStorage, sha256_bytes
from cfdi_vault.storage_contract import (
    EvidenceReference,
    StorageCollisionError,
    StorageIOError,
    StorageKey,
    StorageNotFoundError,
)


def test_local_storage_builds_rfc_period_layout_and_writes_idempotently(tmp_path) -> None:
    storage = LocalStorage(tmp_path / "storage")
    period = datetime(2024, 1, 15, 12, 0, tzinfo=timezone.utc)
    content = b"synthetic package bytes"
    digest = sha256_bytes(content)

    key = storage.package_key("xaxx010101000", period, "PKG-DUMMY", digest)
    first = storage.write_bytes_idempotent(key, content)
    second = storage.write_bytes_idempotent(key, content)

    expected = (
        tmp_path
        / "storage"
        / "XAXX010101000"
        / "packages"
        / "2024"
        / "01"
        / f"PKG-DUMMY-{digest[:12]}.zip"
    )
    assert first.path == expected
    assert first.sha256 == digest
    assert first.size_bytes == len(content)
    assert first.written is True
    assert second.path == expected
    assert second.written is False
    assert (tmp_path / "storage" / "XAXX010101000" / "metadata" / "2024" / "01").is_dir()
    assert (tmp_path / "storage" / "XAXX010101000" / "logs").is_dir()
    assert (tmp_path / "storage" / "XAXX010101000" / "db").is_dir()


def test_local_storage_write_read_and_stat_share_one_stable_reference(tmp_path) -> None:
    storage = LocalStorage(tmp_path / "storage")
    content = b"synthetic XML-like evidence"
    digest = sha256_bytes(content)
    key = StorageKey.xml("XAXX010101000", datetime(2024, 1, 15), "SYN-UUID", digest)

    stored = storage.write_bytes_idempotent(key, content)

    assert stored.reference == EvidenceReference(key=key, sha256=digest, size_bytes=len(content))
    assert stored.reference.as_dict() == {
        "storage_key": str(key),
        "sha256": digest,
        "size_bytes": len(content),
    }
    assert storage.read_bytes(key) == content
    assert storage.stat(key) == stored.reference


def test_local_storage_refuses_a_hash_key_collision_without_mutating_evidence(tmp_path) -> None:
    storage = LocalStorage(tmp_path / "storage")
    first = b"first"
    digest = sha256_bytes(first)
    key = StorageKey.xml("XAXX010101000", datetime(2024, 1, 15), "SYNTHETIC", digest)
    storage.write_bytes_idempotent(key, first)

    with pytest.raises(StorageCollisionError, match="storage write collision") as caught:
        storage.write_bytes_idempotent(key, b"second")

    assert caught.value.key == key
    assert str(key) not in str(caught.value)
    assert str(storage.root.resolve()) not in str(caught.value)
    assert storage.read_bytes(key) == first


def test_local_storage_rejects_traversal_before_read_write_or_stat(tmp_path) -> None:
    storage = LocalStorage(tmp_path / "storage")

    for operation in (
        lambda: storage.write_bytes_idempotent("../outside.xml", b"blocked"),
        lambda: storage.read_bytes("../outside.xml"),
        lambda: storage.stat("../outside.xml"),
    ):
        with pytest.raises(ValueError, match="storage key"):
            operation()

    assert not (tmp_path / "outside.xml").exists()


@pytest.mark.parametrize("operation", ["read", "stat"])
def test_missing_evidence_raises_adapter_neutral_error(operation: str, tmp_path) -> None:
    storage = LocalStorage(tmp_path / "private-root")
    key = StorageKey.parse("XAXX010101000/xml/2024/01/MISSING.xml")

    with pytest.raises(StorageNotFoundError, match=f"storage {operation} not found") as caught:
        getattr(storage, f"{operation}_bytes" if operation == "read" else operation)(key)

    assert caught.value.key == key
    assert str(key) not in str(caught.value)
    assert caught.value.operation == operation
    assert str(storage.root.resolve()) not in str(caught.value)


@pytest.mark.parametrize("operation", ["write", "read", "stat"])
def test_filesystem_io_errors_do_not_expose_adapter_paths(operation: str, tmp_path, monkeypatch) -> None:
    storage = LocalStorage(tmp_path / "private-root")
    key = StorageKey.parse("XAXX010101000/xml/2024/01/SYNTHETIC.xml")
    method = "write_bytes" if operation == "write" else "read_bytes"
    monkeypatch.setattr(
        "pathlib.Path." + method,
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError(f"failure at {storage.root.resolve()}")),
    )

    with pytest.raises(StorageIOError, match=f"storage {operation} failed") as caught:
        if operation == "write":
            storage.write_bytes_idempotent(key, b"synthetic")
        else:
            getattr(storage, "read_bytes" if operation == "read" else operation)(key)

    assert caught.value.key == key
    assert str(key) not in str(caught.value)
    assert caught.value.operation == operation
    assert str(storage.root.resolve()) not in str(caught.value)


@pytest.mark.parametrize("alias_kind", ["component", "extension"])
def test_case_insensitive_key_aliases_are_rejected_on_every_filesystem(alias_kind: str, tmp_path) -> None:
    storage = LocalStorage(tmp_path / "storage")
    key = StorageKey.parse("XAXX010101000/xml/2024/01/SYNTHETIC.xml")
    storage.write_bytes_idempotent(key, b"first")
    alias = StorageKey.parse(
        str(key).replace("XAXX010101000", "xaxx010101000")
        if alias_kind == "component"
        else str(key).replace(".xml", ".XML")
    )

    with pytest.raises(StorageCollisionError, match="storage resolve case-insensitive alias") as caught:
        storage.write_bytes_idempotent(alias, b"second")

    assert caught.value.key == alias
    assert str(alias) not in str(caught.value)
    assert storage.read_bytes(key) == b"first"
