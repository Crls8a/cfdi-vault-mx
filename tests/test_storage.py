from __future__ import annotations

from datetime import datetime, timezone

from cfdi_vault.storage import LocalStorage, sha256_bytes


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
