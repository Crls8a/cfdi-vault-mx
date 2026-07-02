from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.package_processor import (
    MemoryPackageStorage,
    PackageProcessingError,
    process_sat_package,
)
from cfdi_vault.sat_auth import SatAuthSessionManager
from cfdi_vault.sat_orchestration import DownloadRequestOrchestrator
from cfdi_vault.sat_simulator import FakeSatScenarioClient


def _zip(entries: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    rewrites: list[tuple[bytes, bytes]] = []
    with ZipFile(buffer, "w", ZIP_DEFLATED) as package:
        for name, content in entries.items():
            zip_name = name.replace("\\", "/")
            if zip_name != name:
                rewrites.append((zip_name.encode(), name.encode()))
            package.writestr(zip_name, content)
    data = buffer.getvalue()
    for safe_name, raw_name in rewrites:
        data = data.replace(safe_name, raw_name)
    return data


def test_valid_synthetic_zip_stores_package_and_extracts_xml_txt_idempotently() -> None:
    storage = MemoryPackageStorage()
    content = _zip(
        {
            "evidence.xml": b"<SyntheticEvidence>ok</SyntheticEvidence>\n",
            "metadata.txt": b"status=synthetic\n",
        }
    )

    first = process_sat_package("SYN-PKG-001", content, storage)
    second = process_sat_package("SYN-PKG-001", content, storage)

    assert first.package_written is True
    assert second.package_written is False
    assert first.sha256 == second.sha256
    assert [entry.name for entry in first.entries] == ["evidence.xml", "metadata.txt"]
    assert [entry.kind for entry in first.entries] == ["xml", "txt"]
    assert all(entry.written for entry in first.entries)
    assert not any(entry.written for entry in second.entries)
    assert first.package_storage_key in storage.objects
    assert {entry.storage_key for entry in first.entries} <= set(storage.objects)


def test_invalid_zip_fails_safely_without_writes() -> None:
    storage = MemoryPackageStorage()

    with pytest.raises(PackageProcessingError, match="invalid ZIP"):
        process_sat_package("SYN-PKG-001", b"not a zip", storage)

    assert storage.objects == {}


@pytest.mark.parametrize(
    "unsafe_name",
    ["../evil.xml", "/abs.xml", "nested/../../evil.xml", "nested\\evil.xml"],
)
def test_traversal_variants_are_blocked_without_writes(unsafe_name: str) -> None:
    storage = MemoryPackageStorage()

    with pytest.raises(PackageProcessingError):
        process_sat_package("SYN-PKG-001", _zip({unsafe_name: b"synthetic"}), storage)

    assert storage.objects == {}


def test_unsupported_extension_rejected_without_writes() -> None:
    storage = MemoryPackageStorage()

    with pytest.raises(PackageProcessingError, match="unsupported"):
        process_sat_package("SYN-PKG-001", _zip({"payload.json": b"{}"}), storage)

    assert storage.objects == {}


def test_duplicate_normalized_entry_paths_are_rejected_without_writes() -> None:
    storage = MemoryPackageStorage()

    with pytest.raises(PackageProcessingError, match="duplicate"):
        process_sat_package(
            "SYN-PKG-001",
            _zip({"nested/evidence.xml": b"one", "NESTED/evidence.xml": b"two"}),
            storage,
        )

    assert storage.objects == {}


def test_memory_storage_rejects_same_key_with_different_bytes() -> None:
    storage = MemoryPackageStorage()

    first = storage.write_bytes_idempotent("same/key.xml", b"one")
    second = storage.write_bytes_idempotent("same/key.xml", b"one")

    assert first.written is True
    assert second.written is False
    with pytest.raises(ValueError, match="storage collision"):
        storage.write_bytes_idempotent("same/key.xml", b"two")


def test_fake_sat_download_can_be_processed_offline() -> None:
    storage = MemoryPackageStorage()
    download = FakeSatScenarioClient().download_package("SYN-PKG-001")

    assert download.content is not None
    result = process_sat_package(download.package_id, download.content, storage)

    assert result.package_id == "SYN-PKG-001"
    assert [entry.name for entry in result.entries] == ["metadata.txt", "synthetic.xml"]
    assert all(entry.storage_key.startswith("sat-packages/SYN-PKG-001-") for entry in result.entries)


def test_fake_download_pipeline_alpha_reaches_safe_storage_offline() -> None:
    client = FakeSatScenarioClient(package_count=1)
    storage = MemoryPackageStorage()
    query = DownloadQuery(
        tenant_id="default",
        requester_rfc="XAXX010101000",
        direction=DownloadDirection.RECEIVED,
        request_type=RequestType.CFDI,
        period=DateTimePeriod(
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        ),
        issuer_rfc="AAA010101AAA",
    )

    session = SatAuthSessionManager(client, clock=lambda: datetime(2026, 7, 2, tzinfo=timezone.utc)).authenticate()
    orchestrator = DownloadRequestOrchestrator(requester=client, verifier=client)
    submitted = orchestrator.submit_once(query)
    verified = orchestrator.poll_once(submitted.request_id)
    package = client.download_package(verified.package_ids[0])
    assert package.content is not None

    result = process_sat_package(package.package_id, package.content, storage)

    assert session.authorization == "SYNTHETIC_AUTHORIZATION"
    assert submitted.request_id.startswith("SYN-REQ-")
    assert verified.package_ids == ("SYN-PKG-001",)
    assert result.package_storage_key in storage.objects
    assert [entry.name for entry in result.entries] == ["metadata.txt", "synthetic.xml"]
    assert all(entry.storage_key in storage.objects for entry in result.entries)
