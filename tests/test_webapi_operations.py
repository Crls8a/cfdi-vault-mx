from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cfdi_vault.adapters.webapi import app as subject
from cfdi_vault.adapters.webapi.config import WebApiSettings
from cfdi_vault.config import ConfigValidationError
from cfdi_vault.service import ImportBatchResult, ImportRecord, SummaryRow, VaultSummary

ALLOWED_ORIGIN = "http://127.0.0.1:3000"


def _settings(tmp_path: Path) -> WebApiSettings:
    environment = {
        "DATABASE_URL": "postgresql://synthetic:synthetic@localhost/synthetic",
        "CFDI_STORAGE_ROOT": str(tmp_path / "storage"),
    }
    return WebApiSettings.resolve(environment=environment, repository_root=tmp_path / "repo")


def _client(tmp_path: Path) -> TestClient:
    return TestClient(subject.create_app(_settings(tmp_path)))


class _FakeRecoveryService:
    """Stand-in for ``RecoveryService`` capturing the calls each handler makes."""

    def __init__(self) -> None:
        self.closed = False
        self.calls: list[tuple[object, ...]] = []

    def init_tenant(self, tenant_id: str, rfc: str, name: str | None) -> None:
        self.calls.append(("init_tenant", tenant_id, rfc, name))

    def reconcile(self, *, tenant_id: str | None = None) -> int:
        self.calls.append(("reconcile", tenant_id))
        return 3

    def search(self, text: str, *, tenant_id: str | None = None, limit: int = 20) -> tuple[dict[str, object], ...]:
        self.calls.append(("search", text, tenant_id, limit))
        return ({"uuid": "abc-123", "issuer_rfc": "AAA010101AAA"},)

    def render_text(self, uuid: str, *, tenant_id: str | None = None) -> str:
        self.calls.append(("render_text", uuid, tenant_id))
        if uuid == "missing-uuid":
            raise LookupError(f"CFDI not found: {uuid}")
        return f"text-for-{uuid}"

    def render_html(self, uuid: str, *, tenant_id: str | None = None) -> str:
        self.calls.append(("render_html", uuid, tenant_id))
        return f"<html>{uuid}</html>"

    def export_csv(self, output_path: str | Path, *, tenant_id: str | None = None) -> int:
        self.calls.append(("export_csv", str(output_path), tenant_id))
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("uuid\n", encoding="utf-8")
        return 5

    def close(self) -> None:
        self.closed = True


class _FakeEngine:
    """Stand-in for the SQLAlchemy engine ``VaultService`` never closes itself."""

    def __init__(self) -> None:
        self.disposed = False

    def dispose(self) -> None:
        self.disposed = True


class _FakeVaultService:
    """Stand-in for ``VaultService`` capturing the calls each handler makes."""

    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.import_xml_result: ImportRecord | None = None
        self.import_zip_result: ImportBatchResult | None = None
        self.summary_result: VaultSummary | None = None
        self.engine = _FakeEngine()

    def import_xml_file(self, xml_path: str | Path) -> ImportRecord:
        self.calls.append(("import_xml_file", str(xml_path)))
        assert self.import_xml_result is not None
        return self.import_xml_result

    def import_zip_file(self, zip_path: str | Path) -> ImportBatchResult:
        self.calls.append(("import_zip_file", str(zip_path)))
        assert self.import_zip_result is not None
        return self.import_zip_result

    def summary(self) -> VaultSummary:
        self.calls.append(("summary",))
        assert self.summary_result is not None
        return self.summary_result

    def export_csv(self, output_path: str | Path) -> int:
        self.calls.append(("export_csv", str(output_path)))
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("uuid\n", encoding="utf-8")
        return 7


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def test_operations_init_endpoint_delegates_to_recovery_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeRecoveryService()
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).post(
        "/api/operations/init",
        json={"tenant_id": "tenant-a", "rfc": "aaa010101aaa", "name": "Tenant A"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json() == {"tenant_id": "tenant-a", "rfc": "AAA010101AAA"}
    assert service.calls == [("init_tenant", "tenant-a", "aaa010101aaa", "Tenant A")]
    assert service.closed is True


def test_operations_init_endpoint_maps_construction_failure_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(database_url: str, storage: Path) -> _FakeRecoveryService:
        raise RuntimeError("PostgreSQL DATABASE_URL is required.")

    monkeypatch.setattr(subject, "_recovery_service", fail)
    response = _client(tmp_path).post(
        "/api/operations/init",
        json={"rfc": "aaa010101aaa"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "operations-database-unavailable"}}


# ---------------------------------------------------------------------------
# reconcile
# ---------------------------------------------------------------------------


def test_operations_reconcile_endpoint_returns_updated_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeRecoveryService()
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).post(
        "/api/operations/reconcile", json={"tenant_id": "tenant-a"}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json() == {"updated_count": 3}
    assert service.calls == [("reconcile", "tenant-a")]
    assert service.closed is True


def test_operations_reconcile_endpoint_maps_construction_failure_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subject, "_recovery_service",
        lambda database_url, storage: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    response = _client(tmp_path).post(
        "/api/operations/reconcile", json={}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "operations-database-unavailable"}}


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------


def test_operations_search_endpoint_returns_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _FakeRecoveryService()
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).get(
        "/api/operations/search", params={"text": "abc", "tenant_id": "tenant-a", "limit": 5},
    )
    assert response.status_code == 200
    assert response.json() == [{"uuid": "abc-123", "issuer_rfc": "AAA010101AAA"}]
    assert service.calls == [("search", "abc", "tenant-a", 5)]
    assert service.closed is True


def test_operations_search_endpoint_maps_construction_failure_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subject, "_recovery_service",
        lambda database_url, storage: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    response = _client(tmp_path).get("/api/operations/search")
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "operations-database-unavailable"}}


# ---------------------------------------------------------------------------
# cfdi show
# ---------------------------------------------------------------------------


def test_operations_cfdi_endpoint_returns_rendered_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeRecoveryService()
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).get("/api/operations/cfdi/abc-123", params={"tenant_id": "tenant-a"})
    assert response.status_code == 200
    assert response.json() == {"uuid": "abc-123", "text": "text-for-abc-123"}
    assert service.closed is True


def test_operations_cfdi_endpoint_maps_missing_uuid_to_404(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeRecoveryService()
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).get("/api/operations/cfdi/missing-uuid")
    assert response.status_code == 404
    assert response.json() == {"detail": {"reason": "cfdi-not-found"}}
    assert service.closed is True


# ---------------------------------------------------------------------------
# print
# ---------------------------------------------------------------------------


def test_operations_print_endpoint_returns_text_without_output_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeRecoveryService()
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).post(
        "/api/operations/print", json={"uuid": "abc-123"}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json() == {
        "uuid": "abc-123", "format": "text", "output_path": None, "text": "text-for-abc-123",
    }


def test_operations_print_endpoint_writes_text_to_output_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeRecoveryService()
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    output_path = tmp_path / "out" / "abc-123.txt"
    response = _client(tmp_path).post(
        "/api/operations/print",
        json={"uuid": "abc-123", "output_path": str(output_path)},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["output_path"] == str(output_path)
    assert body["text"] is None
    assert output_path.read_text(encoding="utf-8") == "text-for-abc-123"


def test_operations_print_endpoint_writes_pdf_to_default_export_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeRecoveryService()
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).post(
        "/api/operations/print",
        json={"uuid": "abc-123", "format": "pdf"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    body = response.json()
    expected_path = tmp_path / "storage" / "exports" / "abc-123.pdf"
    assert body["output_path"] == str(expected_path)
    assert expected_path.is_file()


def test_operations_print_endpoint_maps_invalid_format_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeRecoveryService()
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).post(
        "/api/operations/print",
        json={"uuid": "abc-123", "format": "docx"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "operations-print-failed"}}
    assert service.closed is True


def test_operations_print_endpoint_maps_missing_uuid_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeRecoveryService()
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).post(
        "/api/operations/print",
        json={"uuid": "missing-uuid"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "operations-print-failed"}}


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


def test_operations_export_endpoint_uses_default_output_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeRecoveryService()
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).post(
        "/api/operations/export", json={}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    expected_path = tmp_path / "storage" / "exports" / "cfdi.csv"
    assert response.json() == {"output_path": str(expected_path), "exported_count": 5}
    assert expected_path.is_file()


def test_operations_export_endpoint_maps_construction_failure_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subject, "_recovery_service",
        lambda database_url, storage: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    response = _client(tmp_path).post(
        "/api/operations/export", json={}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "operations-database-unavailable"}}


# ---------------------------------------------------------------------------
# import-xml
# ---------------------------------------------------------------------------


def test_operations_import_xml_endpoint_returns_import_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    xml_path = tmp_path / "invoice.xml"
    xml_path.write_text("<xml/>", encoding="utf-8")
    service = _FakeVaultService()
    service.import_xml_result = ImportRecord(
        source_name="invoice.xml", uuid="abc-123", imported=True, duplicate=False, xml_sha256="deadbeef",
    )
    monkeypatch.setattr(subject, "VaultService", lambda database_url: service)
    response = _client(tmp_path).post(
        "/api/operations/import-xml", json={"xml_path": str(xml_path)}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json() == {
        "source_name": "invoice.xml", "uuid": "abc-123", "imported": True,
        "duplicate": False, "xml_sha256": "deadbeef", "error": None,
    }
    # VaultService opens its own engine per instance and has no context-manager
    # protocol; a long-lived server process must dispose it explicitly or leak
    # a connection on every call, unlike the short-lived CLI process.
    assert service.engine.disposed is True


def test_operations_import_xml_endpoint_rejects_missing_path_without_touching_vault_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def fail_if_called(database_url: str) -> _FakeVaultService:
        nonlocal called
        called = True
        return _FakeVaultService()

    monkeypatch.setattr(subject, "VaultService", fail_if_called)
    response = _client(tmp_path).post(
        "/api/operations/import-xml",
        json={"xml_path": str(tmp_path / "does-not-exist.xml")},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "operations-xml-path-invalid"}}
    assert called is False


def test_operations_import_xml_endpoint_maps_parse_error_to_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    xml_path = tmp_path / "invoice.xml"
    xml_path.write_text("<xml/>", encoding="utf-8")
    service = _FakeVaultService()
    service.import_xml_result = ImportRecord(
        source_name="invoice.xml", uuid=None, imported=False, duplicate=False,
        xml_sha256="deadbeef", error="not a CFDI document",
    )
    monkeypatch.setattr(subject, "VaultService", lambda database_url: service)
    response = _client(tmp_path).post(
        "/api/operations/import-xml", json={"xml_path": str(xml_path)}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "not a CFDI document"}}


# ---------------------------------------------------------------------------
# import-zip
# ---------------------------------------------------------------------------


def test_operations_import_zip_endpoint_returns_batch_counts_even_with_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    zip_path = tmp_path / "batch.zip"
    zip_path.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    service = _FakeVaultService()
    service.import_zip_result = ImportBatchResult(
        records=(
            ImportRecord(source_name="a.xml", uuid="a", imported=True, duplicate=False, xml_sha256="s1"),
            ImportRecord(
                source_name="b.xml", uuid=None, imported=False, duplicate=False,
                xml_sha256="s2", error="bad xml",
            ),
        )
    )
    monkeypatch.setattr(subject, "VaultService", lambda database_url: service)
    response = _client(tmp_path).post(
        "/api/operations/import-zip", json={"zip_path": str(zip_path)}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total_files"] == 2
    assert body["imported"] == 1
    assert body["duplicates"] == 0
    assert body["failed"] == 1
    assert len(body["records"]) == 2
    assert service.engine.disposed is True


def test_operations_import_zip_endpoint_rejects_missing_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _client(tmp_path).post(
        "/api/operations/import-zip",
        json={"zip_path": str(tmp_path / "does-not-exist.zip")},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "operations-zip-path-invalid"}}


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------


def test_operations_summary_endpoint_returns_three_sections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from decimal import Decimal

    service = _FakeVaultService()
    service.summary_result = VaultSummary(
        by_month=(SummaryRow(label="2026-01", count=2, subtotal=Decimal("100.00"), total=Decimal("116.00")),),
        by_issuer=(),
        by_comprobante_type=(),
    )
    monkeypatch.setattr(subject, "VaultService", lambda database_url: service)
    response = _client(tmp_path).get("/api/operations/summary")
    assert response.status_code == 200
    body = response.json()
    assert body["by_month"] == [{"label": "2026-01", "count": 2, "subtotal": "100.00", "total": "116.00"}]
    assert body["by_issuer"] == []
    assert body["by_comprobante_type"] == []
    assert service.engine.disposed is True


def test_operations_summary_endpoint_maps_construction_failure_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(database_url: str) -> _FakeVaultService:
        raise RuntimeError("boom")

    monkeypatch.setattr(subject, "VaultService", fail)
    response = _client(tmp_path).get("/api/operations/summary")
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "operations-database-unavailable"}}


# ---------------------------------------------------------------------------
# export-csv
# ---------------------------------------------------------------------------


def test_operations_export_csv_endpoint_requires_explicit_output_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeVaultService()
    monkeypatch.setattr(subject, "VaultService", lambda database_url: service)
    output_path = tmp_path / "custom" / "cfdi.csv"
    response = _client(tmp_path).post(
        "/api/operations/export-csv",
        json={"output_path": str(output_path)},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json() == {"output_path": str(output_path), "exported_count": 7}
    assert output_path.is_file()
    assert service.engine.disposed is True


def test_operations_export_csv_endpoint_rejects_missing_body_field(tmp_path: Path) -> None:
    response = _client(tmp_path).post(
        "/api/operations/export-csv", json={}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# config validate
# ---------------------------------------------------------------------------


def test_config_validate_endpoint_returns_profile_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "cfdi-vault.local.json"
    config_path.write_text("{}", encoding="utf-8")

    class _FakeDownload:
        metadata_first = True

    class _FakeProfile:
        profile_id = "default"
        rfc = "AAA010101AAA"
        storage_root = "storage"
        download = _FakeDownload()

    class _FakeConfig:
        schema_version = 1
        profiles = (_FakeProfile(),)

    monkeypatch.setattr(subject, "load_config", lambda path: _FakeConfig())
    response = _client(tmp_path).post(
        "/api/config/validate", json={"config_path": str(config_path)}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json() == {
        "schema_version": 1,
        "profiles": [
            {"profile_id": "default", "rfc": "AAA010101AAA", "storage_root": "storage", "metadata_first": True},
        ],
    }


def test_config_validate_endpoint_maps_validation_error_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "cfdi-vault.local.json"
    config_path.write_text("{}", encoding="utf-8")

    def fail(path: Path) -> None:
        raise ConfigValidationError(["schemaVersion must be 1", "profiles must not be empty"])

    monkeypatch.setattr(subject, "load_config", fail)
    response = _client(tmp_path).post(
        "/api/config/validate", json={"config_path": str(config_path)}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {
        "detail": {
            "reason": "config-invalid",
            "errors": ["schemaVersion must be 1", "profiles must not be empty"],
        }
    }


def test_config_validate_endpoint_rejects_missing_path_without_touching_load_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def fail_if_called(path: Path) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(subject, "load_config", fail_if_called)
    response = _client(tmp_path).post(
        "/api/config/validate",
        json={"config_path": str(tmp_path / "does-not-exist.json")},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "config-path-invalid"}}
    assert called is False
