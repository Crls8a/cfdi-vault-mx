from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cfdi_vault.db import create_engine_from_url, create_session_factory
from cfdi_vault.recovery_db import Tenant
from cfdi_vault.sat_legacy_import import (
    LegacyJsonImportError,
    _legacy_window_status,
    _normalize_recovery,
    _read_legacy_json,
    import_legacy_json,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


@pytest.mark.integration
def test_legacy_import_is_idempotent_and_preserves_request(reset_postgres_database: str, tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    recovery = tmp_path / "recovery.json"
    manifest.write_text(json.dumps({
        "schemaVersion": 1, "campaignRef": "cmp-aaaaaaaaaaaa", "profileId": "legacy-profile",
        "items": [{"workRef": "work-legacy", "direction": "received", "start": "2026-01-01",
                    "end": "2026-01-14", "state": "outstanding"}],
    }), encoding="utf-8")
    recovery.write_text(json.dumps({
        "schemaVersion": 1, "recoveries": [{"recovery": {
            "recoveryRef": "rec-legacy",
            "createdAt": "2026-01-01T12:00:00Z",
            "deadlineAt": "2026-01-03T12:00:00Z",
            "nextCheckAt": "2026-01-01T12:05:00Z",
            "status": "waiting_verify",
            "verifyHistory": [{"attempt": 1, "scheduledAt": "2026-01-01T12:05:00Z",
                                "category": "pending", "result": "pending",
                                "nextCheckAt": "2026-01-01T12:20:00Z"}],
            "packages": [{"packageRef": "package-legacy", "status": "pending"}],
            "artifacts": [{"packageRef": "package-legacy", "packageSha256": "a" * 64,
                            "packageStorageKey": "sat-metadata/cmp-aaaaaaaaaaaa/work-legacy/packages/1-aaaaaaaaaaaa.zip",
                            "byteCount": 10}],
        }, "idSolicitud": "request-legacy",
            "direction": "received", "kind": "Metadata", "fechaInicial": "2026-01-01",
            "fechaFinal": "2026-01-14", "workRef": "work-legacy"}],
    }), encoding="utf-8")
    engine = create_engine_from_url(reset_postgres_database)
    factory = create_session_factory(engine)
    with factory() as session:
        session.add(Tenant(id="legacy-tenant", name="Synthetic", rfc="SYNTHETIC", created_at=NOW))
        session.commit()
    first = import_legacy_json(factory, manifest_path=manifest, recovery_state_path=recovery,
                               tenant_id="legacy-tenant", commit_ref="commit-legacy", now=NOW)
    second = import_legacy_json(factory, manifest_path=manifest, recovery_state_path=recovery,
                                tenant_id="legacy-tenant", commit_ref="commit-legacy", now=NOW)
    assert first.campaign_ref == second.campaign_ref
    assert first.requests_imported == first.attempts_imported == first.packages_imported == 1
    assert second.windows_imported == second.requests_imported == second.attempts_imported == second.packages_imported == 0


def test_legacy_json_reader_rejects_malformed_documents(tmp_path: Path) -> None:
    path = tmp_path / "legacy.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(LegacyJsonImportError) as error:
        _read_legacy_json(path)

    assert error.value.reason == "legacy-json-invalid"
    assert error.value.manual_review is True


def test_legacy_window_status_preserves_terminal_categories() -> None:
    assert _legacy_window_status("planned") == "planned"
    assert _legacy_window_status("outstanding") == "reserved"
    assert _legacy_window_status("completed") == "complete"
    assert _legacy_window_status("no_data") == "no_data"
    assert _legacy_window_status("threshold_blocked") == "manual_review"


def test_import_requires_at_least_one_legacy_state_file() -> None:
    with pytest.raises(LegacyJsonImportError) as error:
        import_legacy_json(
            lambda: None,
            tenant_id="synthetic-tenant",
            commit_ref="synthetic-commit",
        )

    assert error.value.reason == "legacy-json-missing"


def test_reader_preserves_nested_private_values_without_logging(tmp_path: Path) -> None:
    path = tmp_path / "legacy.json"
    payload = {"schemaVersion": 1, "campaignRef": "cmp-aaaaaaaaaaaa"}
    path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = _read_legacy_json(path)

    assert loaded == payload


def test_reader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "legacy.json"
    path.write_text('{"campaignRef":"one","campaignRef":"two"}', encoding="utf-8")

    with pytest.raises(LegacyJsonImportError) as error:
        _read_legacy_json(path)

    assert error.value.reason == "legacy-json-duplicate-key"


def test_normalize_recovery_preserves_nested_lifecycle() -> None:
    normalized = _normalize_recovery({
        "workRef": "work-a",
        "idSolicitud": "request-a",
        "recovery": {"recoveryRef": "recovery-a", "status": "verify_scheduled"},
    })

    assert normalized["recoveryRef"] == "recovery-a"
    assert normalized["status"] == "verify_scheduled"
    assert normalized["workRef"] == "work-a"
