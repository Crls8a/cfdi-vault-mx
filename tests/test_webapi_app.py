from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cfdi_vault.adapters.webapi import app as subject
from cfdi_vault.adapters.webapi.config import WebApiSettings
from cfdi_vault.recovery_service import DoctorCheck
from cfdi_vault.sat_campaign_db_cli import CampaignDatabaseError
from cfdi_vault.secrets import CredentialProviderError
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus, SetupError
from cfdi_vault.storage_observability import (
    InvalidStorageReferenceError,
    StorageObservation,
    StorageObservationError,
)

ALLOWED_ORIGIN = "http://127.0.0.1:3000"


def _settings(tmp_path: Path) -> WebApiSettings:
    environment = {
        "DATABASE_URL": "postgresql://synthetic:synthetic@localhost/synthetic",
        "CFDI_STORAGE_ROOT": str(tmp_path / "storage"),
    }
    return WebApiSettings.resolve(environment=environment, repository_root=tmp_path / "repo")


def _client(tmp_path: Path) -> TestClient:
    return TestClient(subject.create_app(_settings(tmp_path)))


def test_health_is_reachable_without_origin_header(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_post_without_origin_header_is_rejected(tmp_path: Path) -> None:
    response = _client(tmp_path).post("/api/docker/postgres/start")
    assert response.status_code == 403


def test_post_with_wrong_origin_is_rejected(tmp_path: Path) -> None:
    response = _client(tmp_path).post(
        "/api/docker/postgres/start", headers={"origin": "http://evil.example"},
    )
    assert response.status_code == 403


def test_post_with_correct_origin_reaches_handler(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        subject, "_run_compose", lambda action, service: calls.append([action, service]),
    )
    response = _client(tmp_path).post(
        "/api/docker/postgres/start", headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert calls == [["start", "postgres"]]


def test_get_docker_services_passes_regardless_of_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_docker_service_status", lambda name: {"service": name, "state": "running"})
    response = _client(tmp_path).get("/api/docker/services")
    assert response.status_code == 200
    services = [entry["service"] for entry in response.json()]
    assert services == ["postgres", "rabbitmq", "redis", "worker"]


@pytest.mark.parametrize("service", ["sat-monitor", "postgres; rm -rf /", "../etc"])
def test_docker_start_rejects_service_outside_allow_list_without_touching_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, service: str,
) -> None:
    called = False

    def fail_if_called(action: str, service_name: str) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(subject, "_run_compose", fail_if_called)
    response = _client(tmp_path).post(
        f"/api/docker/{service}/start", headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code in (400, 404)
    assert called is False


def test_docker_stop_rejects_service_outside_allow_list_without_touching_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def fail_if_called(action: str, service_name: str) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(subject, "_run_compose", fail_if_called)
    response = _client(tmp_path).post(
        "/api/docker/sat-monitor/stop", headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code in (400, 404)
    assert called is False


def test_profile_status_endpoint_returns_redacted_summary(tmp_path: Path) -> None:
    response = _client(tmp_path).get("/api/profile/unknown-profile/status")
    assert response.status_code == 200
    body = response.json()
    assert body["profile_id"] == "unknown-profile"
    assert "Setup profile: unknown-profile" in body["status"]
    assert "missing" in body["status"]


def test_campaign_status_endpoint_delegates_to_db_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, str] = {}
    last_run = {
        "run_ref": "run-synthetic", "status": "failed", "result_code": "commit-ref-mismatch",
        "requested_at": "2026-01-15T12:00:00+00:00", "finished_at": "2026-01-15T12:00:05+00:00",
    }

    def fake_campaign_status(profile_id: str, campaign_ref: str) -> dict[str, object]:
        captured.update(profile_id=profile_id, campaign_ref=campaign_ref)
        return {"campaign_ref": campaign_ref, "base_count": 0, "last_run": last_run}

    monkeypatch.setattr(subject, "campaign_status", fake_campaign_status)
    response = _client(tmp_path).get("/api/campaign/profile-a/campaign-b/status")
    assert response.status_code == 200
    assert response.json() == {"campaign_ref": "campaign-b", "base_count": 0, "last_run": last_run}
    assert captured == {"profile_id": "profile-a", "campaign_ref": "campaign-b"}


def test_campaign_status_endpoint_maps_database_error_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_campaign_status(profile_id: str, campaign_ref: str) -> dict[str, object]:
        raise CampaignDatabaseError("campaign-not-found")

    monkeypatch.setattr(subject, "campaign_status", fake_campaign_status)
    response = _client(tmp_path).get("/api/campaign/profile-a/campaign-b/status")
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "campaign-not-found"}}


def test_campaign_run_requires_correct_origin(tmp_path: Path) -> None:
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/campaign-b/run", json={"grant": "grant-ref"},
    )
    assert response.status_code == 403


def test_campaign_run_endpoint_queues_the_run_and_returns_202_without_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The handler must enqueue, never execute the live SAT sequence (ADR 0005)."""

    captured: dict[str, str] = {}
    hints: list[tuple[str, ...]] = []

    def fake_enqueue(profile_id: str, campaign_ref: str, grant_ref: str) -> dict[str, object]:
        captured.update(profile_id=profile_id, campaign_ref=campaign_ref, grant_ref=grant_ref)
        return {
            "status": "queued",
            "run_ref": "run-synthetic",
            "campaign_ref": campaign_ref,
            "requested_at": "2026-01-15T12:00:00+00:00",
        }

    monkeypatch.setattr(subject, "enqueue_campaign_run", fake_enqueue)
    monkeypatch.setattr(
        subject, "publish_campaign_run_hint",
        lambda *args: bool(hints.append(tuple(args))) or True,
    )
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/campaign-b/run",
        json={"grant": "grant-ref"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"
    assert body["run_ref"] == "run-synthetic"
    assert captured == {"profile_id": "profile-a", "campaign_ref": "campaign-b", "grant_ref": "grant-ref"}
    # The hint is published only after the row is committed by the enqueue call.
    assert hints == [("profile-a", "campaign-b", "grant-ref", "run-synthetic")]


def test_campaign_run_endpoint_accepts_the_request_even_when_the_broker_hint_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost wake hint delays the run; it must not reject an accepted request."""

    monkeypatch.setattr(
        subject, "enqueue_campaign_run",
        lambda profile_id, campaign_ref, grant_ref: {
            "status": "queued", "run_ref": "run-synthetic", "campaign_ref": campaign_ref,
            "requested_at": "2026-01-15T12:00:00+00:00",
        },
    )
    monkeypatch.setattr(subject, "publish_campaign_run_hint", lambda *args: False)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/campaign-b/run",
        json={"grant": "grant-ref"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 202
    assert response.json()["run_ref"] == "run-synthetic"


def test_campaign_run_endpoint_maps_database_error_to_redacted_4xx_without_raw_exception_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    published = False

    def fake_enqueue(profile_id: str, campaign_ref: str, grant_ref: str) -> dict[str, object]:
        raise CampaignDatabaseError("campaign-database-unavailable")

    def fail_if_published(*args: str) -> bool:
        nonlocal published
        published = True
        return True

    monkeypatch.setattr(subject, "enqueue_campaign_run", fake_enqueue)
    monkeypatch.setattr(subject, "publish_campaign_run_hint", fail_if_published)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/campaign-b/run",
        json={"grant": "SYNTHETIC-SECRET-GRANT"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "campaign-database-unavailable"}}
    assert "Traceback" not in response.text
    assert "phrase" not in response.text.lower()
    # A rejected pre-check must never leave a wake hint on the broker.
    assert published is False


class _FakeRecoveryService:
    def __init__(self, checks: tuple[DoctorCheck, ...]) -> None:
        self._checks = checks
        self.closed = False

    def doctor(self) -> tuple[DoctorCheck, ...]:
        return self._checks

    def close(self) -> None:
        self.closed = True


def test_doctor_endpoint_reports_checks_and_redacts_raw_storage_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeRecoveryService(
        (
            DoctorCheck("database", True, "schema reachable"),
            DoctorCheck("storage", True, str(tmp_path / "storage" / "secret-tenant")),
        )
    )
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).get("/api/system/doctor")
    assert response.status_code == 200
    body = response.json()
    assert body["checks"][0] == {"name": "database", "ok": True, "detail": "schema reachable"}
    storage_check = body["checks"][1]
    assert storage_check["name"] == "storage"
    assert str(tmp_path) not in storage_check["detail"]
    assert "profile_status" in body
    assert service.closed is True


def test_doctor_endpoint_redacts_failing_check_exception_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_path = str(tmp_path / "storage" / "secret-tenant")
    service = _FakeRecoveryService(
        (
            DoctorCheck("database", False, "connection to server at amqp://user:pass@host failed"),
            DoctorCheck("storage", False, f"[Errno 13] Permission denied: '{secret_path}'"),
        )
    )
    monkeypatch.setattr(subject, "_recovery_service", lambda database_url, storage: service)
    response = _client(tmp_path).get("/api/system/doctor")
    assert response.status_code == 200
    body = response.json()
    for check in body["checks"]:
        assert check["ok"] is False
        assert "pass" not in check["detail"]
        assert secret_path not in check["detail"]
        assert str(tmp_path) not in check["detail"]


def test_doctor_endpoint_maps_construction_failure_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(database_url: str, storage: Path) -> _FakeRecoveryService:
        raise RuntimeError("PostgreSQL DATABASE_URL is required.")

    monkeypatch.setattr(subject, "_recovery_service", fail)
    response = _client(tmp_path).get("/api/system/doctor")
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "doctor-database-unavailable"}}


class _FakePreflightReport:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def sanitized(self) -> dict[str, object]:
        return self._payload


def test_preflight_endpoint_returns_sanitized_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = LocalProfile(
        profile_id="default",
        rfc="AAA010101AAA",
        storage_root=tmp_path / "storage",
        credential_mode=CredentialMode.COPIED,
        certificate_path=tmp_path / "cert.cer",
        private_key_path=tmp_path / "key.key",
        phrase_ref="local-dev-dummy://default/phrase",
        status=LocalProfileStatus.READY,
        certificate_fingerprint="AA:BB",
    )
    payload = {"ready": True, "checks": [{"name": "profile", "status": "passed", "reason": "ok"}]}
    monkeypatch.setattr(subject, "load_profile", lambda profile_id: profile)
    monkeypatch.setattr(subject, "_setup_provider", lambda profile_id: None)
    monkeypatch.setattr(subject, "default_local_probes", lambda settings: {})
    monkeypatch.setattr(
        subject, "run_local_preflight",
        lambda settings, profile, provider, *, probes, repository_root: _FakePreflightReport(payload),
    )
    response = _client(tmp_path).get("/api/system/preflight")
    assert response.status_code == 200
    assert response.json() == payload


def test_preflight_endpoint_maps_invalid_profile_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(profile_id: str) -> LocalProfile:
        raise SetupError(["profile is not configured: default"])

    monkeypatch.setattr(subject, "load_profile", fail)
    response = _client(tmp_path).get("/api/system/preflight")
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "preflight-local-configuration-invalid"}}


def test_analysis_report_endpoint_returns_sanitized_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeProfile:
        profile_id = "tenant-a"

    monkeypatch.setattr(subject, "_analysis_database_url", lambda value: "postgresql://synthetic/db")
    monkeypatch.setattr(subject, "_analysis_load_exact_profile", lambda profile_id: _FakeProfile())
    monkeypatch.setattr(subject, "_analysis_parse_date", lambda value: date.fromisoformat(value))
    monkeypatch.setattr(
        subject, "_analysis_build_report",
        lambda *, database_url, tenant_id, start, end: {"tenant_id": tenant_id, "total": 0},
    )
    response = _client(tmp_path).get(
        "/api/analysis/report",
        params={"profile": "tenant-a", "tenant_id": "tenant-a", "from": "2026-01-01", "to": "2026-01-31"},
    )
    assert response.status_code == 200
    assert response.json() == {"tenant_id": "tenant-a", "total": 0, "provenance": "postgres-v5-read"}


def test_analysis_report_endpoint_maps_profile_mismatch_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeProfile:
        profile_id = "tenant-a"

    monkeypatch.setattr(subject, "_analysis_database_url", lambda value: "postgresql://synthetic/db")
    monkeypatch.setattr(subject, "_analysis_load_exact_profile", lambda profile_id: _FakeProfile())
    response = _client(tmp_path).get(
        "/api/analysis/report",
        params={"profile": "tenant-a", "tenant_id": "tenant-b", "from": "2026-01-01", "to": "2026-01-31"},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "analysis-tenant-profile-mismatch"}}


def test_storage_status_endpoint_returns_redacted_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeStorageService:
        def status(self, reference: str) -> StorageObservation:
            return StorageObservation(True, "ref-abc123", "xml", size_bytes=42, sha256_prefix="deadbeef1234")

    monkeypatch.setattr(subject, "_storage_service", lambda storage: _FakeStorageService())
    response = _client(tmp_path).get("/api/storage/status", params={"reference": "xml/foo.xml"})
    assert response.status_code == 200
    assert response.json() == {
        "exists": True, "reference": "ref-abc123", "category": "xml",
        "size_bytes": 42, "sha256_prefix": "deadbeef1234", "location": None,
    }


def test_storage_status_endpoint_maps_invalid_reference_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeStorageService:
        def status(self, reference: str) -> StorageObservation:
            raise InvalidStorageReferenceError("invalid storage reference")

    monkeypatch.setattr(subject, "_storage_service", lambda storage: _FakeStorageService())
    response = _client(tmp_path).get("/api/storage/status", params={"reference": "../etc/passwd"})
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "invalid_storage_reference"}}


def test_storage_locate_endpoint_returns_redacted_logical_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeStorageService:
        def locate(self, reference: str) -> StorageObservation:
            return StorageObservation(
                True, "ref-abc123", "xml", size_bytes=42, sha256_prefix="deadbeef1234",
                location="filesystem://xml/ref-abc123",
            )

    monkeypatch.setattr(subject, "_storage_service", lambda storage: _FakeStorageService())
    response = _client(tmp_path).get("/api/storage/locate", params={"reference": "xml/foo.xml"})
    assert response.status_code == 200
    body = response.json()
    assert body["location"] == "filesystem://xml/ref-abc123"
    assert str(tmp_path) not in response.text


def test_storage_locate_endpoint_maps_adapter_failure_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeStorageService:
        def locate(self, reference: str) -> StorageObservation:
            raise StorageObservationError("storage observation failed")

    monkeypatch.setattr(subject, "_storage_service", lambda storage: _FakeStorageService())
    response = _client(tmp_path).get("/api/storage/locate", params={"reference": "xml/foo.xml"})
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "storage_observation_failed"}}


def test_secret_verify_endpoint_returns_existence_without_the_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeProvider:
        def exists(self, reference: object, *, purpose: str) -> bool:
            return True

    monkeypatch.setattr(subject, "native_provider_for_reference", lambda reference, **kwargs: _FakeProvider())
    response = _client(tmp_path).get(
        "/api/secret/verify", params={"reference": "wincred://cfdi-vault/default/phrase", "kind": "phrase"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body == {"reference": "wincred://cfdi-vault/default/phrase", "kind": "phrase", "exists": True}


def test_secret_verify_endpoint_maps_provider_error_to_redacted_4xx_without_the_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeProvider:
        def exists(self, reference: object, *, purpose: str) -> bool:
            raise CredentialProviderError("secure-provider-verify-failed")

    monkeypatch.setattr(subject, "native_provider_for_reference", lambda reference, **kwargs: _FakeProvider())
    response = _client(tmp_path).get(
        "/api/secret/verify", params={"reference": "wincred://cfdi-vault/default/phrase", "kind": "phrase"},
    )
    assert 400 <= response.status_code < 500
    assert response.json() == {"detail": {"reason": "secret-verification-failed"}}
    assert "phrase" not in response.json()["detail"]["reason"]
