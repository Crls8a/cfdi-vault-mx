"""Control-panel endpoints that create access or carry credential material (ADR 0006).

Two invariants are under test here and nowhere else:

* the typed-confirmation gate on ``create``/``authorize`` is a *server-side*
  boundary — a mismatch must be rejected before the underlying database
  function is reached, not merely before a button is enabled;
* a secret submitted in a request body (the FIEL phrase, a credential value)
  must not appear in the raw response text on any path, success or failure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import typer
from fastapi.testclient import TestClient

from cfdi_vault.adapters.webapi import app as subject
from cfdi_vault.adapters.webapi.config import WebApiSettings
from cfdi_vault.sat_campaign_db_cli import CampaignDatabaseError
from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference
from cfdi_vault.setup_core import (
    AppDataPaths,
    CredentialMode,
    LocalProfile,
    LocalProfileStatus,
    SetupError,
    SetupResult,
)

ALLOWED_ORIGIN = "http://127.0.0.1:3000"
PHRASE = "SYNTHETIC-PHRASE-DO-NOT-ECHO-9d2f"
SECRET_VALUE = "SYNTHETIC-CREDENTIAL-DO-NOT-ECHO-4b71"


def _settings(tmp_path: Path) -> WebApiSettings:
    environment = {
        "DATABASE_URL": "postgresql://synthetic:synthetic@localhost/synthetic",
        "CFDI_STORAGE_ROOT": str(tmp_path / "storage"),
    }
    return WebApiSettings.resolve(environment=environment, repository_root=tmp_path / "repo")


def _client(tmp_path: Path) -> TestClient:
    return TestClient(subject.create_app(_settings(tmp_path)))


def _profile(tmp_path: Path, profile_id: str = "default") -> LocalProfile:
    return LocalProfile(
        profile_id=profile_id,
        rfc="AAA010101AAA",
        storage_root=tmp_path / "storage",
        credential_mode=CredentialMode.COPIED,
        certificate_path=tmp_path / "cert.cer",
        private_key_path=tmp_path / "key.key",
        phrase_ref="local-dev-dummy://default/phrase",
        status=LocalProfileStatus.READY,
        certificate_fingerprint="deadbeef",
    )


def _explode(*args: object, **kwargs: object) -> Any:
    raise AssertionError("the guarded function must not be reached")


class _CallRecorder:
    """Records whether a guarded function was reached, and raises if it was.

    The handlers wrap their database call in ``except Exception``, so a bare
    raising stub alone could be swallowed into a *different* 400 rather than
    surfacing.  The recorder therefore also exposes ``called`` so a gate test
    can assert non-invocation directly instead of inferring it from the reason.
    """

    def __init__(self) -> None:
        self.called = False

    def __call__(self, *args: object, **kwargs: object) -> Any:
        self.called = True
        raise AssertionError("the guarded function must not be reached")


# --------------------------------------------------------------------------
# POST /api/campaign/{profile_id}/create
# --------------------------------------------------------------------------


def test_campaign_create_rejects_confirmation_mismatch_without_touching_the_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    load = _CallRecorder()
    create = _CallRecorder()
    monkeypatch.setattr(subject, "load_profile", load)
    monkeypatch.setattr(subject, "create_campaign", create)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/create",
        json={"confirm": "profile-b"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "confirmation-mismatch"}}
    # The gate is a boundary, not a message: nothing downstream ran at all.
    assert create.called is False
    assert load.called is False


def test_campaign_create_confirmation_is_case_sensitive_and_untrimmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "load_profile", _explode)
    monkeypatch.setattr(subject, "create_campaign", _explode)
    client = _client(tmp_path)
    for confirm in ("PROFILE-A", " profile-a", "profile-a "):
        response = client.post(
            "/api/campaign/profile-a/create",
            json={"confirm": confirm},
            headers={"origin": ALLOWED_ORIGIN},
        )
        assert response.status_code == 400
        assert response.json() == {"detail": {"reason": "confirmation-mismatch"}}


def test_campaign_create_requires_a_confirm_field_at_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "load_profile", _explode)
    monkeypatch.setattr(subject, "create_campaign", _explode)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/create", json={}, headers={"origin": ALLOWED_ORIGIN},
    )
    assert 400 <= response.status_code < 500


def test_campaign_create_requires_correct_origin_before_any_confirmation(tmp_path: Path) -> None:
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/create", json={"confirm": "profile-a"},
    )
    assert response.status_code == 403


def test_campaign_create_with_matching_confirmation_delegates_to_db_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, str] = {}
    summary = {"campaign_ref": "campaign-2026", "base_count": 28, "split_count": 0, "leaf_count": 28}

    def fake_create(profile_id: str, *, tenant_rfc: str) -> dict[str, object]:
        captured.update(profile_id=profile_id, tenant_rfc=tenant_rfc)
        return summary

    monkeypatch.setattr(subject, "load_profile", lambda profile_id: _profile(tmp_path, profile_id))
    monkeypatch.setattr(subject, "create_campaign", fake_create)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/create",
        json={"confirm": "profile-a"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json() == summary
    assert captured == {"profile_id": "profile-a", "tenant_rfc": "AAA010101AAA"}


def test_campaign_create_maps_database_error_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(profile_id: str, *, tenant_rfc: str) -> dict[str, object]:
        raise CampaignDatabaseError("campaign-database-unavailable")

    monkeypatch.setattr(subject, "load_profile", lambda profile_id: _profile(tmp_path, profile_id))
    monkeypatch.setattr(subject, "create_campaign", fail)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/create",
        json={"confirm": "profile-a"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "campaign-database-unavailable"}}
    assert "Traceback" not in response.text


def test_campaign_create_maps_unexpected_driver_failure_to_a_fixed_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(profile_id: str, *, tenant_rfc: str) -> dict[str, object]:
        raise RuntimeError("connection to server at postgresql://user:pass@host failed")

    monkeypatch.setattr(subject, "load_profile", lambda profile_id: _profile(tmp_path, profile_id))
    monkeypatch.setattr(subject, "create_campaign", fail)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/create",
        json={"confirm": "profile-a"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "campaign-database-operation-failed"}}
    assert "pass@host" not in response.text


def test_campaign_create_maps_invalid_profile_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(profile_id: str) -> LocalProfile:
        raise SetupError([f"profile is not configured: {tmp_path}"])

    monkeypatch.setattr(subject, "load_profile", fail)
    monkeypatch.setattr(subject, "create_campaign", _explode)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/create",
        json={"confirm": "profile-a"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "campaign-profile-invalid"}}
    assert str(tmp_path) not in response.text


def test_campaign_create_rejects_a_profile_document_that_disagrees_with_the_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "load_profile", lambda profile_id: _profile(tmp_path, "other-profile"))
    monkeypatch.setattr(subject, "create_campaign", _explode)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/create",
        json={"confirm": "profile-a"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "campaign-profile-mismatch"}}


# --------------------------------------------------------------------------
# POST /api/campaign/{profile_id}/{campaign_ref}/authorize
# --------------------------------------------------------------------------


def test_campaign_authorize_rejects_confirmation_mismatch_without_touching_the_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorize = _CallRecorder()
    monkeypatch.setattr(subject, "authorize_campaign", authorize)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/campaign-b/authorize",
        json={
            "confirm": "campaign-c",
            "phase": "metadata-proof",
            "expires_days": 7,
            "reason": "synthetic",
        },
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "confirmation-mismatch"}}
    # No grant may be reached by an unconfirmed request, on any code path.
    assert authorize.called is False


def test_campaign_authorize_confirmation_must_be_the_campaign_ref_not_the_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "authorize_campaign", _explode)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/campaign-b/authorize",
        json={
            "confirm": "profile-a",
            "phase": "metadata-proof",
            "expires_days": 7,
            "reason": "synthetic",
        },
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "confirmation-mismatch"}}


def test_campaign_authorize_requires_correct_origin(tmp_path: Path) -> None:
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/campaign-b/authorize",
        json={
            "confirm": "campaign-b",
            "phase": "metadata-proof",
            "expires_days": 7,
            "reason": "synthetic",
        },
        headers={"origin": "http://evil.example"},
    )
    assert response.status_code == 403


def test_campaign_authorize_with_matching_confirmation_returns_the_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    grant = {
        "grant_ref": "grant-synthetic",
        "phase": "metadata-proof",
        "expires_at": "2026-02-01T00:00:00+00:00",
        "max_open_operations": 2,
    }

    def fake_authorize(
        profile_id: str, campaign_ref: str, phase: str, expires_days: int, reason: str,
    ) -> dict[str, object]:
        captured.update(
            profile_id=profile_id, campaign_ref=campaign_ref, phase=phase,
            expires_days=expires_days, reason=reason,
        )
        return grant

    monkeypatch.setattr(subject, "authorize_campaign", fake_authorize)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/campaign-b/authorize",
        json={
            "confirm": "campaign-b",
            "phase": "metadata-proof",
            "expires_days": 7,
            "reason": "quarterly proof run",
        },
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json() == grant
    assert captured == {
        "profile_id": "profile-a",
        "campaign_ref": "campaign-b",
        "phase": "metadata-proof",
        "expires_days": 7,
        "reason": "quarterly proof run",
    }


def test_campaign_authorize_maps_database_error_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(
        profile_id: str, campaign_ref: str, phase: str, expires_days: int, reason: str,
    ) -> dict[str, object]:
        raise CampaignDatabaseError("campaign-grant-validity-invalid")

    monkeypatch.setattr(subject, "authorize_campaign", fail)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/campaign-b/authorize",
        json={"confirm": "campaign-b", "phase": "metadata-proof", "expires_days": 99, "reason": "x"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "campaign-grant-validity-invalid"}}


def test_campaign_authorize_maps_unexpected_failure_to_a_fixed_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(
        profile_id: str, campaign_ref: str, phase: str, expires_days: int, reason: str,
    ) -> dict[str, object]:
        raise RuntimeError("psycopg: connection failed for user 'synthetic'")

    monkeypatch.setattr(subject, "authorize_campaign", fail)
    response = _client(tmp_path).post(
        "/api/campaign/profile-a/campaign-b/authorize",
        json={"confirm": "campaign-b", "phase": "metadata-proof", "expires_days": 7, "reason": "x"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "campaign-database-authorize-failed"}}
    assert "psycopg" not in response.text


# --------------------------------------------------------------------------
# POST /api/setup
# --------------------------------------------------------------------------


def _setup_result(tmp_path: Path) -> SetupResult:
    base = tmp_path / "appdata"
    paths = AppDataPaths(
        base_dir=base,
        profiles_dir=base / "profiles",
        profile_dir=base / "profiles" / "default",
        profile_json=base / "profiles" / "default" / "profile.json",
        credentials_dir=base / "profiles" / "default" / "credentials",
        storage_root=base / "storage" / "default",
    )
    return SetupResult(profile=_profile(tmp_path), paths=paths)


def _setup_body(tmp_path: Path) -> dict[str, object]:
    return {
        "profile_id": "default",
        "rfc": "AAA010101AAA",
        "source_folder": str(tmp_path / "external"),
        "credential_mode": "copied",
        "phrase": PHRASE,
    }


def test_setup_requires_correct_origin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subject, "run_setup", _explode)
    response = _client(tmp_path).post("/api/setup", json=_setup_body(tmp_path))
    assert response.status_code == 403
    assert PHRASE not in response.text


def test_setup_is_not_reachable_by_query_string(tmp_path: Path) -> None:
    """There is no GET form of this endpoint: the phrase can only arrive in a body."""

    response = _client(tmp_path).get("/api/setup", params={"phrase": PHRASE})
    assert response.status_code == 405


def test_setup_happy_path_returns_a_redacted_summary_without_the_phrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run_setup(**kwargs: object) -> SetupResult:
        captured.update(kwargs)
        return _setup_result(tmp_path)

    monkeypatch.setattr(subject, "_setup_provider", lambda profile_id: object())
    monkeypatch.setattr(subject, "run_setup", fake_run_setup)
    response = _client(tmp_path).post(
        "/api/setup", json=_setup_body(tmp_path), headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json() == {
        "profile_id": "default",
        "rfc": "AA********AA",
        "credential_mode": "copied",
        "credentials_imported": True,
        "phrase_stored": True,
    }
    # The phrase reached run_setup exactly once and came back out nowhere.
    assert captured["phrase_value"] == PHRASE
    assert captured["mode"] is CredentialMode.COPIED
    assert captured["certificate_path"] is None
    assert PHRASE not in response.text
    assert "AAA010101AAA" not in response.text


def test_setup_passes_explicit_certificate_and_key_paths_through(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run_setup(**kwargs: object) -> SetupResult:
        captured.update(kwargs)
        return _setup_result(tmp_path)

    monkeypatch.setattr(subject, "_setup_provider", lambda profile_id: object())
    monkeypatch.setattr(subject, "run_setup", fake_run_setup)
    body = _setup_body(tmp_path)
    body["certificate_path"] = str(tmp_path / "external" / "fiel.cer")
    body["private_key_path"] = str(tmp_path / "external" / "fiel.key")
    body["credential_mode"] = "referenced"
    response = _client(tmp_path).post("/api/setup", json=body, headers={"origin": ALLOWED_ORIGIN})
    assert response.status_code == 200
    assert captured["certificate_path"] == Path(str(tmp_path / "external" / "fiel.cer"))
    assert captured["private_key_path"] == Path(str(tmp_path / "external" / "fiel.key"))
    assert captured["mode"] is CredentialMode.REFERENCED


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        ("source folder does not exist or is not a folder: {path}", "setup-source-folder-invalid"),
        ("certificate file does not exist or is not a file: {path}", "setup-credential-file-invalid"),
        ("source folder must be outside the repository", "setup-path-inside-repository"),
        ("credential intake is not allowed in CI", "setup-ci-not-allowed"),
        ("RFC must be 12 or 13 uppercase RFC-shaped characters", "setup-rfc-invalid"),
        ("no certificate candidate found in source folder", "setup-credential-candidate-missing"),
        ("ambiguous private key candidates; pass an explicit file path", "setup-credential-candidate-ambiguous"),
        ("PEM private key appears unencrypted; use encrypted key material", "setup-private-key-unencrypted"),
        (
            "private-key phrase must be provided and is stored only through the secret provider",
            "setup-phrase-required",
        ),
        ("something nobody has classified yet", "setup-input-invalid"),
    ],
)
def test_setup_maps_setup_errors_to_bounded_reasons_without_echoing_the_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: str, reason: str,
) -> None:
    message = error.format(path=tmp_path / "external")

    def fail(**kwargs: object) -> SetupResult:
        raise SetupError([message])

    monkeypatch.setattr(subject, "_setup_provider", lambda profile_id: object())
    monkeypatch.setattr(subject, "run_setup", fail)
    response = _client(tmp_path).post(
        "/api/setup", json=_setup_body(tmp_path), headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": reason}}
    # Neither the secret nor the raw operator message leaves the process.
    assert PHRASE not in response.text
    assert str(tmp_path) not in response.text
    assert "Traceback" not in response.text


def test_setup_failure_never_leaks_the_phrase_even_if_an_exception_carries_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defence in depth: no current SetupError embeds the phrase, and none may.

    ``_setup_failure_reason`` returns a slug from a fixed table rather than any
    part of the message, so even a future error that wrongly interpolated the
    phrase could not reach the client through this handler.
    """

    def fail(**kwargs: object) -> SetupResult:
        raise SetupError([f"source folder does not exist or is not a folder: {PHRASE}"])

    monkeypatch.setattr(subject, "_setup_provider", lambda profile_id: object())
    monkeypatch.setattr(subject, "run_setup", fail)
    response = _client(tmp_path).post(
        "/api/setup", json=_setup_body(tmp_path), headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "setup-source-folder-invalid"}}
    assert PHRASE not in response.text


def test_setup_maps_provider_error_to_redacted_4xx_without_the_phrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(**kwargs: object) -> SetupResult:
        raise CredentialProviderError("credential reference uses an unsupported provider scheme")

    monkeypatch.setattr(subject, "_setup_provider", lambda profile_id: object())
    monkeypatch.setattr(subject, "run_setup", fail)
    response = _client(tmp_path).post(
        "/api/setup", json=_setup_body(tmp_path), headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "setup-local-configuration-invalid"}}
    assert PHRASE not in response.text


def test_setup_maps_unexpected_os_failure_to_a_fixed_reason_without_the_phrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(**kwargs: object) -> SetupResult:
        raise OSError(13, "Permission denied", str(tmp_path / "external" / "fiel.key"))

    monkeypatch.setattr(subject, "_setup_provider", lambda profile_id: object())
    monkeypatch.setattr(subject, "run_setup", fail)
    response = _client(tmp_path).post(
        "/api/setup", json=_setup_body(tmp_path), headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "setup-failed"}}
    assert PHRASE not in response.text
    assert str(tmp_path) not in response.text


def test_setup_rejects_an_unknown_credential_mode_before_building_a_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_setup_provider", _explode)
    monkeypatch.setattr(subject, "run_setup", _explode)
    body = _setup_body(tmp_path)
    body["credential_mode"] = "smuggled"
    response = _client(tmp_path).post("/api/setup", json=body, headers={"origin": ALLOWED_ORIGIN})
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "setup-credential-mode-invalid"}}
    assert PHRASE not in response.text


def test_setup_requires_the_phrase_field(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subject, "run_setup", _explode)
    body = _setup_body(tmp_path)
    del body["phrase"]
    response = _client(tmp_path).post("/api/setup", json=body, headers={"origin": ALLOWED_ORIGIN})
    assert 400 <= response.status_code < 500


# --------------------------------------------------------------------------
# POST /api/secret/register and POST /api/secret/delete
# --------------------------------------------------------------------------


class _FakeProvider:
    def __init__(self, *, error: Exception | None = None, deleted: bool = True) -> None:
        self._error = error
        self._deleted = deleted
        self.stored: list[tuple[str, str, str]] = []
        self.deletes: list[tuple[str, str]] = []

    def store(self, reference: CredentialReference, value: str, *, purpose: str) -> None:
        if self._error is not None:
            raise self._error
        self.stored.append((reference.uri, value, purpose))

    def delete(self, reference: CredentialReference, *, purpose: str) -> bool:
        if self._error is not None:
            raise self._error
        self.deletes.append((reference.uri, purpose))
        return self._deleted


def _install_provider(monkeypatch: pytest.MonkeyPatch, provider: _FakeProvider) -> None:
    monkeypatch.setattr(subject, "_provider_for_reference", lambda reference: provider)


REFERENCE = "windows-credential-manager://cfdi-vault/setup/default/private-key-phrase"


def test_secret_register_requires_correct_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_provider_for_reference", _explode)
    response = _client(tmp_path).post(
        "/api/secret/register",
        json={"reference": REFERENCE, "kind": "phrase", "value": SECRET_VALUE},
    )
    assert response.status_code == 403
    assert SECRET_VALUE not in response.text


def test_secret_register_stores_the_value_and_echoes_only_the_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider()
    _install_provider(monkeypatch, provider)
    response = _client(tmp_path).post(
        "/api/secret/register",
        json={"reference": REFERENCE, "kind": "phrase", "value": SECRET_VALUE, "purpose": "webapi-register"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json() == {"reference": REFERENCE, "kind": "phrase"}
    assert provider.stored == [(REFERENCE, SECRET_VALUE, "webapi-register")]
    assert SECRET_VALUE not in response.text


def test_secret_register_maps_provider_error_without_echoing_the_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_provider(monkeypatch, _FakeProvider(error=CredentialProviderError("store rejected")))
    response = _client(tmp_path).post(
        "/api/secret/register",
        json={"reference": REFERENCE, "kind": "phrase", "value": SECRET_VALUE},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "secret-registration-failed"}}
    assert SECRET_VALUE not in response.text
    assert "store rejected" not in response.text


def test_secret_register_rejects_an_invalid_kind_before_building_a_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_provider_for_reference", _explode)
    response = _client(tmp_path).post(
        "/api/secret/register",
        json={"reference": REFERENCE, "kind": "not-a-kind", "value": SECRET_VALUE},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "secret-kind-invalid"}}
    assert SECRET_VALUE not in response.text


def test_secret_register_maps_an_unsupported_provider_scheme_to_a_fixed_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(reference: CredentialReference) -> object:
        raise typer.BadParameter(f"unsupported provider scheme for {reference.uri}")

    monkeypatch.setattr(subject, "_provider_for_reference", fail)
    response = _client(tmp_path).post(
        "/api/secret/register",
        json={"reference": REFERENCE, "kind": "phrase", "value": SECRET_VALUE},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "secret-provider-unavailable"}}
    assert SECRET_VALUE not in response.text


def test_secret_delete_requires_correct_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subject, "_provider_for_reference", _explode)
    response = _client(tmp_path).post(
        "/api/secret/delete", json={"reference": REFERENCE, "kind": "phrase"},
    )
    assert response.status_code == 403


def test_secret_delete_removes_the_reference_and_reports_the_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider()
    _install_provider(monkeypatch, provider)
    response = _client(tmp_path).post(
        "/api/secret/delete",
        json={"reference": REFERENCE, "kind": "phrase", "purpose": "webapi-delete"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json() == {"reference": REFERENCE, "kind": "phrase", "deleted": True}
    assert provider.deletes == [(REFERENCE, "webapi-delete")]


def test_secret_delete_reports_a_missing_reference_without_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_provider(monkeypatch, _FakeProvider(deleted=False))
    response = _client(tmp_path).post(
        "/api/secret/delete",
        json={"reference": REFERENCE, "kind": "phrase"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json()["deleted"] is False


def test_secret_delete_maps_provider_error_to_redacted_4xx(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_provider(monkeypatch, _FakeProvider(error=CredentialProviderError("vault locked")))
    response = _client(tmp_path).post(
        "/api/secret/delete",
        json={"reference": REFERENCE, "kind": "phrase"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": {"reason": "secret-deletion-failed"}}
    assert "vault locked" not in response.text


def test_secret_delete_defaults_to_the_generic_kind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider()
    _install_provider(monkeypatch, provider)
    response = _client(tmp_path).post(
        "/api/secret/delete",
        json={"reference": "local-dev-dummy://cfdi-vault/misc"},
        headers={"origin": ALLOWED_ORIGIN},
    )
    assert response.status_code == 200
    assert response.json()["kind"] == CredentialKind.GENERIC.value
