from __future__ import annotations

from pathlib import Path

import pytest

from cfdi_vault.adapters.webapi.config import WebApiSettings, WebApiSettingsError


def _valid_environment(tmp_path: Path, **overrides: str) -> dict[str, str]:
    environment = {
        "DATABASE_URL": "postgresql://synthetic:synthetic@localhost/synthetic",
        "CFDI_STORAGE_ROOT": str(tmp_path / "storage"),
    }
    environment.update(overrides)
    return environment


def test_resolve_accepts_valid_config_with_defaults(tmp_path: Path) -> None:
    settings = WebApiSettings.resolve(
        environment=_valid_environment(tmp_path), repository_root=tmp_path / "repo",
    )

    assert settings.webapi_host == "127.0.0.1"
    assert settings.webapi_port == 8420
    assert settings.webapi_allowed_origin == "http://127.0.0.1:3000"
    assert settings.runtime.database_url.startswith("postgresql://")


def test_resolve_accepts_explicit_valid_overrides(tmp_path: Path) -> None:
    environment = _valid_environment(
        tmp_path, WEBAPI_PORT="9000", WEBAPI_ALLOWED_ORIGIN="https://127.0.0.1:4000",
    )
    settings = WebApiSettings.resolve(environment=environment, repository_root=tmp_path / "repo")

    assert settings.webapi_port == 9000
    assert settings.webapi_allowed_origin == "https://127.0.0.1:4000"


def test_resolve_rejects_non_loopback_host(tmp_path: Path) -> None:
    environment = _valid_environment(tmp_path, WEBAPI_HOST="0.0.0.0")

    with pytest.raises(WebApiSettingsError) as exc_info:
        WebApiSettings.resolve(environment=environment, repository_root=tmp_path / "repo")
    assert exc_info.value.reason == "webapi-host-loopback-required"


def test_resolve_rejects_out_of_range_port(tmp_path: Path) -> None:
    environment = _valid_environment(tmp_path, WEBAPI_PORT="70000")

    with pytest.raises(WebApiSettingsError) as exc_info:
        WebApiSettings.resolve(environment=environment, repository_root=tmp_path / "repo")
    assert exc_info.value.reason == "webapi-port-invalid"


def test_resolve_rejects_origin_with_path(tmp_path: Path) -> None:
    environment = _valid_environment(tmp_path, WEBAPI_ALLOWED_ORIGIN="http://127.0.0.1:3000/panel")

    with pytest.raises(WebApiSettingsError) as exc_info:
        WebApiSettings.resolve(environment=environment, repository_root=tmp_path / "repo")
    assert exc_info.value.reason == "webapi-allowed-origin-invalid"


def test_resolve_rejects_non_http_origin_scheme(tmp_path: Path) -> None:
    environment = _valid_environment(tmp_path, WEBAPI_ALLOWED_ORIGIN="ftp://127.0.0.1:3000")

    with pytest.raises(WebApiSettingsError) as exc_info:
        WebApiSettings.resolve(environment=environment, repository_root=tmp_path / "repo")
    assert exc_info.value.reason == "webapi-allowed-origin-invalid"


def test_redacted_never_reveals_database_credentials(tmp_path: Path) -> None:
    settings = WebApiSettings.resolve(
        environment=_valid_environment(tmp_path), repository_root=tmp_path / "repo",
    )
    redacted = settings.redacted()
    assert "synthetic:synthetic" not in str(redacted)
