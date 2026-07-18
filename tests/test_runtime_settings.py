from __future__ import annotations

import os
from pathlib import Path

import pytest

from cfdi_vault.runtime_settings import (
    RuntimeSettings,
    RuntimeSettingsError,
    _redact_url,
    load_dotenv_mapping,
)

BASE_ENV = {
    "DATABASE_URL": "postgresql+psycopg://user:password@localhost:5432/vault",
    "RABBITMQ_URL": "amqp://user:password@localhost:5672/",
    "REDIS_URL": "redis://:password@localhost:6379/0",
    "CFDI_STORAGE_ROOT": str(Path.cwd().parent / "cfdi-vault-runtime-storage"),
}


def test_resolve_precedence_and_defaults() -> None:
    cli_storage = str(Path.cwd().parent / "cli-storage")
    env_storage = str(Path.cwd().parent / "env-storage")
    dotenv_storage = str(Path.cwd().parent / "dotenv-storage")
    settings = RuntimeSettings.resolve(
        cli={"CFDI_STORAGE_ROOT": cli_storage, "SAT_MONITOR_ENABLED": "true"},
        environment={**BASE_ENV, "CFDI_STORAGE_ROOT": env_storage, "SAT_MONITOR_ENABLED": "0"},
        dotenv={"CFDI_STORAGE_ROOT": dotenv_storage},
    )

    assert settings.storage_root == Path(cli_storage).resolve(strict=False)
    assert settings.sat_monitor_enabled is True
    assert settings.live_worker_enabled is False


def test_load_dotenv_mapping_supports_safe_lines_and_resolve_precedence(tmp_path: Path) -> None:
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text(
        "# local non-secret settings\n"
        "export DATABASE_URL=postgresql+psycopg://dotenv@localhost:5432/vault\n"
        "CFDI_STORAGE_ROOT=\"%s\"\n" % (tmp_path / "storage"),
        encoding="utf-8",
    )

    values = load_dotenv_mapping(dotenv_path)
    settings = RuntimeSettings.resolve(
        dotenv_path=dotenv_path,
        repository_root=tmp_path / "checkout",
    )

    assert values["DATABASE_URL"].startswith("postgresql+")
    assert settings.database_url == values["DATABASE_URL"]
    assert settings.storage_root == (tmp_path / "storage").resolve(strict=False)


def test_load_dotenv_mapping_rejects_direct_credential_values(tmp_path: Path) -> None:
    dotenv_path = tmp_path / ".env"
    dotenv_path.write_text(
        "DATABASE_URL=postgresql+psycopg://localhost/vault\n"
        "CFDI_VAULT_EFIRMA_PASSWORD=synthetic\n"
        "CFDI_STORAGE_ROOT=%s\n" % (tmp_path / "storage"),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeSettingsError, match="runtime-direct-credential-forbidden"):
        RuntimeSettings.resolve(dotenv_path=dotenv_path, repository_root=tmp_path / "checkout")


def test_resolve_accepts_postgres_and_redacts_urls() -> None:
    settings = RuntimeSettings.resolve(environment=BASE_ENV)
    safe = settings.redacted()

    assert safe["database_url"] == "postgresql+psycopg://localhost:5432/vault"
    assert safe["rabbitmq_url"] == "amqp://localhost:5672/"
    assert safe["redis_url"] == "redis://localhost:6379/0"
    assert "password" not in repr(safe)
    assert safe["storage_configured"] is True


@pytest.mark.parametrize("value", ["sqlite:///vault.db", "mysql://localhost/vault", "not-a-url"])
def test_resolve_rejects_non_postgres_database(value: str) -> None:
    with pytest.raises(RuntimeSettingsError) as error:
        RuntimeSettings.resolve(environment={"DATABASE_URL": value})
    assert error.value.reason in {"runtime-database-postgresql-required", "runtime-database-url-invalid"}


def test_resolve_rejects_direct_credential_environment() -> None:
    with pytest.raises(RuntimeSettingsError, match="runtime-direct-credential-forbidden"):
        RuntimeSettings.resolve(environment={**BASE_ENV, "CFDI_VAULT_EFIRMA_PASSWORD": "secret"})


def test_resolve_rejects_invalid_flag_and_url() -> None:
    with pytest.raises(RuntimeSettingsError, match="runtime-sat_monitor_enabled-invalid"):
        RuntimeSettings.resolve(environment={**BASE_ENV, "SAT_MONITOR_ENABLED": "sometimes"})
    with pytest.raises(RuntimeSettingsError, match="runtime-rabbitmq-url-invalid"):
        RuntimeSettings.resolve(environment={**BASE_ENV, "RABBITMQ_URL": "localhost"})


def test_resolve_accepts_opaque_runtime_references() -> None:
    settings = RuntimeSettings.resolve(
        environment={
            **BASE_ENV,
            "CFDI_VAULT_COMMIT_REF": "abc123",
            "SAT_CAMPAIGN_PROFILE": "local-profile",
            "SAT_CAMPAIGN_REF": "campaign-ref",
            "SAT_CAMPAIGN_GRANT": "grant-ref",
        }
    )
    assert settings.commit_ref == "abc123"
    assert settings.campaign_profile == "local-profile"


def test_storage_root_requires_absolute_path() -> None:
    with pytest.raises(RuntimeSettingsError, match="runtime-storage-root-absolute-required"):
        RuntimeSettings.resolve(environment={**BASE_ENV, "CFDI_STORAGE_ROOT": "relative-storage"})


def test_storage_root_rejects_default_current_working_directory_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeSettingsError, match="runtime-storage-root-repository-forbidden"):
        RuntimeSettings.resolve(environment={**BASE_ENV, "CFDI_STORAGE_ROOT": str(tmp_path / "private")})


def test_storage_root_rejects_explicit_repository_boundary(tmp_path: Path) -> None:
    repository_root = tmp_path / "checkout"
    with pytest.raises(RuntimeSettingsError, match="runtime-storage-root-repository-forbidden"):
        RuntimeSettings.resolve(
            environment={**BASE_ENV, "CFDI_STORAGE_ROOT": str(repository_root / "storage")},
            repository_root=repository_root,
        )


def test_storage_root_outside_explicit_boundary_need_not_exist(tmp_path: Path) -> None:
    repository_root = tmp_path / "checkout"
    storage_root = tmp_path / "private-storage"
    settings = RuntimeSettings.resolve(
        environment={**BASE_ENV, "CFDI_STORAGE_ROOT": str(storage_root)},
        repository_root=repository_root,
    )
    assert settings.storage_root == storage_root.resolve(strict=False)
    assert not storage_root.exists()


@pytest.mark.parametrize(
    ("key", "value", "reason"),
    [
        ("RABBITMQ_URL", "redis://localhost:6379/0", "runtime-rabbitmq-url-invalid"),
        ("REDIS_URL", "amqp://localhost:5672/", "runtime-redis-url-invalid"),
    ],
)
def test_resolve_rejects_wrong_message_broker_scheme(key: str, value: str, reason: str) -> None:
    with pytest.raises(RuntimeSettingsError, match=reason):
        RuntimeSettings.resolve(environment={**BASE_ENV, key: value})


def test_windows_style_storage_path_is_handled_without_files(tmp_path: Path) -> None:
    windows_style = r"C:\sat-vault-storage"
    if os.name != "nt":
        with pytest.raises(RuntimeSettingsError, match="runtime-storage-root-absolute-required"):
            RuntimeSettings.resolve(environment={**BASE_ENV, "CFDI_STORAGE_ROOT": windows_style})
        return
    settings = RuntimeSettings.resolve(
        environment={**BASE_ENV, "CFDI_STORAGE_ROOT": windows_style},
        repository_root=r"C:\cfdi-vault-checkout",
    )
    assert settings.storage_root == Path(windows_style).resolve(strict=False)
    assert not settings.storage_root.exists()


@pytest.mark.parametrize(
    "key,value",
    [
        ("RABBITMQ_URL", "amqp://localhost:not-a-port/"),
        ("REDIS_URL", "redis://localhost:65536/0"),
        ("RABBITMQ_URL", "amqp://[::1/"),
        ("REDIS_URL", "redis://:6379/0"),
    ],
)
def test_resolve_rejects_malformed_port_ipv6_or_empty_host(key: str, value: str) -> None:
    with pytest.raises(RuntimeSettingsError, match=f"runtime-{key.split('_')[0].lower()}-url-invalid"):
        RuntimeSettings.resolve(environment={**BASE_ENV, key: value})


def test_resolve_accepts_bracketed_ipv6_broker_urls() -> None:
    settings = RuntimeSettings.resolve(
        environment={
            **BASE_ENV,
            "RABBITMQ_URL": "amqps://[::1]:5671/",
            "REDIS_URL": "rediss://[::1]:6380/0",
        }
    )
    assert settings.rabbitmq_url == "amqps://[::1]:5671/"
    assert settings.redis_url == "rediss://[::1]:6380/0"


@pytest.mark.parametrize("value", ["amqp://localhost:not-a-port/", "amqp://[::1/", "not a url"])
def test_redact_url_is_fail_safe_for_malformed_input(value: str) -> None:
    assert _redact_url(value) == "<redacted>"


def test_redact_url_preserves_bracketed_ipv6_without_credentials() -> None:
    assert _redact_url("amqps://user:password@[::1]:5671/vhost?query=value") == (
        "amqps://[::1]:5671/vhost?<redacted>"
    )
