from __future__ import annotations

from pathlib import Path

from cfdi_vault.local_preflight import LocalCheckStatus, run_local_preflight
from cfdi_vault.os_secret_providers import (
    InMemorySecretBackend,
    native_provider_for_reference,
)
from cfdi_vault.runtime_settings import RuntimeSettings
from cfdi_vault.secrets import CredentialKind, CredentialReference
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus


def _settings(storage_root: Path) -> RuntimeSettings:
    return RuntimeSettings.resolve(
        environment={
            "DATABASE_URL": "postgresql+psycopg://user:password@localhost:5432/vault",
            "RABBITMQ_URL": "amqp://localhost:5672/",
            "REDIS_URL": "redis://localhost:6379/0",
            "CFDI_STORAGE_ROOT": str(storage_root),
            "CFDI_VAULT_COMMIT_REF": "synthetic-commit",
        },
        repository_root=storage_root.parent / "checkout",
    )


def _profile(tmp_path: Path) -> LocalProfile:
    storage = tmp_path / "storage"
    storage.mkdir()
    credentials = tmp_path / "credentials"
    credentials.mkdir()
    certificate = credentials / "certificate.cer"
    private_key = credentials / "private-key.key"
    certificate.write_bytes(b"SYNTHETIC-CERTIFICATE")
    private_key.write_bytes(b"SYNTHETIC-KEY")
    return LocalProfile(
        profile_id="dummy-profile",
        rfc="XAXX010101000",
        storage_root=storage,
        credential_mode=CredentialMode.COPIED,
        certificate_path=certificate,
        private_key_path=private_key,
        phrase_ref="linux-secret-service://cfdi-vault/setup/dummy-profile/phrase",
        status=LocalProfileStatus.READY,
        certificate_fingerprint="a" * 64,
    )


def test_local_preflight_passes_with_injected_local_probes(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    settings = _settings(profile.storage_root)
    reference = CredentialReference(profile.phrase_ref, CredentialKind.PHRASE)
    provider = native_provider_for_reference(
        reference,
        platform="linux",
        backend=InMemorySecretBackend(),
    )
    provider.store(reference, "SYNTHETIC-PHRASE", purpose="unit-test")

    report = run_local_preflight(
        settings,
        profile,
        provider,
        probes={name: lambda: True for name in ("postgresql", "flyway", "rabbitmq", "redis")},
        repository_root=tmp_path / "checkout",
    )

    assert report.ready is True
    assert all(check.status is LocalCheckStatus.PASSED for check in report.checks)
    assert "SYNTHETIC-PHRASE" not in repr(report.sanitized())
    assert str(tmp_path) not in repr(report.sanitized())


def test_local_preflight_fails_closed_without_dependency_probes(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    settings = _settings(profile.storage_root)
    report = run_local_preflight(settings, profile, provider=None)

    assert report.ready is False
    assert {check.reason for check in report.checks} >= {"dependency-probe-missing", "local-check-failed"}
    assert all("localhost" not in repr(item) for item in report.sanitized()["checks"])


def test_local_preflight_rejects_dummy_provider(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    settings = _settings(profile.storage_root)
    from cfdi_vault.secrets import DummySecretProvider

    report = run_local_preflight(
        settings,
        profile,
        DummySecretProvider(),
        probes={name: lambda: True for name in ("postgresql", "flyway", "rabbitmq", "redis")},
    )

    credential_check = next(check for check in report.checks if check.name == "credentials")
    assert credential_check.status is LocalCheckStatus.FAILED
