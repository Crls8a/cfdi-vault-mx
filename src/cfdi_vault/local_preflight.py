"""Sanitized local readiness checks for configuration and worker startup.

The preflight validates only local state and configured dependencies.  It does
not create SAT requests, resolve credential values, or contact SAT.  Probe
implementations are injectable so CI can prove the contract without requiring
PostgreSQL, RabbitMQ, Redis, or an OS credential store.
"""

from __future__ import annotations

import socket
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit

from cfdi_vault.runtime_settings import RuntimeSettings
from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference, DummySecretProvider
from cfdi_vault.setup_core import ExistenceProvider, LocalProfile, LocalProfileStatus


class LocalPreflightError(ValueError):
    """Raised when a local readiness report cannot be constructed safely."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class LocalCheckStatus(StrEnum):
    """Sanitized outcome for one local dependency check."""

    PASSED = "passed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class LocalCheck:
    """One fixed-name, fixed-reason local readiness result."""

    name: str
    status: LocalCheckStatus
    reason: str


@dataclass(frozen=True, slots=True)
class LocalPreflightReport:
    """Aggregate local readiness without paths, URLs, or credential values."""

    checks: tuple[LocalCheck, ...]

    @property
    def ready(self) -> bool:
        """Return whether every required local check passed."""

        return all(check.status is LocalCheckStatus.PASSED for check in self.checks)

    def sanitized(self) -> dict[str, object]:
        """Return the only representation allowed in CLI/log output."""

        return {
            "ready": self.ready,
            "checks": [
                {"name": check.name, "status": check.status.value, "reason": check.reason}
                for check in self.checks
            ],
        }


Probe = Callable[[], bool]
_CHECK_NAMES = (
    "profile",
    "credentials",
    "storage",
    "commit",
    "postgresql",
    "flyway",
    "rabbitmq",
    "redis",
)


def run_local_preflight(
    settings: RuntimeSettings,
    profile: LocalProfile,
    provider: ExistenceProvider | None,
    *,
    probes: Mapping[str, Probe] | None = None,
    repository_root: Path | None = None,
) -> LocalPreflightReport:
    """Run local checks with injected dependency probes and fixed redaction."""

    if type(settings) is not RuntimeSettings:
        raise LocalPreflightError("local-preflight-settings-invalid")
    probe_map = dict(probes or {})
    checks = [
        _check("profile", lambda: _profile_ready(profile, settings, repository_root)),
        _check("credentials", lambda: _credentials_ready(profile, provider)),
        _check("storage", lambda: _storage_ready(settings, profile)),
        _check("commit", lambda: bool(settings.commit_ref)),
    ]
    for name in _CHECK_NAMES[4:]:
        checks.append(_probe_check(name, probe_map.get(name)))
    return LocalPreflightReport(tuple(checks))


def default_local_probes(settings: RuntimeSettings) -> dict[str, Probe]:
    """Build non-SAT probes for configured PostgreSQL, Flyway, and brokers."""

    return {
        "postgresql": lambda: _probe_postgresql(settings.database_url),
        "flyway": lambda: _probe_flyway(settings.database_url),
        "rabbitmq": lambda: _probe_socket(settings.rabbitmq_url, default_port=5672),
        "redis": lambda: _probe_socket(settings.redis_url, default_port=6379),
    }


def _check(name: str, operation: Probe) -> LocalCheck:
    try:
        passed = operation() is True
    except Exception:
        passed = False
    return LocalCheck(name, LocalCheckStatus.PASSED if passed else LocalCheckStatus.FAILED, "ok" if passed else "local-check-failed")


def _probe_check(name: str, probe: Probe | None) -> LocalCheck:
    if probe is None:
        return LocalCheck(name, LocalCheckStatus.FAILED, "dependency-probe-missing")
    return _check(name, probe)


def _profile_ready(profile: LocalProfile, settings: RuntimeSettings, repository_root: Path | None) -> bool:
    if type(profile) is not LocalProfile or profile.status is not LocalProfileStatus.READY:
        return False
    if repository_root is not None and _inside(profile.storage_root, repository_root):
        return False
    return profile.certificate_path.is_file() and profile.private_key_path.is_file()


def _credentials_ready(profile: LocalProfile, provider: ExistenceProvider | None) -> bool:
    if provider is None or isinstance(provider, DummySecretProvider):
        return False
    reference = CredentialReference(profile.phrase_ref, CredentialKind.PHRASE)
    if getattr(provider, "provider_scheme", None) != reference.provider_scheme:
        return False
    try:
        return provider.exists(reference, purpose="local-preflight") is True
    except CredentialProviderError:
        return False


def _storage_ready(settings: RuntimeSettings, profile: LocalProfile) -> bool:
    try:
        return (
            settings.storage_root.resolve(strict=False) == profile.storage_root.resolve(strict=False)
            and settings.storage_root.is_dir()
        )
    except OSError:
        return False


def _inside(candidate: Path, root: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, ValueError):
        return False
    return True


def _probe_postgresql(database_url: str) -> bool:
    from sqlalchemy import create_engine, text

    engine = create_engine(database_url, future=True)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    finally:
        engine.dispose()


def _probe_flyway(database_url: str) -> bool:
    from sqlalchemy import create_engine, text

    engine = create_engine(database_url, future=True)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT installed_rank FROM flyway_schema_history LIMIT 1"))
        return True
    finally:
        engine.dispose()


def _probe_socket(url: str | None, *, default_port: int) -> bool:
    if not url:
        return False
    parsed = urlsplit(url)
    host = parsed.hostname
    port = parsed.port or default_port
    if not host or not 1 <= port <= 65_535:
        return False
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False
