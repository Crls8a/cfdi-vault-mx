"""Typed, redacted runtime settings for the local reference system.

This module resolves non-secret process configuration only.  It deliberately
does not read credential material, open a secret provider, contact SAT, or
replace PostgreSQL with a local database.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.engine import make_url

from cfdi_vault.setup_core import DIRECT_CREDENTIAL_ENV_VARS


class RuntimeSettingsError(ValueError):
    """Raised when non-secret runtime configuration is invalid."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class SatTransportSettings:
    """Bounded, non-secret timeouts for one SAT SOAP call."""

    timeout_seconds: float
    connect_timeout_seconds: float
    read_timeout_seconds: float

    @classmethod
    def resolve(
        cls,
        *,
        cli: Mapping[str, object] | None = None,
        environment: Mapping[str, str] | None = None,
        dotenv: Mapping[str, str] | None = None,
    ) -> "SatTransportSettings":
        """Resolve transport values without requiring database or storage config."""

        sources = (cli or {}, environment or {}, dotenv or {})

        def value(key: str) -> str:
            for source in sources:
                if key in source and source[key] is not None:
                    return str(source[key]).strip()
            return _DEFAULTS[key]

        total = _bounded_seconds(value("SAT_TRANSPORT_TIMEOUT_SECONDS"), "timeout", 300)
        connect = _bounded_seconds(
            value("SAT_TRANSPORT_CONNECT_TIMEOUT_SECONDS"), "connect-timeout", 120,
        )
        read = _bounded_seconds(value("SAT_TRANSPORT_READ_TIMEOUT_SECONDS"), "read-timeout", 300)
        if connect > total:
            raise RuntimeSettingsError("runtime-sat-transport-connect-timeout-invalid")
        if read > total:
            raise RuntimeSettingsError("runtime-sat-transport-read-timeout-invalid")
        return cls(total, connect, read)

    def redacted(self) -> dict[str, float]:
        """Return safe numeric values for status output."""

        return {
            "sat_transport_timeout_seconds": self.timeout_seconds,
            "sat_transport_connect_timeout_seconds": self.connect_timeout_seconds,
            "sat_transport_read_timeout_seconds": self.read_timeout_seconds,
        }


_DEFAULTS: dict[str, str] = {
    "SAT_MONITOR_ENABLED": "0",
    "CFDI_VAULT_LIVE_WORKER_ENABLED": "0",
    "SAT_MONITOR_WATCHDOG_SECONDS": "300",
    "SAT_CAMPAIGN_RUN_LEASE_SECONDS": "900",
    "SAT_MONITOR_NOTIFY_CHANNEL": "sat_schedule_changed",
    "SAT_MONITOR_ADAPTIVE_ENABLED": "0",
    "SAT_TRANSPORT_TIMEOUT_SECONDS": "90",
    "SAT_TRANSPORT_CONNECT_TIMEOUT_SECONDS": "15",
    "SAT_TRANSPORT_READ_TIMEOUT_SECONDS": "60",
}
SAT_MONITOR_NOTIFY_CHANNEL = "sat_schedule_changed"
SAT_CAMPAIGN_RUN_LEASE_ENV = "SAT_CAMPAIGN_RUN_LEASE_SECONDS"
_BOOLEAN_KEYS = frozenset(
    {"SAT_MONITOR_ENABLED", "CFDI_VAULT_LIVE_WORKER_ENABLED", "SAT_MONITOR_ADAPTIVE_ENABLED"}
)
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})
_REFERENCE_KEYS = frozenset({"CFDI_VAULT_COMMIT_REF", "SAT_CAMPAIGN_PROFILE", "SAT_CAMPAIGN_REF", "SAT_CAMPAIGN_GRANT"})
_DOTENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_NOTIFY_CHANNEL = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


@dataclass(frozen=True)
class RuntimeSettings:
    """Validated non-secret settings shared by CLI, workers, and monitor.

    ``database_url`` may contain credentials because PostgreSQL URLs commonly
    do; callers must use :meth:`redacted` for logs or user-facing output.
    Credential values for e.firma are never accepted by this model.
    """

    database_url: str
    rabbitmq_url: str | None
    redis_url: str | None
    storage_root: Path
    sat_monitor_enabled: bool
    live_worker_enabled: bool
    sat_monitor_watchdog_seconds: int
    sat_campaign_run_lease_seconds: int
    sat_monitor_notify_channel: str
    sat_monitor_adaptive_enabled: bool
    sat_transport_timeout_seconds: float
    sat_transport_connect_timeout_seconds: float
    sat_transport_read_timeout_seconds: float
    commit_ref: str | None
    campaign_profile: str | None
    campaign_ref: str | None
    campaign_grant: str | None

    @classmethod
    def resolve(
        cls,
        *,
        cli: Mapping[str, object] | None = None,
        environment: Mapping[str, str] | None = None,
        dotenv: Mapping[str, str] | None = None,
        dotenv_path: str | Path | None = None,
        repository_root: str | Path | None = None,
    ) -> "RuntimeSettings":
        """Resolve settings with precedence ``cli`` > environment > dotenv > defaults.

        The resolver accepts mappings so callers can load a dotenv file without
        making hidden filesystem reads.  It rejects direct credential variables
        in every source, requires a PostgreSQL ``DATABASE_URL``, and requires
        an absolute artifact root outside the repository boundary.  The
        boundary defaults to the current working directory and path resolution
        does not require the target directory to exist.
        """

        cli_values = cli or {}
        env_values = environment if environment is not None else os.environ
        dotenv_values = load_dotenv_mapping(dotenv_path) if dotenv_path is not None else {}
        if dotenv:
            dotenv_values.update(dotenv)
        _reject_direct_credentials(cli_values, env_values, dotenv_values)

        def value(key: str) -> str | None:
            for source in (cli_values, env_values, dotenv_values):
                if key in source and source[key] is not None:
                    return str(source[key]).strip()
            default = _DEFAULTS.get(key)
            return default.strip() if default is not None else None

        database_url = value("DATABASE_URL")
        if not database_url:
            raise RuntimeSettingsError("runtime-database-required")
        _validate_database_url(database_url)

        storage_text = value("CFDI_STORAGE_ROOT")
        if not storage_text:
            raise RuntimeSettingsError("runtime-storage-root-required")
        storage_root = _validate_storage_root(storage_text, repository_root)
        transport = SatTransportSettings.resolve(
            cli=cli_values, environment=env_values, dotenv=dotenv_values,
        )

        return cls(
            database_url=database_url,
            rabbitmq_url=_optional_url(value("RABBITMQ_URL"), "rabbitmq"),
            redis_url=_optional_url(value("REDIS_URL"), "redis"),
            storage_root=storage_root,
            sat_monitor_enabled=_boolean(value("SAT_MONITOR_ENABLED"), "SAT_MONITOR_ENABLED"),
            live_worker_enabled=_boolean(
                value("CFDI_VAULT_LIVE_WORKER_ENABLED"), "CFDI_VAULT_LIVE_WORKER_ENABLED"
            ),
            sat_monitor_watchdog_seconds=_positive_int(
                value("SAT_MONITOR_WATCHDOG_SECONDS"), "sat-monitor-watchdog"
            ),
            sat_campaign_run_lease_seconds=_positive_int(
                value(SAT_CAMPAIGN_RUN_LEASE_ENV), "sat-campaign-run-lease"
            ),
            sat_monitor_notify_channel=_notify_channel(value("SAT_MONITOR_NOTIFY_CHANNEL")),
            sat_monitor_adaptive_enabled=_boolean(
                value("SAT_MONITOR_ADAPTIVE_ENABLED"), "SAT_MONITOR_ADAPTIVE_ENABLED"
            ),
            sat_transport_timeout_seconds=transport.timeout_seconds,
            sat_transport_connect_timeout_seconds=transport.connect_timeout_seconds,
            sat_transport_read_timeout_seconds=transport.read_timeout_seconds,
            commit_ref=_optional_reference(value("CFDI_VAULT_COMMIT_REF"), "CFDI_VAULT_COMMIT_REF"),
            campaign_profile=_optional_reference(value("SAT_CAMPAIGN_PROFILE"), "SAT_CAMPAIGN_PROFILE"),
            campaign_ref=_optional_reference(value("SAT_CAMPAIGN_REF"), "SAT_CAMPAIGN_REF"),
            campaign_grant=_optional_reference(value("SAT_CAMPAIGN_GRANT"), "SAT_CAMPAIGN_GRANT"),
        )

    def redacted(self) -> dict[str, object]:
        """Return a log-safe representation without passwords or local paths."""

        return {
            "database_url": _redact_url(self.database_url),
            "rabbitmq_url": _redact_url(self.rabbitmq_url),
            "redis_url": _redact_url(self.redis_url),
            "storage_configured": bool(str(self.storage_root)),
            "sat_monitor_enabled": self.sat_monitor_enabled,
            "live_worker_enabled": self.live_worker_enabled,
            "sat_monitor_watchdog_seconds": self.sat_monitor_watchdog_seconds,
            "sat_campaign_run_lease_seconds": self.sat_campaign_run_lease_seconds,
            "sat_monitor_notify_channel": self.sat_monitor_notify_channel,
            "sat_monitor_adaptive_enabled": self.sat_monitor_adaptive_enabled,
            "sat_transport_timeout_seconds": self.sat_transport_timeout_seconds,
            "sat_transport_connect_timeout_seconds": self.sat_transport_connect_timeout_seconds,
            "sat_transport_read_timeout_seconds": self.sat_transport_read_timeout_seconds,
            "commit_ref_set": bool(self.commit_ref),
            "campaign_profile_set": bool(self.campaign_profile),
            "campaign_ref_set": bool(self.campaign_ref),
            "campaign_grant_set": bool(self.campaign_grant),
        }


def campaign_run_lease_seconds(environment: Mapping[str, str] | None = None) -> int:
    """Resolve the bounded campaign-run lease without requiring full settings.

    Both the panel process (which writes the queued row) and the host-only
    campaign-run consumer (which claims it) need this one value, and neither
    should have to resolve a storage root to read it.  The lease is what makes
    an unclaimed run detectable: a row nobody ever started is abandoned by the
    reaper once ``lease_until`` passes.
    """

    values = environment if environment is not None else os.environ
    raw = values.get(SAT_CAMPAIGN_RUN_LEASE_ENV)
    text = str(raw).strip() if raw is not None else ""
    return _positive_int(text or _DEFAULTS[SAT_CAMPAIGN_RUN_LEASE_ENV], "sat-campaign-run-lease")


def _reject_direct_credentials(*sources: Mapping[str, object]) -> None:
    for source in sources:
        for key in DIRECT_CREDENTIAL_ENV_VARS:
            raw = source.get(key)
            if raw is not None and str(raw).strip():
                raise RuntimeSettingsError("runtime-direct-credential-forbidden")


def load_dotenv_mapping(path: str | Path) -> dict[str, str]:
    """Read a small, non-secret dotenv mapping without mutating the process.

    The parser intentionally supports only ``KEY=VALUE`` lines, optional
    ``export`` prefixes, comments, and matching single/double quotes.  It does
    not expand variables or interpret shell syntax.  Direct e.firma variables
    are returned so :meth:`RuntimeSettings.resolve` can reject them uniformly.
    """

    candidate = Path(path).expanduser()
    try:
        text = candidate.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeError) as exc:
        raise RuntimeSettingsError("runtime-dotenv-read-failed") from exc

    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[7:].lstrip()
        if "=" not in stripped:
            raise RuntimeSettingsError("runtime-dotenv-invalid")
        key, raw_value = (part.strip() for part in stripped.split("=", 1))
        if not _DOTENV_KEY.fullmatch(key):
            raise RuntimeSettingsError("runtime-dotenv-invalid")
        value = raw_value.strip()
        if value[:1] in {"'", '"'}:
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                raise RuntimeSettingsError("runtime-dotenv-invalid")
            value = value[1:-1]
        if "\x00" in value or "\n" in value or "\r" in value:
            raise RuntimeSettingsError("runtime-dotenv-invalid")
        values[key] = value
    return values


def _validate_database_url(value: str) -> None:
    try:
        driver = make_url(value).drivername
    except Exception as exc:
        raise RuntimeSettingsError("runtime-database-url-invalid") from exc
    if not driver.startswith("postgresql"):
        raise RuntimeSettingsError("runtime-database-postgresql-required")


def _optional_url(value: str | None, name: str) -> str | None:
    if not value:
        return None
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        port = parts.port
    except (TypeError, UnicodeError, ValueError) as exc:
        raise RuntimeSettingsError(f"runtime-{name}-url-invalid") from exc
    allowed_schemes = {
        "rabbitmq": frozenset({"amqp", "amqps"}),
        "redis": frozenset({"redis", "rediss"}),
    }.get(name, frozenset())
    if (not parts.scheme or not parts.netloc or not hostname or
            parts.scheme.lower() not in allowed_schemes or
            (port is not None and not 1 <= port <= 65_535)):
        raise RuntimeSettingsError(f"runtime-{name}-url-invalid")
    return value


def _validate_storage_root(value: str, repository_root: str | Path | None) -> Path:
    """Return a canonical absolute storage root outside the repository boundary."""

    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        raise RuntimeSettingsError("runtime-storage-root-absolute-required")
    boundary = Path(repository_root) if repository_root is not None else Path.cwd()
    try:
        resolved_candidate = candidate.resolve(strict=False)
        resolved_boundary = boundary.expanduser().resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise RuntimeSettingsError("runtime-storage-root-invalid") from exc
    try:
        resolved_candidate.relative_to(resolved_boundary)
    except ValueError:
        return resolved_candidate
    raise RuntimeSettingsError("runtime-storage-root-repository-forbidden")


def _boolean(value: str | None, name: str) -> bool:
    normalized = (value or "").lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise RuntimeSettingsError(f"runtime-{name.lower()}-invalid")


def _positive_int(value: str | None, name: str) -> int:
    try:
        parsed = int(value or "")
    except ValueError as exc:
        raise RuntimeSettingsError(f"runtime-{name}-invalid") from exc
    if parsed < 60:
        raise RuntimeSettingsError(f"runtime-{name}-invalid")
    return parsed


def _bounded_seconds(value: str, name: str, maximum: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeSettingsError(f"runtime-sat-transport-{name}-invalid") from exc
    if not math.isfinite(parsed) or parsed <= 0 or parsed > maximum:
        raise RuntimeSettingsError(f"runtime-sat-transport-{name}-invalid")
    return parsed


def _notify_channel(value: str | None) -> str:
    if (
        not value
        or _NOTIFY_CHANNEL.fullmatch(value) is None
        or value != SAT_MONITOR_NOTIFY_CHANNEL
    ):
        raise RuntimeSettingsError("runtime-sat-monitor-notify-channel-invalid")
    return value


def _optional_reference(value: str | None, name: str) -> str | None:
    if value is None or not value:
        return None
    if any(char.isspace() for char in value) or len(value) > 256:
        raise RuntimeSettingsError(f"runtime-{name.lower()}-invalid")
    return value


def _redact_url(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except (TypeError, UnicodeError, ValueError):
        return "<redacted>"
    if not parts.scheme or not parts.netloc or not host:
        return "<redacted>"
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "<redacted>" if parts.query else "", ""))
