"""Typed, redacted runtime settings for the local reference system.

This module resolves non-secret process configuration only.  It deliberately
does not read credential material, open a secret provider, contact SAT, or
replace PostgreSQL with a local database.
"""

from __future__ import annotations

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


_DEFAULTS: dict[str, str] = {
    "SAT_MONITOR_ENABLED": "0",
    "CFDI_VAULT_LIVE_WORKER_ENABLED": "0",
}
_BOOLEAN_KEYS = frozenset({"SAT_MONITOR_ENABLED", "CFDI_VAULT_LIVE_WORKER_ENABLED"})
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})
_REFERENCE_KEYS = frozenset({"CFDI_VAULT_COMMIT_REF", "SAT_CAMPAIGN_PROFILE", "SAT_CAMPAIGN_REF", "SAT_CAMPAIGN_GRANT"})
_DOTENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


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

        return cls(
            database_url=database_url,
            rabbitmq_url=_optional_url(value("RABBITMQ_URL"), "rabbitmq"),
            redis_url=_optional_url(value("REDIS_URL"), "redis"),
            storage_root=storage_root,
            sat_monitor_enabled=_boolean(value("SAT_MONITOR_ENABLED"), "SAT_MONITOR_ENABLED"),
            live_worker_enabled=_boolean(
                value("CFDI_VAULT_LIVE_WORKER_ENABLED"), "CFDI_VAULT_LIVE_WORKER_ENABLED"
            ),
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
            "commit_ref_set": bool(self.commit_ref),
            "campaign_profile_set": bool(self.campaign_profile),
            "campaign_ref_set": bool(self.campaign_ref),
            "campaign_grant_set": bool(self.campaign_grant),
        }


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
