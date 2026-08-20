"""Typed, validated settings for the local control-panel API (ADR 0004).

This module adds exactly three new non-secret settings on top of
:class:`cfdi_vault.runtime_settings.RuntimeSettings`: the bind host, the bind
port, and the allowed browser origin for the CSRF/origin guard.  It does not
duplicate ``RuntimeSettings`` validation; it wraps it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

from cfdi_vault.runtime_settings import RuntimeSettings, load_dotenv_mapping

_LOOPBACK_HOST = "127.0.0.1"
_DEFAULT_PORT = "8420"
_DEFAULT_ALLOWED_ORIGIN = "http://127.0.0.1:3000"


class WebApiSettingsError(ValueError):
    """Raised when control-panel API configuration is invalid."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class WebApiSettings:
    """Validated settings for the local-only control-panel API process."""

    runtime: RuntimeSettings
    webapi_host: str
    webapi_port: int
    webapi_allowed_origin: str

    @classmethod
    def resolve(
        cls,
        *,
        cli: Mapping[str, object] | None = None,
        environment: Mapping[str, str] | None = None,
        dotenv: Mapping[str, str] | None = None,
        dotenv_path: str | Path | None = None,
        repository_root: str | Path | None = None,
    ) -> "WebApiSettings":
        """Resolve settings with precedence ``cli`` > environment > dotenv > defaults."""

        runtime = RuntimeSettings.resolve(
            cli=cli,
            environment=environment,
            dotenv=dotenv,
            dotenv_path=dotenv_path,
            repository_root=repository_root,
        )

        cli_values = cli or {}
        env_values = environment if environment is not None else os.environ
        dotenv_values = load_dotenv_mapping(dotenv_path) if dotenv_path is not None else {}
        if dotenv:
            dotenv_values = dict(dotenv_values)
            dotenv_values.update(dotenv)

        def value(key: str, default: str) -> str:
            for source in (cli_values, env_values, dotenv_values):
                if key in source and source[key] is not None:
                    return str(source[key]).strip()
            return default

        host = value("WEBAPI_HOST", _LOOPBACK_HOST)
        if host != _LOOPBACK_HOST:
            raise WebApiSettingsError("webapi-host-loopback-required")

        port = _validate_port(value("WEBAPI_PORT", _DEFAULT_PORT))
        origin = _validate_origin(value("WEBAPI_ALLOWED_ORIGIN", _DEFAULT_ALLOWED_ORIGIN))

        return cls(
            runtime=runtime,
            webapi_host=host,
            webapi_port=port,
            webapi_allowed_origin=origin,
        )

    def redacted(self) -> dict[str, object]:
        """Return a log-safe representation without passwords or local paths."""

        return {
            "runtime": self.runtime.redacted(),
            "webapi_host": self.webapi_host,
            "webapi_port": self.webapi_port,
            "webapi_allowed_origin": self.webapi_allowed_origin,
        }


def _validate_port(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise WebApiSettingsError("webapi-port-invalid") from exc
    if not 1 <= parsed <= 65_535:
        raise WebApiSettingsError("webapi-port-invalid")
    return parsed


def _validate_origin(value: str) -> str:
    try:
        parts = urlsplit(value)
    except (TypeError, UnicodeError, ValueError) as exc:
        raise WebApiSettingsError("webapi-allowed-origin-invalid") from exc
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not parts.netloc
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
    ):
        raise WebApiSettingsError("webapi-allowed-origin-invalid")
    return f"{parts.scheme.lower()}://{parts.netloc}"
