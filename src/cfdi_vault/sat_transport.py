"""Guarded SOAP transport boundary for SAT adapters.

This module defines transport primitives only. Live SAT access must remain
behind explicit guards and injectable I/O so tests and offline flows never
perform network calls accidentally.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from urllib import request as urllib_request

_FALSEY_ENV_VALUES = {"", "0", "false", "no", "off"}


@dataclass(frozen=True, repr=False)
class SoapTransportRequest:
    """SOAP HTTP request payload without leaking body/header values in repr."""

    endpoint: str
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)
    timeout_seconds: float | None = None

    def __repr__(self) -> str:
        return (
            "SoapTransportRequest("
            f"endpoint={_redact_endpoint(self.endpoint)!r}, "
            f"headers={_redact_headers(self.headers)!r}, "
            f"body=<redacted {len(self.body)} bytes>, "
            f"timeout_seconds={self.timeout_seconds!r})"
        )


@dataclass(frozen=True, repr=False)
class SoapTransportResponse:
    """SOAP HTTP response payload without leaking body/header values in repr."""

    status_code: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""
    reason: str = ""

    def __repr__(self) -> str:
        return (
            "SoapTransportResponse("
            f"status_code={self.status_code!r}, "
            f"headers={_redact_headers(self.headers)!r}, "
            f"body=<redacted {len(self.body)} bytes>, "
            f"reason={self.reason!r})"
        )


class SoapTransportPort(Protocol):
    """Boundary for sending SOAP requests."""

    def send(self, request: SoapTransportRequest) -> SoapTransportResponse:
        """Send one SOAP request and return a normalized transport response."""


class LiveSatGuardError(RuntimeError):
    """Raised before network I/O when live SAT safety gates are not satisfied."""

    def __init__(self, reasons: Sequence[str]) -> None:
        self.reasons = tuple(reasons)
        super().__init__("live SAT transport denied: " + ", ".join(self.reasons))


@dataclass(frozen=True)
class LiveSatGuardInput:
    """Injectable live SAT guard state.

    Defaults are intentionally safe: manual access is false and readiness
    checks are false, so a default guard always denies live network I/O.
    """

    manual_real_sat: bool = False
    terminal_interactive: bool = False
    confirmation_verified: bool = False
    profile_ready: bool = False
    credentials_ready: bool = False
    doctor_ok: bool = False
    scanner_passed: bool = False
    repo_clean: bool = False
    metadata_only: bool = False
    range_within_limit: bool = False
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)


def validate_live_sat_guard(input: LiveSatGuardInput) -> None:
    """Raise before network I/O unless every live SAT gate is satisfied."""

    reasons: list[str] = []
    if _is_truthy(input.environ.get("CI")):
        reasons.append("ci-enabled")
    if input.environ.get("CFDI_VAULT_ALLOW_REAL_SAT") != "1":
        reasons.append("missing-explicit-real-sat-env")
    if input.environ.get("CFDI_VAULT_ALLOW_REAL_CREDENTIALS") != "1":
        reasons.append("missing-explicit-real-credentials-env")
    if not input.manual_real_sat:
        reasons.append("missing-manual-real-sat-flag")
    if not input.terminal_interactive:
        reasons.append("non-interactive-terminal")
    if not input.confirmation_verified:
        reasons.append("missing-live-smoke-confirmation")
    if not input.profile_ready:
        reasons.append("profile-not-ready")
    if not input.credentials_ready:
        reasons.append("local-credentials-not-ready")
    if not input.doctor_ok:
        reasons.append("doctor-not-ok")
    if not input.scanner_passed:
        reasons.append("scanner-not-passed")
    if not input.repo_clean:
        reasons.append("repo-dirty")
    if not input.metadata_only:
        reasons.append("metadata-only-required")
    if not input.range_within_limit:
        reasons.append("range-too-wide")
    if reasons:
        raise LiveSatGuardError(reasons)


class FakeSoapTransport:
    """Offline SOAP transport that records requests and returns synthetic responses."""

    def __init__(self, responses: Sequence[SoapTransportResponse] | None = None) -> None:
        self._responses = list(responses or [SoapTransportResponse(status_code=200, body=b"SYNTHETIC_SOAP_RESPONSE")])
        self.requests: list[SoapTransportRequest] = []

    def send(self, request: SoapTransportRequest) -> SoapTransportResponse:
        self.requests.append(request)
        if not self._responses:
            return SoapTransportResponse(status_code=200, body=b"SYNTHETIC_SOAP_RESPONSE")
        return self._responses.pop(0)


SoapSender = Callable[[SoapTransportRequest], SoapTransportResponse]
GuardInputFactory = Callable[[], LiveSatGuardInput]


class GuardedSoapHttpTransport:
    """HTTP SOAP adapter protected by explicit live SAT guards."""

    def __init__(
        self,
        *,
        sender: SoapSender | None = None,
        opener: object | None = None,
        guard_input_factory: GuardInputFactory | None = None,
    ) -> None:
        self._sender = sender
        self._opener = opener
        self._guard_input_factory = guard_input_factory or LiveSatGuardInput

    def send(self, request: SoapTransportRequest) -> SoapTransportResponse:
        validate_live_sat_guard(self._guard_input_factory())
        if self._sender is not None:
            return self._sender(request)
        return self._send_with_urllib(request)

    def _send_with_urllib(self, request: SoapTransportRequest) -> SoapTransportResponse:
        http_request = urllib_request.Request(
            request.endpoint,
            data=request.body,
            headers=dict(request.headers),
            method="POST",
        )
        opener = self._opener or urllib_request.build_opener()
        response = opener.open(http_request, timeout=request.timeout_seconds)  # type: ignore[attr-defined]
        with response:
            return SoapTransportResponse(
                status_code=response.getcode(),
                headers=dict(response.headers.items()),
                body=response.read(),
                reason=getattr(response, "reason", ""),
            )


def _is_truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() not in _FALSEY_ENV_VALUES


def _redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {key: "<redacted>" for key in headers}


def _redact_endpoint(endpoint: str) -> str:
    parts = urlsplit(endpoint)
    netloc = parts.netloc
    if "@" in netloc:
        _, host = netloc.rsplit("@", 1)
        netloc = f"<redacted>@{host}"
    query = urlencode([(key, "<redacted>") for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))
