"""Offline SAT authentication session primitives."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cfdi_vault.sat_contract import SatAuthResult
from cfdi_vault.sat_soap import build_authentication_envelope
from cfdi_vault.sat_soap_parse import SatSoapParseError, parse_authentication_response
from cfdi_vault.sat_transport import SoapTransportPort, SoapTransportRequest

SYNTHETIC_AUTH_ENDPOINT = "https://synthetic.invalid/cfdi-vault/sat-auth"
SYNTHETIC_AUTH_PLACEHOLDER = "SYNTHETIC_AUTHORIZATION"
DEFAULT_REFRESH_MARGIN = timedelta(minutes=5)

Clock = Callable[[], datetime]
_SAFE_EVENTS = {
    "authentication_failed",
    "session_authenticated",
    "session_invalidated",
    "session_refreshed",
    "session_reused",
}
_SAFE_REASONS = {"auth-error", "manual", "redacted", "unspecified"}


class SatAuthError(RuntimeError):
    """Raised when an offline SAT authentication attempt cannot be normalized."""


@dataclass(frozen=True, repr=False)
class SatAuthSession:
    """In-memory SAT authorization session."""

    authorization: str
    expires_at: datetime | None
    created_at: datetime

    def __repr__(self) -> str:
        return (
            "SatAuthSession(authorization=<redacted>, "
            f"expires_at={self.expires_at!r}, created_at={self.created_at!r})"
        )


@dataclass(frozen=True, repr=False)
class SatAuthAuditEvent:
    """Redacted audit event for SAT auth session lifecycle changes."""

    event: str
    occurred_at: datetime
    reason: str | None = None
    expires_at: datetime | None = None

    def __repr__(self) -> str:
        event = self.event if self.event in _SAFE_EVENTS else "<redacted>"
        reason = "<redacted>" if self.reason is not None else None
        return (
            f"SatAuthAuditEvent(event={event!r}, occurred_at={self.occurred_at!r}, "
            f"reason={reason!r}, expires_at={self.expires_at!r})"
        )


class SatSoapAuthenticator:
    """Build, send, and parse one synthetic SAT authentication SOAP request."""

    def __init__(
        self,
        transport: SoapTransportPort,
        *,
        endpoint: str = SYNTHETIC_AUTH_ENDPOINT,
        timeout_seconds: float | None = None,
        synthetic_placeholder: str = SYNTHETIC_AUTH_PLACEHOLDER,
    ) -> None:
        if not endpoint:
            raise ValueError("endpoint is required")
        self._transport = transport
        self._endpoint = endpoint
        self._timeout_seconds = timeout_seconds
        self._synthetic_placeholder = synthetic_placeholder

    def authenticate(self) -> SatAuthResult:
        """Return normalized SAT authorization data from an injected transport."""

        request = SoapTransportRequest(
            endpoint=self._endpoint,
            body=build_authentication_envelope(self._synthetic_placeholder),
            headers={"Content-Type": "application/soap+xml; charset=utf-8"},
            timeout_seconds=self._timeout_seconds,
        )
        try:
            response = self._transport.send(request)
            if not 200 <= response.status_code < 300:
                raise SatAuthError("SAT authentication transport returned a non-success status")
            return parse_authentication_response(response.body)
        except SatAuthError:
            raise
        except (SatSoapParseError, ValueError):
            raise SatAuthError("SAT authentication response could not be parsed") from None
        except Exception:
            raise SatAuthError("SAT authentication transport failed") from None


class SatAuthSessionManager:
    """In-memory SAT auth session cache with refresh and redacted audit events."""

    def __init__(
        self,
        authenticator: SatSoapAuthenticator,
        *,
        refresh_margin: timedelta = DEFAULT_REFRESH_MARGIN,
        clock: Clock | None = None,
    ) -> None:
        if refresh_margin < timedelta(0):
            raise ValueError("refresh_margin must be non-negative")
        self._authenticator = authenticator
        self._refresh_margin = refresh_margin
        self._clock = clock or _utc_now
        self._session: SatAuthSession | None = None
        self._audit_events: list[SatAuthAuditEvent] = []

    @property
    def audit_events(self) -> tuple[SatAuthAuditEvent, ...]:
        """Return lifecycle events without token/session values."""

        return tuple(self._audit_events)

    def authenticate(self) -> SatAuthSession:
        """Return a cached session when valid, otherwise authenticate again."""

        now = _normalize_datetime(self._clock())
        if self._session is not None and not self._needs_refresh(self._session, now):
            self._record("session_reused", now, expires_at=self._session.expires_at)
            return self._session

        event = "session_refreshed" if self._session is not None else "session_authenticated"
        try:
            result = self._authenticator.authenticate()
        except SatAuthError:
            self._record("authentication_failed", now, reason="auth-error")
            raise
        except Exception:
            self._record("authentication_failed", now, reason="auth-error")
            raise SatAuthError("SAT authentication failed") from None

        self._session = SatAuthSession(
            authorization=result.authorization,
            expires_at=_normalize_datetime(result.expires_at) if result.expires_at else None,
            created_at=now,
        )
        self._record(event, now, expires_at=self._session.expires_at)
        return self._session

    def invalidate(self, reason: str = "manual") -> None:
        """Forget the cached session without storing caller-provided reason text."""

        self._session = None
        self._record("session_invalidated", _normalize_datetime(self._clock()), reason=_safe_external_reason(reason))

    def _needs_refresh(self, session: SatAuthSession, now: datetime) -> bool:
        return session.expires_at is not None and _normalize_datetime(session.expires_at) <= now + self._refresh_margin

    def _record(
        self,
        event: str,
        occurred_at: datetime,
        *,
        reason: str | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        self._audit_events.append(
            SatAuthAuditEvent(
                event=event if event in _SAFE_EVENTS else "redacted",
                occurred_at=occurred_at,
                reason=_safe_reason(reason),
                expires_at=expires_at,
            )
        )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_datetime(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _safe_external_reason(value: str | None) -> str:
    if not value:
        return "unspecified"
    return "manual" if value.strip().lower().replace("_", "-") == "manual" else "redacted"


def _safe_reason(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower().replace("_", "-")
    return normalized if normalized in _SAFE_REASONS else "redacted"
