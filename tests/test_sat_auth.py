from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cfdi_vault.sat_auth import (
    SYNTHETIC_AUTH_ENDPOINT,
    SatAuthAuditEvent,
    SatAuthError,
    SatAuthSession,
    SatAuthSessionManager,
    SatSoapAuthenticator,
)
from cfdi_vault.sat_contract import SatAuthResult
from cfdi_vault.sat_transport import FakeSoapTransport, SoapTransportResponse

SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
SAT_NS = "http://DescargaMasivaTerceros.sat.gob.mx"
SAFE_AUTHORIZATION = "SYNTHETIC_AUTHORIZATION_VALUE"
SECOND_AUTHORIZATION = "SYNTHETIC_AUTHORIZATION_VALUE_2"
SYNTHETIC_MARKER = "SYNTHETIC_TOKEN_MARKER"
NOW = datetime(2026, 7, 2, 12, 0, tzinfo=timezone.utc)


def _soap(body: str) -> bytes:
    return f'<soap:Envelope xmlns:soap="{SOAP_NS}" xmlns:sat="{SAT_NS}"><soap:Body>{body}</soap:Body></soap:Envelope>'.encode()


def _auth_response(authorization: str = SAFE_AUTHORIZATION, expires_at: datetime | None = None) -> bytes:
    expiry = (expires_at or NOW + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    return _soap(
        f"<sat:AutenticaResponse><sat:AutenticaResult>"
        f"<sat:Authorization>{authorization}</sat:Authorization><sat:ExpiresAt>{expiry}</sat:ExpiresAt>"
        f"</sat:AutenticaResult></sat:AutenticaResponse>"
    )


class FakeAuthenticator:
    def __init__(self, results: list[SatAuthResult]) -> None:
        self.results = results
        self.calls = 0

    def authenticate(self) -> SatAuthResult:
        self.calls += 1
        return self.results.pop(0)


def _manager(results: list[SatAuthResult], *, now: datetime = NOW) -> SatAuthSessionManager:
    return SatAuthSessionManager(FakeAuthenticator(results), refresh_margin=timedelta(minutes=5), clock=lambda: now)


def test_authenticator_sends_one_synthetic_auth_request_and_parses_authorization_expiry() -> None:
    transport = FakeSoapTransport([SoapTransportResponse(status_code=200, body=_auth_response())])

    result = SatSoapAuthenticator(transport).authenticate()

    assert result.authorization == SAFE_AUTHORIZATION
    assert result.expires_at == NOW + timedelta(hours=1)
    assert len(transport.requests) == 1
    request = transport.requests[0]
    assert request.endpoint == SYNTHETIC_AUTH_ENDPOINT
    assert "synthetic.invalid" in request.endpoint
    assert "sat.gob.mx" not in request.endpoint
    assert b"Autentica" in request.body


def test_session_manager_reuses_non_expired_session() -> None:
    manager = _manager([SatAuthResult(authorization=SAFE_AUTHORIZATION, expires_at=NOW + timedelta(hours=1))])
    authenticator = manager._authenticator  # noqa: SLF001 - test double assertion

    first = manager.authenticate()
    second = manager.authenticate()

    assert first is second
    assert first.authorization == SAFE_AUTHORIZATION
    assert authenticator.calls == 1
    assert [event.event for event in manager.audit_events] == ["session_authenticated", "session_reused"]


@pytest.mark.parametrize("expires_delta", [timedelta(seconds=-1), timedelta(minutes=4)])
def test_session_manager_refreshes_expired_or_near_expiry_session(expires_delta: timedelta) -> None:
    manager = _manager(
        [
            SatAuthResult(authorization=SAFE_AUTHORIZATION, expires_at=NOW + expires_delta),
            SatAuthResult(authorization=SECOND_AUTHORIZATION, expires_at=NOW + timedelta(hours=1)),
        ]
    )

    assert manager.authenticate().authorization == SAFE_AUTHORIZATION
    assert manager.authenticate().authorization == SECOND_AUTHORIZATION
    assert [event.event for event in manager.audit_events] == ["session_authenticated", "session_refreshed"]


def test_invalidate_default_reason_is_safe_manual_and_forces_next_authenticate() -> None:
    manager = _manager(
        [
            SatAuthResult(authorization=SAFE_AUTHORIZATION, expires_at=NOW + timedelta(hours=1)),
            SatAuthResult(authorization=SECOND_AUTHORIZATION, expires_at=NOW + timedelta(hours=2)),
        ]
    )

    assert manager.authenticate().authorization == SAFE_AUTHORIZATION
    manager.invalidate()
    assert manager.audit_events[-1].reason == "manual"
    assert "reason='<redacted>'" in repr(manager.audit_events[-1])
    assert manager.authenticate().authorization == SECOND_AUTHORIZATION


def test_audit_events_and_reprs_never_leak_authorization_or_reason_values() -> None:
    opaque_value = "abc123-session-value"
    session = SatAuthSession(authorization=SAFE_AUTHORIZATION, expires_at=NOW + timedelta(hours=1), created_at=NOW)
    event = SatAuthAuditEvent(event="session_invalidated", occurred_at=NOW, reason=f"bearer {SYNTHETIC_MARKER}")
    manager = _manager([SatAuthResult(authorization=opaque_value, expires_at=NOW + timedelta(hours=1))])

    manager.invalidate(reason=f"manual token={SYNTHETIC_MARKER}")
    assert manager.audit_events[-1].reason == "redacted"
    active = manager.authenticate()
    manager.invalidate(reason=active.authorization)
    rendered = f"{session!r} {event!r} {manager.audit_events!r}"

    assert SAFE_AUTHORIZATION not in rendered
    assert SYNTHETIC_MARKER not in rendered
    assert opaque_value not in rendered
    assert manager.audit_events[-1].reason == "redacted"
    assert "authorization=<redacted>" in rendered


def test_auth_error_fault_does_not_leak_marker() -> None:
    transport = FakeSoapTransport([SoapTransportResponse(status_code=200, body=_soap(f"<soap:Fault>{SYNTHETIC_MARKER}</soap:Fault>"))])

    with pytest.raises(SatAuthError) as exc_info:
        SatSoapAuthenticator(transport).authenticate()

    assert SYNTHETIC_MARKER not in str(exc_info.value)
    assert exc_info.value.__cause__ is None


def test_auth_layer_uses_only_fake_transport_and_synthetic_placeholders() -> None:
    transport = FakeSoapTransport([SoapTransportResponse(status_code=200, body=_auth_response())])
    SatSoapAuthenticator(transport).authenticate()

    rendered = f"{transport.requests[0].body!r} {transport.requests[0].headers!r}"
    assert "sat.gob.mx" not in transport.requests[0].endpoint
    assert "clouda.sat.gob.mx" not in rendered
    assert all(extension not in rendered for extension in (".cer", ".key", ".pfx", ".pem", ".p12"))
    assert "RFC" not in rendered
