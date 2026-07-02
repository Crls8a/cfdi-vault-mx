from __future__ import annotations

import pytest

from cfdi_vault.sat_transport import (
    FakeSoapTransport,
    GuardedSoapHttpTransport,
    LiveSatGuardError,
    LiveSatGuardInput,
    SoapTransportRequest,
    SoapTransportResponse,
    validate_live_sat_guard,
)


SAFE_ENDPOINT = "https://synthetic.invalid/sat/soap?token=URL_SECRET_TOKEN&trace=SYNTHETIC_TRACE"
SAFE_BODY = b"<soap:SYNTHETIC>OK</soap:SYNTHETIC>"


def _request() -> SoapTransportRequest:
    return SoapTransportRequest(
        endpoint=SAFE_ENDPOINT,
        body=SAFE_BODY,
        headers={"Content-Type": "text/xml", "Authorization": "Bearer SECRET_TOKEN_VALUE"},
    )


def _passing_guard() -> LiveSatGuardInput:
    return LiveSatGuardInput(
        manual_real_sat=True,
        profile_ready=True,
        scanner_passed=True,
        repo_clean=True,
        environ={"CFDI_VAULT_ALLOW_REAL_SAT": "1"},
    )


def test_fake_transport_records_requests_and_returns_synthetic_response_without_network() -> None:
    response = SoapTransportResponse(status_code=202, body=b"SYNTHETIC_RESPONSE")
    transport = FakeSoapTransport([response])

    result = transport.send(_request())

    assert result == response
    assert len(transport.requests) == 1
    assert transport.requests[0].endpoint == SAFE_ENDPOINT


@pytest.mark.parametrize(
    ("guard", "reason"),
    [
        (
            LiveSatGuardInput(
                manual_real_sat=True,
                profile_ready=True,
                scanner_passed=True,
                repo_clean=True,
                environ={"CI": "true", "CFDI_VAULT_ALLOW_REAL_SAT": "1"},
            ),
            "ci-enabled",
        ),
        (
            LiveSatGuardInput(
                manual_real_sat=True,
                profile_ready=True,
                scanner_passed=True,
                repo_clean=True,
                environ={},
            ),
            "missing-explicit-real-sat-env",
        ),
        (
            LiveSatGuardInput(
                manual_real_sat=False,
                profile_ready=True,
                scanner_passed=True,
                repo_clean=True,
                environ={"CFDI_VAULT_ALLOW_REAL_SAT": "1"},
            ),
            "missing-manual-real-sat-flag",
        ),
        (
            LiveSatGuardInput(
                manual_real_sat=True,
                profile_ready=False,
                scanner_passed=True,
                repo_clean=True,
                environ={"CFDI_VAULT_ALLOW_REAL_SAT": "1"},
            ),
            "profile-not-ready",
        ),
        (
            LiveSatGuardInput(
                manual_real_sat=True,
                profile_ready=True,
                scanner_passed=False,
                repo_clean=True,
                environ={"CFDI_VAULT_ALLOW_REAL_SAT": "1"},
            ),
            "scanner-not-passed",
        ),
        (
            LiveSatGuardInput(
                manual_real_sat=True,
                profile_ready=True,
                scanner_passed=True,
                repo_clean=False,
                environ={"CFDI_VAULT_ALLOW_REAL_SAT": "1"},
            ),
            "repo-dirty",
        ),
    ],
)
def test_live_sat_guard_denies_each_required_gate(guard: LiveSatGuardInput, reason: str) -> None:
    with pytest.raises(LiveSatGuardError) as exc_info:
        validate_live_sat_guard(guard)

    assert reason in exc_info.value.reasons
    assert reason in str(exc_info.value)


def test_http_adapter_does_not_call_sender_when_guard_fails() -> None:
    calls: list[SoapTransportRequest] = []

    def sender(request: SoapTransportRequest) -> SoapTransportResponse:
        calls.append(request)
        return SoapTransportResponse(status_code=200, body=b"SHOULD_NOT_HAPPEN")

    transport = GuardedSoapHttpTransport(
        sender=sender,
        guard_input_factory=lambda: LiveSatGuardInput(environ={}),
    )

    with pytest.raises(LiveSatGuardError):
        transport.send(_request())

    assert calls == []


def test_http_adapter_calls_injected_sender_only_when_all_guards_pass() -> None:
    calls: list[SoapTransportRequest] = []

    def sender(request: SoapTransportRequest) -> SoapTransportResponse:
        calls.append(request)
        return SoapTransportResponse(status_code=200, body=b"SYNTHETIC_OK")

    transport = GuardedSoapHttpTransport(sender=sender, guard_input_factory=_passing_guard)

    response = transport.send(_request())

    assert response.status_code == 200
    assert response.body == b"SYNTHETIC_OK"
    assert calls == [_request()]


def test_repr_and_guard_errors_do_not_leak_authorization_tokens_or_body() -> None:
    request = _request()
    response = SoapTransportResponse(
        status_code=200,
        headers={"Set-Cookie": "SESSION_SECRET", "X-Trace": "SYNTHETIC_TRACE"},
        body=b"<secret>BODY_SECRET</secret>",
    )

    rendered = f"{request!r} {response!r}"

    assert "SECRET_TOKEN_VALUE" not in rendered
    assert "URL_SECRET_TOKEN" not in rendered
    assert "Bearer" not in rendered
    assert "SESSION_SECRET" not in rendered
    assert "BODY_SECRET" not in rendered
    assert SAFE_BODY.decode() not in rendered
    assert "<redacted" in rendered
    assert "SYNTHETIC_TRACE" not in rendered
    assert "trace=" in rendered

    with pytest.raises(LiveSatGuardError) as exc_info:
        GuardedSoapHttpTransport(
            sender=lambda _: response,
            guard_input_factory=lambda: LiveSatGuardInput(environ={}),
        ).send(request)

    error_text = str(exc_info.value)
    assert "SECRET_TOKEN_VALUE" not in error_text
    assert "BODY_SECRET" not in error_text
    assert SAFE_BODY.decode() not in error_text
