from __future__ import annotations

from dataclasses import replace

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
        terminal_interactive=True,
        confirmation_verified=True,
        profile_ready=True,
        credentials_ready=True,
        doctor_ok=True,
        scanner_passed=True,
        repo_clean=True,
        metadata_only=True,
        range_within_limit=True,
        environ={
            "CFDI_VAULT_ALLOW_REAL_SAT": "1",
            "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": "1",
        },
    )


def _passing_campaign_guard() -> LiveSatGuardInput:
    return LiveSatGuardInput(
        profile_ready=True,
        credentials_ready=True,
        doctor_ok=True,
        scanner_passed=True,
        repo_clean=True,
        metadata_only=True,
        range_within_limit=True,
        campaign_grant_verified=True,
        campaign_grant_allows_real_credentials=True,
        environ={},
    )


def test_fake_transport_records_requests_and_returns_synthetic_response_without_network() -> None:
    response = SoapTransportResponse(status_code=202, body=b"SYNTHETIC_RESPONSE")
    transport = FakeSoapTransport([response])

    result = transport.send(_request())

    assert result == response
    assert len(transport.requests) == 1
    assert transport.requests[0].endpoint == SAFE_ENDPOINT


def test_transport_request_rejects_disabled_tls_verification_and_client_cert() -> None:
    with pytest.raises(ValueError, match="soap-body-bytes-required"):
        SoapTransportRequest(
            endpoint=SAFE_ENDPOINT,
            body="<soap/>",  # type: ignore[arg-type]
        )

    with pytest.raises(ValueError, match="soap-body-required"):
        SoapTransportRequest(
            endpoint=SAFE_ENDPOINT,
            body=b"",
        )

    with pytest.raises(ValueError, match="tls-verification-required"):
        SoapTransportRequest(
            endpoint=SAFE_ENDPOINT,
            body=SAFE_BODY,
            tls_verify=False,
        )

    with pytest.raises(ValueError, match="client-tls-certificate-not-supported"):
        SoapTransportRequest(
            endpoint=SAFE_ENDPOINT,
            body=SAFE_BODY,
            client_tls_certificate=object(),
        )


@pytest.mark.parametrize(
    ("guard", "reason"),
    [
        (
            LiveSatGuardInput(
                manual_real_sat=True,
                profile_ready=True,
                scanner_passed=True,
                repo_clean=True,
                environ={
                    "CI": "true",
                    "CFDI_VAULT_ALLOW_REAL_SAT": "1",
                    "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": "1",
                },
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
                manual_real_sat=True,
                profile_ready=True,
                scanner_passed=True,
                repo_clean=True,
                environ={"CFDI_VAULT_ALLOW_REAL_SAT": "1"},
            ),
            "missing-explicit-real-credentials-env",
        ),
        (
            LiveSatGuardInput(
                manual_real_sat=False,
                profile_ready=True,
                scanner_passed=True,
                repo_clean=True,
                environ={
                    "CFDI_VAULT_ALLOW_REAL_SAT": "1",
                    "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": "1",
                },
            ),
            "missing-manual-real-sat-flag",
        ),
        (
            LiveSatGuardInput(
                manual_real_sat=True,
                profile_ready=False,
                scanner_passed=True,
                repo_clean=True,
                environ={
                    "CFDI_VAULT_ALLOW_REAL_SAT": "1",
                    "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": "1",
                },
            ),
            "profile-not-ready",
        ),
        (
            LiveSatGuardInput(
                manual_real_sat=True,
                profile_ready=True,
                scanner_passed=False,
                repo_clean=True,
                environ={
                    "CFDI_VAULT_ALLOW_REAL_SAT": "1",
                    "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": "1",
                },
            ),
            "scanner-not-passed",
        ),
        (
            LiveSatGuardInput(
                manual_real_sat=True,
                profile_ready=True,
                scanner_passed=True,
                repo_clean=False,
                environ={
                    "CFDI_VAULT_ALLOW_REAL_SAT": "1",
                    "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": "1",
                },
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


def test_http_adapter_sends_request_body_bytes_and_headers_unchanged() -> None:
    captured: dict[str, object] = {}
    body = b"<signed-auth-envelope>bytes stay unchanged</signed-auth-envelope>"
    headers = {
        "Content-Type": "text/xml; charset=utf-8",
        "SOAPAction": '"urn:auth-action"',
        "Accept": "text/xml",
    }

    class Response:
        headers = {"X-Synthetic": "ok"}
        reason = "OK"

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def getcode(self) -> int:
            return 202

        def read(self) -> bytes:
            return b"SYNTHETIC_RESPONSE"

    class Opener:
        def open(self, http_request: object, timeout: float | None = None) -> Response:
            captured["method"] = http_request.get_method()  # type: ignore[attr-defined]
            captured["data"] = http_request.data  # type: ignore[attr-defined]
            captured["headers"] = {key.lower(): value for key, value in http_request.header_items()}  # type: ignore[attr-defined]
            captured["timeout"] = timeout
            return Response()

    response = GuardedSoapHttpTransport(opener=Opener(), guard_input_factory=_passing_guard).send(
        SoapTransportRequest(endpoint=SAFE_ENDPOINT, body=body, headers=headers, timeout_seconds=17)
    )

    assert response.status_code == 202
    assert captured["method"] == "POST"
    assert captured["data"] == body
    assert captured["timeout"] == 17
    captured_headers = captured["headers"]
    assert isinstance(captured_headers, dict)
    assert captured_headers["content-type"] == "text/xml; charset=utf-8"
    assert captured_headers["soapaction"] == '"urn:auth-action"'
    assert captured_headers["accept"] == "text/xml"


def test_live_sat_guard_accepts_noninteractive_permit_without_credentials_for_transport_probe() -> None:
    validate_live_sat_guard(
        LiveSatGuardInput(
            profile_ready=True,
            credentials_ready=False,
            doctor_ok=True,
            scanner_passed=True,
            repo_clean=True,
            metadata_only=True,
            range_within_limit=True,
            live_permit_verified=True,
            real_credentials_required=False,
            environ={},
        )
    )


def test_live_sat_guard_keeps_ci_and_credential_gates_with_permit() -> None:
    with pytest.raises(LiveSatGuardError) as ci_exc:
        validate_live_sat_guard(
            LiveSatGuardInput(
                profile_ready=True,
                credentials_ready=True,
                doctor_ok=True,
                scanner_passed=True,
                repo_clean=True,
                metadata_only=True,
                range_within_limit=True,
                live_permit_verified=True,
                live_permit_allows_real_credentials=True,
                environ={"CI": "true"},
            )
        )
    assert "ci-enabled" in ci_exc.value.reasons

    with pytest.raises(LiveSatGuardError) as credentials_exc:
        validate_live_sat_guard(
            LiveSatGuardInput(
                profile_ready=True,
                credentials_ready=True,
                doctor_ok=True,
                scanner_passed=True,
                repo_clean=True,
                metadata_only=True,
                range_within_limit=True,
                live_permit_verified=True,
                live_permit_allows_real_credentials=False,
                environ={},
            )
        )
    assert "missing-explicit-real-credentials-env" in credentials_exc.value.reasons


def test_live_sat_guard_accepts_verified_campaign_authority_without_legacy_permit() -> None:
    guard = _passing_campaign_guard()

    validate_live_sat_guard(guard)

    assert guard.live_permit_verified is False
    assert guard.live_permit_allows_real_credentials is False


@pytest.mark.parametrize(
    ("verified", "allows_real_credentials"),
    [(True, False), (False, True)],
)
def test_live_sat_guard_rejects_partial_campaign_authority(
    verified: bool,
    allows_real_credentials: bool,
) -> None:
    guard = replace(
        _passing_campaign_guard(),
        campaign_grant_verified=verified,
        campaign_grant_allows_real_credentials=allows_real_credentials,
    )

    with pytest.raises(LiveSatGuardError) as exc_info:
        validate_live_sat_guard(guard)

    assert "invalid-campaign-grant-authority" in exc_info.value.reasons


def test_live_sat_guard_rejects_non_boolean_campaign_authority() -> None:
    guard = replace(
        _passing_campaign_guard(),
        live_permit_verified=True,
        live_permit_allows_real_credentials=True,
        campaign_grant_verified="verified",  # type: ignore[arg-type]
    )

    with pytest.raises(LiveSatGuardError) as exc_info:
        validate_live_sat_guard(guard)

    assert exc_info.value.reasons == ("invalid-campaign-grant-authority",)


def test_live_sat_guard_rejects_partial_campaign_claim_with_complete_legacy_permit() -> None:
    guard = replace(
        _passing_campaign_guard(),
        live_permit_verified=True,
        live_permit_allows_real_credentials=True,
        campaign_grant_allows_real_credentials=False,
    )

    with pytest.raises(LiveSatGuardError) as exc_info:
        validate_live_sat_guard(guard)

    assert exc_info.value.reasons == ("invalid-campaign-grant-authority",)


def test_live_sat_guard_does_not_combine_partial_legacy_and_campaign_authority() -> None:
    guard = replace(
        _passing_campaign_guard(),
        live_permit_verified=True,
        campaign_grant_verified=False,
        campaign_grant_allows_real_credentials=True,
    )

    with pytest.raises(LiveSatGuardError) as exc_info:
        validate_live_sat_guard(guard)

    assert "invalid-campaign-grant-authority" in exc_info.value.reasons
    assert "missing-explicit-real-credentials-env" in exc_info.value.reasons


def test_live_sat_guard_rejects_when_both_noninteractive_authorities_are_absent() -> None:
    guard = replace(
        _passing_campaign_guard(),
        campaign_grant_verified=False,
        campaign_grant_allows_real_credentials=False,
    )

    with pytest.raises(LiveSatGuardError) as exc_info:
        validate_live_sat_guard(guard)

    assert "missing-explicit-real-sat-env" in exc_info.value.reasons
    assert "missing-explicit-real-credentials-env" in exc_info.value.reasons
    assert "missing-manual-real-sat-flag" in exc_info.value.reasons


def test_live_sat_guard_preserves_complete_legacy_permit_authority() -> None:
    guard = replace(
        _passing_campaign_guard(),
        campaign_grant_verified=False,
        campaign_grant_allows_real_credentials=False,
        live_permit_verified=True,
        live_permit_allows_real_credentials=True,
    )

    validate_live_sat_guard(guard)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"environ": {"CI": "1"}}, "ci-enabled"),
        ({"profile_ready": False}, "profile-not-ready"),
        ({"credentials_ready": False}, "local-credentials-not-ready"),
        ({"doctor_ok": False}, "doctor-not-ok"),
        ({"scanner_passed": False}, "scanner-not-passed"),
        ({"repo_clean": False}, "repo-dirty"),
        ({"metadata_only": False}, "metadata-only-required"),
        ({"range_within_limit": False}, "range-too-wide"),
    ],
)
def test_live_sat_guard_campaign_authority_cannot_bypass_preflight(
    changes: dict[str, object],
    reason: str,
) -> None:
    guard = replace(_passing_campaign_guard(), **changes)

    with pytest.raises(LiveSatGuardError) as exc_info:
        validate_live_sat_guard(guard)

    assert reason in exc_info.value.reasons


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
