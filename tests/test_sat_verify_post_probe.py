from __future__ import annotations

from http.client import RemoteDisconnected
from typing import Mapping
from urllib.error import URLError
import socket
import ssl

from cfdi_vault.sat_live_smoke import DEFAULT_VERIFY_ENDPOINT, VERIFY_ACTION
from cfdi_vault.sat_verify_post_probe import (
    VERIFY_POST_PROBE_BODY,
    VERIFY_POST_PROBE_HEADERS,
    VerifyPostProbeHttpResponse,
    run_sat_verify_post_probe,
)


class FakeVerifyPostClient:
    def __init__(self, *, response: VerifyPostProbeHttpResponse | None = None, error: BaseException | None = None) -> None:
        self.response = response or VerifyPostProbeHttpResponse(500, b"synthetic server error")
        self.error = error
        self.calls: list[tuple[str, bytes, Mapping[str, str], float]] = []

    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> VerifyPostProbeHttpResponse:
        self.calls.append((url, body, headers, timeout_seconds))
        if self.error is not None:
            raise self.error
        return self.response


def test_verify_post_probe_treats_http_error_as_reached_server_without_raw_body() -> None:
    client = FakeVerifyPostClient(response=VerifyPostProbeHttpResponse(415, b"raw unsupported media detail"))

    result = run_sat_verify_post_probe(client=client, endpoint="https://verify.example/svc", timeout_seconds=7)

    assert result.status == "ok"
    assert result.error_kind == "http_status_error"
    assert result.http_status == 415
    assert result.payload_size == len(b"raw unsupported media detail")
    assert result.host == "verify.example"
    assert result.request_body_bytes_len == len(VERIFY_POST_PROBE_BODY)
    assert result.has_authorization is True
    assert "raw unsupported" not in repr(result)
    assert client.calls == [("https://verify.example/svc", VERIFY_POST_PROBE_BODY, VERIFY_POST_PROBE_HEADERS, 7)]


def test_verify_post_probe_uses_canonical_verify_contract_constants() -> None:
    assert b"VerificaSolicitudDescarga" in VERIFY_POST_PROBE_BODY
    assert b"DUMMY-VERIFY-REQUEST" in VERIFY_POST_PROBE_BODY
    assert VERIFY_POST_PROBE_HEADERS["SOAPAction"] == f'"{VERIFY_ACTION}"'
    assert VERIFY_POST_PROBE_HEADERS["Content-Type"] == "text/xml; charset=utf-8"
    assert VERIFY_POST_PROBE_HEADERS["Authorization"] == 'WRAP access_token="DUMMY"'
    result = run_sat_verify_post_probe(client=FakeVerifyPostClient())
    assert result.path == "/VerificaSolicitudDescargaService.svc"
    assert DEFAULT_VERIFY_ENDPOINT.endswith(result.path)


def test_verify_post_probe_treats_soap_fault_as_reached_server() -> None:
    result = run_sat_verify_post_probe(client=FakeVerifyPostClient(response=VerifyPostProbeHttpResponse(500, b"<soap:Fault />")))

    assert result.status == "ok"
    assert result.error_kind == "soap_fault"


def test_verify_post_probe_classifies_transport_failures_precisely() -> None:
    failures = [
        (ssl.SSLError("synthetic tls failure"), "tls_handshake_failed"),
        (ssl.SSLCertVerificationError("synthetic ca failure"), "certificate_verify_failed"),
        (TimeoutError("synthetic timeout"), "timeout"),
        (ConnectionResetError("synthetic reset"), "connection_reset_during_post"),
        (RemoteDisconnected("synthetic remote close"), "remote_closed_connection"),
        (URLError(OSError("synthetic proxy tunnel failure")), "proxy_connect_failed"),
        (socket.gaierror("synthetic dns failure"), "dns_failed"),
        (RuntimeError("synthetic client configuration failure"), "client_configuration_error"),
    ]

    for failure, error_kind in failures:
        result = run_sat_verify_post_probe(client=FakeVerifyPostClient(error=failure))

        assert result.status == "failed"
        assert result.error_kind == error_kind
        assert "synthetic" not in repr(result)
