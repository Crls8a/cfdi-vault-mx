from __future__ import annotations

import socket
import ssl
from typing import Mapping
from urllib.error import URLError

from cfdi_vault.sat_auth_post_probe import (
    AUTH_POST_PROBE_BODY,
    AUTH_POST_PROBE_HEADERS,
    AuthPostProbeHttpResponse,
    run_sat_auth_post_probe,
)


class FakeAuthPostClient:
    def __init__(self, *, response: AuthPostProbeHttpResponse | None = None, error: BaseException | None = None) -> None:
        self.response = response or AuthPostProbeHttpResponse(500, b"synthetic server error")
        self.error = error
        self.calls: list[tuple[str, bytes, Mapping[str, str], float]] = []

    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> AuthPostProbeHttpResponse:
        self.calls.append((url, body, headers, timeout_seconds))
        if self.error is not None:
            raise self.error
        return self.response


def test_auth_post_probe_treats_http_error_as_reached_server_without_raw_body() -> None:
    client = FakeAuthPostClient(response=AuthPostProbeHttpResponse(415, b"raw unsupported media detail"))

    result = run_sat_auth_post_probe(client=client, endpoint="https://auth.example/svc", timeout_seconds=7)

    assert result.status == "ok"
    assert result.error_kind == "http_status_error"
    assert result.http_status == 415
    assert result.payload_size == len(b"raw unsupported media detail")
    assert result.host == "auth.example"
    assert "raw unsupported" not in repr(result)
    assert client.calls == [("https://auth.example/svc", AUTH_POST_PROBE_BODY, AUTH_POST_PROBE_HEADERS, 7)]


def test_auth_post_probe_treats_soap_fault_as_reached_server() -> None:
    result = run_sat_auth_post_probe(client=FakeAuthPostClient(response=AuthPostProbeHttpResponse(500, b"<soap:Fault />")))

    assert result.status == "ok"
    assert result.error_kind == "soap_fault"


def test_auth_post_probe_classifies_tls_certificate_timeout_and_proxy_failures() -> None:
    tls_result = run_sat_auth_post_probe(client=FakeAuthPostClient(error=ssl.SSLError("synthetic tls failure")))
    ca_result = run_sat_auth_post_probe(client=FakeAuthPostClient(error=ssl.SSLCertVerificationError("synthetic ca failure")))
    timeout_result = run_sat_auth_post_probe(client=FakeAuthPostClient(error=TimeoutError("synthetic timeout")))
    proxy_result = run_sat_auth_post_probe(client=FakeAuthPostClient(error=URLError(OSError("synthetic proxy tunnel failure"))))
    dns_result = run_sat_auth_post_probe(client=FakeAuthPostClient(error=socket.gaierror("synthetic dns failure")))

    assert tls_result.status == "failed"
    assert tls_result.error_kind == "tls_handshake_failed"
    assert ca_result.error_kind == "certificate_verify_failed"
    assert timeout_result.error_kind == "timeout"
    assert proxy_result.error_kind == "proxy_connect_failed"
    assert dns_result.error_kind == "dns_failed"
