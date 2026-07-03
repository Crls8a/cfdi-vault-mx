from __future__ import annotations

import socket
import ssl
from urllib.error import URLError

from cfdi_vault.sat_auth_matrix_probe import AuthMatrixHttpResponse, run_sat_auth_matrix_probe


class FakeMatrixClient:
    def __init__(self, responses: list[AuthMatrixHttpResponse] | None = None, error: BaseException | None = None) -> None:
        self.responses = responses or [AuthMatrixHttpResponse(415, b"unsupported media")] * 4
        self.error = error
        self.calls: list[tuple[str, str, bytes | None, float]] = []

    def request(self, method: str, url: str, *, body: bytes | None, headers, timeout_seconds: float):  # noqa: ANN001, ANN201
        self.calls.append((method, url, body, timeout_seconds))
        if self.error is not None:
            raise self.error
        return self.responses.pop(0)


def test_auth_matrix_runs_python_get_wsdl_and_post_without_raw_output() -> None:
    client = FakeMatrixClient(
        responses=[
            AuthMatrixHttpResponse(200, b"<html>service page</html>"),
            AuthMatrixHttpResponse(200, b"<wsdl:definitions>raw wsdl detail</wsdl:definitions>"),
            AuthMatrixHttpResponse(500, b"<soap:Fault />"),
            AuthMatrixHttpResponse(415, b"unsupported media"),
        ]
    )

    results = run_sat_auth_matrix_probe(
        client=client,
        endpoint="https://auth.example.test/Autenticacion/Autenticacion.svc?marker=not-printed",
        include_external=False,
        timeout_seconds=7,
        env={},
    )

    assert [(result.method, result.check) for result in results] == [
        ("GET", "service_page"),
        ("GET", "single_wsdl"),
        ("POST", "dummy_envelope"),
        ("POST", "empty_body"),
    ]
    assert all(result.host == "auth.example.test" for result in results)
    assert all(result.path == "/Autenticacion/Autenticacion.svc" for result in results)
    assert all(result.query_present is True for result in results)
    assert results[0].error_kind == "unexpected_http_response"
    assert results[2].error_kind == "soap_fault"
    assert results[3].error_kind == "http_status_error"
    rendered = "\n".join(repr(result) for result in results)
    assert "raw wsdl detail" not in rendered
    assert "not-printed" not in rendered


def test_auth_matrix_classifies_transport_failures_safely() -> None:
    failures = [
        (ssl.SSLError("synthetic tls failure"), "tls_handshake_failed", "SSLError"),
        (ssl.SSLCertVerificationError("synthetic ca failure"), "certificate_verify_failed", "SSLCertVerificationError"),
        (TimeoutError("synthetic timeout"), "timeout", "TimeoutError"),
        (ConnectionResetError("synthetic reset"), "connection_reset_during_post", "ConnectionResetError"),
        (URLError(OSError("synthetic remote end closed connection")), "remote_closed_connection", "OSError"),
        (socket.gaierror("synthetic dns failure"), "dns_failed", "gaierror"),
    ]

    for exc, error_kind, exception_class in failures:
        results = run_sat_auth_matrix_probe(client=FakeMatrixClient(error=exc), include_external=False, env={})

        assert all(result.status == "failed" for result in results)
        assert all(result.error_kind == error_kind for result in results)
        assert all(result.exception_class == exception_class for result in results)
        assert all("synthetic" not in repr(result).lower() for result in results)


def test_auth_matrix_reports_proxy_presence_without_values() -> None:
    results = run_sat_auth_matrix_probe(
        client=FakeMatrixClient(),
        endpoint="https://auth.example.test/Autenticacion/Autenticacion.svc",
        include_external=False,
        env={"HTTPS_PROXY": "http://proxy-value.example"},
    )

    assert all(result.proxy_detected is True for result in results)
    assert all(result.ca_mode == "default" for result in results)
    assert all("proxy-value" not in repr(result) for result in results)
