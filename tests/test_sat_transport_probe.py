from __future__ import annotations

import socket
import ssl
from urllib.error import URLError

from cfdi_vault.sat_transport_probe import ProbeHttpResponse, run_sat_transport_probe


class FakeProbeClient:
    def __init__(self, *, tls_error: BaseException | None = None, response: ProbeHttpResponse | None = None) -> None:
        self.tls_error = tls_error
        self.response = response or ProbeHttpResponse(200, b"<wsdl:definitions />")
        self.urls: list[str] = []

    def resolve(self, _host: str) -> None:
        return None

    def tls_handshake(self, _host: str, _port: int, _timeout_seconds: float) -> None:
        if self.tls_error:
            raise self.tls_error

    def get(self, url: str, _timeout_seconds: float) -> ProbeHttpResponse:
        self.urls.append(url)
        return self.response


def test_transport_probe_reports_wsdl_ok_without_raw_body() -> None:
    client = FakeProbeClient(response=ProbeHttpResponse(200, b"<wsdl:definitions>raw wsdl detail</wsdl:definitions>"))

    results = run_sat_transport_probe(client=client)

    assert any(result.endpoint == "auth_service" and result.check == "wsdl_get" and result.status == "ok" for result in results)
    assert any(url.endswith("?singleWsdl") for url in client.urls)
    assert all("raw wsdl detail" not in repr(result) for result in results)


def test_transport_probe_classifies_tls_failure() -> None:
    results = run_sat_transport_probe(client=FakeProbeClient(tls_error=ssl.SSLError("synthetic tls failure")))

    tls_results = [result for result in results if result.check == "tls"]
    assert tls_results
    assert {result.error_kind for result in tls_results} == {"tls_handshake_failed"}


def test_transport_probe_classifies_certificate_failure() -> None:
    results = run_sat_transport_probe(client=FakeProbeClient(tls_error=ssl.SSLCertVerificationError("synthetic ca failure")))

    cert_results = [result for result in results if result.check == "tls"]
    assert cert_results
    assert {result.error_kind for result in cert_results} == {"certificate_verify_failed"}


def test_transport_probe_classifies_http_and_wsdl_statuses() -> None:
    results = run_sat_transport_probe(client=FakeProbeClient(response=ProbeHttpResponse(500, b"synthetic failure")))

    assert any(result.check == "http_get" and result.error_kind == "http_status_error" for result in results)
    assert any(result.check == "wsdl_get" and result.error_kind == "wsdl_unavailable" for result in results)


def test_transport_probe_classifies_dns_and_proxy_failures() -> None:
    class DnsFailureProbe(FakeProbeClient):
        def resolve(self, _host: str) -> None:
            raise socket.gaierror("synthetic dns failure")

        def get(self, _url: str, _timeout_seconds: float) -> ProbeHttpResponse:
            raise URLError(OSError("synthetic proxy failure"))

    results = run_sat_transport_probe(client=DnsFailureProbe())

    assert any(result.check == "dns" and result.error_kind == "dns_failed" for result in results)
    assert any(result.check in {"http_get", "wsdl_get"} and result.error_kind == "proxy_or_firewall_failed" for result in results)
