"""Redacted public SAT transport/WSDL probe helpers."""
from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from typing import Protocol
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from uuid import uuid4

from cfdi_vault.sat_auth_endpoints import RedactedEndpoint, auth_wsdl_endpoint, describe_endpoint, resolve_auth_endpoint
from cfdi_vault.sat_live_smoke import DEFAULT_REQUEST_ENDPOINT, DEFAULT_VERIFY_ENDPOINT

DEFAULT_PROBE_ENDPOINTS = (
    ("auth_service", resolve_auth_endpoint()),
    ("metadata_request", DEFAULT_REQUEST_ENDPOINT),
    ("verify", DEFAULT_VERIFY_ENDPOINT),
    ("package_download", "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc"),
)


@dataclass(frozen=True)
class SatProbeResult:
    endpoint: str
    check: str
    host: str
    status: str
    error_kind: str
    safe_hint: str
    http_status: int | None = None
    payload_size: int | None = None
    duration_ms: int = 0
    correlation_id: str = ""
    scheme: str = ""
    port: int = 443
    path: str = ""
    query_present: bool = False


@dataclass(frozen=True)
class ProbeHttpResponse:
    status_code: int
    body: bytes = b""


class SatTransportProbeClient(Protocol):
    def resolve(self, host: str) -> None:
        """Resolve one host or raise a transport error."""

    def tls_handshake(self, host: str, port: int, timeout_seconds: float) -> None:
        """Perform a TLS handshake or raise a transport error."""

    def get(self, url: str, timeout_seconds: float) -> ProbeHttpResponse:
        """Perform a public GET or raise a transport error."""


class DefaultSatTransportProbeClient:
    def resolve(self, host: str) -> None:
        socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)

    def tls_handshake(self, host: str, port: int, timeout_seconds: float) -> None:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout_seconds) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host):
                return

    def get(self, url: str, timeout_seconds: float) -> ProbeHttpResponse:
        request = urllib_request.Request(url, method="GET", headers={"User-Agent": "cfdi-vault-transport-probe"})
        try:
            with urllib_request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - explicit manual SAT probe
                return ProbeHttpResponse(status_code=response.getcode(), body=response.read(8192))
        except HTTPError as exc:
            return ProbeHttpResponse(status_code=exc.code, body=exc.read(8192))


def run_sat_transport_probe(
    *,
    client: SatTransportProbeClient | None = None,
    timeout_seconds: float = 10,
) -> tuple[SatProbeResult, ...]:
    probe_client = client or DefaultSatTransportProbeClient()
    results: list[SatProbeResult] = []
    for endpoint, url in DEFAULT_PROBE_ENDPOINTS:
        endpoint_info = describe_endpoint(endpoint, url)
        results.append(_probe_call(lambda: probe_client.resolve(endpoint_info.host), endpoint_info, "dns"))
        results.append(
            _probe_call(lambda: probe_client.tls_handshake(endpoint_info.host, endpoint_info.port, timeout_seconds), endpoint_info, "tls")
        )
        results.append(_http_probe(probe_client, endpoint_info, "http_get", url, timeout_seconds, wsdl=False))
        results.append(_http_probe(probe_client, endpoint_info, "wsdl_get", auth_wsdl_endpoint(url), timeout_seconds, wsdl=True))
    return tuple(results)


def _probe_call(action: object, endpoint_info: RedactedEndpoint, check: str) -> SatProbeResult:
    started = time.perf_counter()
    try:
        action()  # type: ignore[operator]
    except Exception as exc:
        return _result(endpoint_info, check, _classify_probe_exception(exc), _elapsed_ms(started))
    return _result(endpoint_info, check, "ok", _elapsed_ms(started))


def _http_probe(
    client: SatTransportProbeClient,
    endpoint_info: RedactedEndpoint,
    check: str,
    url: str,
    timeout_seconds: float,
    *,
    wsdl: bool,
) -> SatProbeResult:
    started = time.perf_counter()
    try:
        response = client.get(url, timeout_seconds)
    except Exception as exc:
        return _result(endpoint_info, check, _classify_probe_exception(exc), _elapsed_ms(started))
    if not 200 <= response.status_code < 400:
        return _result(endpoint_info, check, "wsdl_unavailable" if wsdl else "http_status_error", _elapsed_ms(started), response)
    if wsdl and b"definitions" not in response.body.lower() and b"wsdl" not in response.body.lower():
        return _result(endpoint_info, check, "unexpected_response", _elapsed_ms(started), response)
    return _result(endpoint_info, check, "ok", _elapsed_ms(started), response)


def _result(
    endpoint_info: RedactedEndpoint,
    check: str,
    error_kind: str,
    duration_ms: int,
    response: ProbeHttpResponse | None = None,
) -> SatProbeResult:
    return SatProbeResult(
        endpoint=endpoint_info.logical_endpoint,
        check=check,
        host=endpoint_info.host,
        status="ok" if error_kind == "ok" else "failed",
        error_kind=error_kind,
        safe_hint=_safe_hint(error_kind),
        http_status=response.status_code if response else None,
        payload_size=len(response.body) if response else None,
        duration_ms=duration_ms,
        correlation_id=f"probe-{uuid4().hex[:12]}",
        scheme=endpoint_info.scheme,
        port=endpoint_info.port,
        path=endpoint_info.path,
        query_present=endpoint_info.query_present,
    )


def _classify_probe_exception(exc: BaseException) -> str:
    if isinstance(exc, socket.gaierror):
        return "dns_failed"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "certificate_verify_failed"
    if isinstance(exc, ssl.SSLError):
        return "tls_handshake_failed"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "endpoint_unreachable"
    if isinstance(exc, URLError):
        return _classify_probe_exception(exc.reason) if isinstance(exc.reason, BaseException) else "endpoint_unreachable"
    marker = f"{type(exc).__name__} {exc}".lower()
    if "proxy" in marker or "tunnel" in marker or "firewall" in marker:
        return "proxy_or_firewall_failed"
    return "unexpected_response"


def _safe_hint(error_kind: str) -> str:
    return {
        "ok": "public transport check passed",
        "dns_failed": "check DNS resolution for the SAT host",
        "tls_handshake_failed": "check TLS handshake, SNI, proxy, and SAT endpoint availability",
        "certificate_verify_failed": "check local CA trust store without disabling TLS verification",
        "proxy_or_firewall_failed": "check proxy or firewall policy for outbound SAT HTTPS",
        "endpoint_unreachable": "check network reachability and timeout policy",
        "http_status_error": "endpoint reached but returned a non-success HTTP status",
        "wsdl_unavailable": "WSDL endpoint reached but did not return a successful WSDL response",
    }.get(error_kind, "unexpected public transport response; do not copy raw body")


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.perf_counter() - started) * 1000))
