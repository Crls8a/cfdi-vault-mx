"""No-credential SAT auth POST transport probe."""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from typing import Mapping, Protocol
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from uuid import uuid4

from cfdi_vault.sat_live_smoke import AUTH_ACTION, DEFAULT_AUTH_ENDPOINT

AUTH_POST_PROBE_BODY = b'''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="http://DescargaMasivaTerceros.gob.mx">
  <soapenv:Header/>
  <soapenv:Body>
    <des:Autentica/>
  </soapenv:Body>
</soapenv:Envelope>'''
AUTH_POST_PROBE_HEADERS = {
    "Content-Type": "text/xml;charset=UTF-8",
    "SOAPAction": f'"{AUTH_ACTION}"',
    "User-Agent": "cfdi-vault-auth-post-probe",
}


@dataclass(frozen=True)
class SatAuthPostProbeResult:
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


@dataclass(frozen=True)
class AuthPostProbeHttpResponse:
    status_code: int
    body: bytes = b""


class SatAuthPostProbeClient(Protocol):
    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> AuthPostProbeHttpResponse:
        """Perform one synthetic auth POST or raise a transport error."""


class DefaultSatAuthPostProbeClient:
    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> AuthPostProbeHttpResponse:
        request = urllib_request.Request(url, data=body, headers=dict(headers), method="POST")
        try:
            with urllib_request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - explicit guarded SAT probe
                return AuthPostProbeHttpResponse(status_code=response.getcode(), body=response.read(8192))
        except HTTPError as exc:
            return AuthPostProbeHttpResponse(status_code=exc.code, body=exc.read(8192))


def run_sat_auth_post_probe(
    *,
    client: SatAuthPostProbeClient | None = None,
    endpoint: str = DEFAULT_AUTH_ENDPOINT,
    timeout_seconds: float = 10,
) -> SatAuthPostProbeResult:
    probe_client = client or DefaultSatAuthPostProbeClient()
    host = urlsplit(endpoint).hostname or "unknown"
    started = time.perf_counter()
    try:
        response = probe_client.post(endpoint, AUTH_POST_PROBE_BODY, AUTH_POST_PROBE_HEADERS, timeout_seconds)
    except Exception as exc:
        return _result(host, _classify_exception(exc), _elapsed_ms(started))
    return _result(host, _classify_response(response), _elapsed_ms(started), response)


def _classify_response(response: AuthPostProbeHttpResponse) -> str:
    body = response.body.lower()
    if b"fault" in body:
        return "soap_fault"
    if not 200 <= response.status_code < 300:
        return "http_status_error"
    return "post_reached_server"


def _classify_exception(exc: BaseException) -> str:
    if isinstance(exc, socket.gaierror):
        return "dns_failed"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "certificate_verify_failed"
    if isinstance(exc, ssl.SSLError):
        return "tls_handshake_failed"
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(exc, URLError):
        return _classify_exception(exc.reason) if isinstance(exc.reason, BaseException) else "proxy_connect_failed"
    marker = f"{type(exc).__name__} {exc}".lower()
    if "proxy" in marker or "tunnel" in marker or "firewall" in marker:
        return "proxy_connect_failed"
    if "reset" in marker:
        return "connection_reset"
    return "unexpected_transport_error"


def _result(
    host: str,
    error_kind: str,
    duration_ms: int,
    response: AuthPostProbeHttpResponse | None = None,
) -> SatAuthPostProbeResult:
    return SatAuthPostProbeResult(
        endpoint="auth",
        check="post",
        host=host,
        status="ok" if _post_reached_server(error_kind) else "failed",
        error_kind=error_kind,
        safe_hint=_safe_hint(error_kind),
        http_status=response.status_code if response else None,
        payload_size=len(response.body) if response else None,
        duration_ms=duration_ms,
        correlation_id=f"authpost-{uuid4().hex[:12]}",
    )


def _post_reached_server(error_kind: str) -> bool:
    return error_kind in {"post_reached_server", "http_status_error", "soap_fault"}


def _safe_hint(error_kind: str) -> str:
    return {
        "post_reached_server": "synthetic auth POST reached the server",
        "http_status_error": "auth POST reached the server and returned an HTTP error; inspect SOAPAction/content-type/body shape safely",
        "soap_fault": "auth POST reached SOAP handling and returned a fault; inspect contract/firma safely",
        "dns_failed": "check DNS resolution for the auth host",
        "tls_handshake_failed": "check TLS handshake, SNI, proxy, and SAT auth endpoint availability",
        "certificate_verify_failed": "check local CA trust store without disabling TLS verification",
        "proxy_connect_failed": "check proxy or firewall policy for outbound SAT HTTPS POST",
        "connection_reset": "auth POST connection was reset before an HTTP response",
        "timeout": "auth POST timed out before an HTTP response",
    }.get(error_kind, "unexpected auth POST transport result; do not copy raw body")


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.perf_counter() - started) * 1000))
