"""No-credential SAT auth POST transport probe."""

from __future__ import annotations

import socket
import ssl
import time
from http.client import RemoteDisconnected
from dataclasses import dataclass
from typing import Mapping, Protocol
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from uuid import uuid4

from cfdi_vault.sat_auth_constants import AUTH_NAMESPACE, AUTH_OPERATION, AUTH_SOAP_ACTION
from cfdi_vault.sat_auth_http import build_soap11_headers
from cfdi_vault.sat_auth_endpoints import RedactedEndpoint, describe_endpoint, resolve_auth_endpoint

AUTH_POST_PROBE_BODY = f'''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="{AUTH_NAMESPACE}">
  <soapenv:Header/>
  <soapenv:Body>
    <des:{AUTH_OPERATION}/>
  </soapenv:Body>
</soapenv:Envelope>'''.encode("utf-8")
AUTH_POST_PROBE_HEADERS = build_soap11_headers(AUTH_SOAP_ACTION, user_agent="cfdi-vault-auth-post-probe")


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
    scheme: str = ""
    port: int = 443
    path: str = ""
    query_present: bool = False


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
    endpoint: str | None = None,
    timeout_seconds: float = 10,
) -> SatAuthPostProbeResult:
    probe_client = client or DefaultSatAuthPostProbeClient()
    resolved_endpoint = endpoint or resolve_auth_endpoint()
    endpoint_info = describe_endpoint("auth", resolved_endpoint)
    started = time.perf_counter()
    try:
        response = probe_client.post(resolved_endpoint, AUTH_POST_PROBE_BODY, AUTH_POST_PROBE_HEADERS, timeout_seconds)
    except Exception as exc:
        return _result(endpoint_info, _classify_exception(exc), _elapsed_ms(started))
    return _result(endpoint_info, _classify_response(response), _elapsed_ms(started), response)


def _classify_response(response: AuthPostProbeHttpResponse) -> str:
    body = response.body.lower()
    if b"fault" in body:
        return "soap_fault"
    if not 200 <= response.status_code < 300:
        return "http_status_error"
    return "post_reached_server"


def _classify_exception(exc: BaseException) -> str:
    root = _root_exception(exc)
    marker = f"{type(root).__module__} {type(root).__name__} {root}".lower()
    if isinstance(root, socket.gaierror):
        return "dns_failed"
    if isinstance(root, ssl.SSLCertVerificationError):
        return "certificate_verify_failed"
    if isinstance(root, ssl.SSLError):
        return "tls_handshake_failed"
    if isinstance(root, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(root, (RemoteDisconnected, EOFError)) or "remote end closed" in marker or "remote host closed" in marker or "connection closed" in marker:
        return "remote_closed_connection"
    if isinstance(root, ConnectionResetError) or "reset" in marker:
        return "connection_reset_during_post"
    if "proxy" in marker or "tunnel" in marker or "firewall" in marker:
        return "proxy_connect_failed"
    return "client_configuration_error"


def _root_exception(exc: BaseException) -> BaseException:
    if isinstance(exc, URLError) and isinstance(exc.reason, BaseException):
        return _root_exception(exc.reason)
    for attr in ("__cause__", "__context__"):
        nested = getattr(exc, attr, None)
        if isinstance(nested, BaseException):
            return _root_exception(nested)
    return exc


def _result(
    endpoint_info: RedactedEndpoint,
    error_kind: str,
    duration_ms: int,
    response: AuthPostProbeHttpResponse | None = None,
) -> SatAuthPostProbeResult:
    return SatAuthPostProbeResult(
        endpoint=endpoint_info.logical_endpoint,
        check="post",
        host=endpoint_info.host,
        status="ok" if _post_reached_server(error_kind) else "failed",
        error_kind=error_kind,
        safe_hint=_safe_hint(error_kind),
        http_status=response.status_code if response else None,
        payload_size=len(response.body) if response else None,
        duration_ms=duration_ms,
        correlation_id=f"authpost-{uuid4().hex[:12]}",
        scheme=endpoint_info.scheme,
        port=endpoint_info.port,
        path=endpoint_info.path,
        query_present=endpoint_info.query_present,
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
        "connection_reset_during_post": "auth POST connection was reset before an HTTP response",
        "remote_closed_connection": "auth POST remote closed the connection before an HTTP response",
        "timeout": "auth POST timed out before an HTTP response",
        "client_configuration_error": "auth POST client configuration failed before a trustworthy HTTP result",
    }.get(error_kind, "unexpected auth POST transport result; do not copy raw body")


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.perf_counter() - started) * 1000))
