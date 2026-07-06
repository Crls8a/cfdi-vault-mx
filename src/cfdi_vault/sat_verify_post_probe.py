"""No-credential SAT verify POST transport probe."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
import time
from urllib import request as urllib_request
from urllib.error import HTTPError
from uuid import uuid4

from cfdi_vault.sat_auth_endpoints import RedactedEndpoint, describe_endpoint
from cfdi_vault.sat_auth_http import build_soap11_headers
from cfdi_vault.sat_auth_post_probe import _classify_exception, _elapsed_ms
from cfdi_vault.sat_live_smoke import DEFAULT_VERIFY_ENDPOINT, SAT_REQUEST_NS, VERIFY_ACTION

VERIFY_POST_PROBE_BODY = f'''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:des="{SAT_REQUEST_NS}">
  <soapenv:Header/>
  <soapenv:Body>
    <des:VerificaSolicitudDescarga>
      <des:solicitud IdSolicitud="DUMMY-VERIFY-REQUEST" RfcSolicitante="XAXX010101000"/>
    </des:VerificaSolicitudDescarga>
  </soapenv:Body>
</soapenv:Envelope>'''.encode("utf-8")
VERIFY_POST_PROBE_HEADERS = {
    **build_soap11_headers(VERIFY_ACTION, user_agent="cfdi-vault-verify-post-probe"),
    "Authorization": 'WRAP access_' + 'token="DUMMY"',
}


@dataclass(frozen=True)
class SatVerifyPostProbeResult:
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
    request_body_bytes_len: int = 0
    has_authorization: bool = False


@dataclass(frozen=True)
class VerifyPostProbeHttpResponse:
    status_code: int
    body: bytes = b""


class DefaultSatVerifyPostProbeClient:
    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> VerifyPostProbeHttpResponse:
        request = urllib_request.Request(url, data=body, headers=dict(headers), method="POST")
        try:
            with urllib_request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - explicit guarded SAT probe
                return VerifyPostProbeHttpResponse(status_code=response.getcode(), body=response.read(8192))
        except HTTPError as exc:
            return VerifyPostProbeHttpResponse(status_code=exc.code, body=exc.read(8192))


def run_sat_verify_post_probe(
    *,
    client: object | None = None,
    endpoint: str = DEFAULT_VERIFY_ENDPOINT,
    timeout_seconds: float = 10,
) -> SatVerifyPostProbeResult:
    probe_client = client or DefaultSatVerifyPostProbeClient()
    endpoint_info = describe_endpoint("verify", endpoint)
    started = time.perf_counter()
    try:
        response = probe_client.post(endpoint, VERIFY_POST_PROBE_BODY, VERIFY_POST_PROBE_HEADERS, timeout_seconds)  # type: ignore[attr-defined]
    except Exception as exc:
        return _result(endpoint_info, _classify_exception(exc), _elapsed_ms(started))
    return _result(endpoint_info, _classify_response(response), _elapsed_ms(started), response)


def _classify_response(response: VerifyPostProbeHttpResponse) -> str:
    body = response.body.lower()
    if b"fault" in body:
        return "soap_fault"
    if not 200 <= response.status_code < 300:
        return "http_status_error"
    return "post_reached_server"


def _result(
    endpoint_info: RedactedEndpoint,
    error_kind: str,
    duration_ms: int,
    response: VerifyPostProbeHttpResponse | None = None,
) -> SatVerifyPostProbeResult:
    return SatVerifyPostProbeResult(
        endpoint=endpoint_info.logical_endpoint,
        check="post",
        host=endpoint_info.host,
        status="ok" if error_kind in {"post_reached_server", "http_status_error", "soap_fault"} else "failed",
        error_kind=error_kind,
        safe_hint=_safe_hint(error_kind),
        http_status=response.status_code if response else None,
        payload_size=len(response.body) if response else None,
        duration_ms=duration_ms,
        correlation_id=f"verifypost-{uuid4().hex[:12]}",
        scheme=endpoint_info.scheme,
        port=endpoint_info.port,
        path=endpoint_info.path,
        query_present=endpoint_info.query_present,
        request_body_bytes_len=len(VERIFY_POST_PROBE_BODY),
        has_authorization="Authorization" in VERIFY_POST_PROBE_HEADERS,
    )


def _safe_hint(error_kind: str) -> str:
    return {
        "post_reached_server": "synthetic verify POST reached the server",
        "http_status_error": "verify POST reached the server and returned an HTTP error; compare with real verify timeout safely",
        "soap_fault": "verify POST reached SOAP handling and returned a fault; compare with real verify timeout safely",
        "dns_failed": "check DNS resolution for the verify host",
        "tls_handshake_failed": "check TLS handshake, SNI, proxy, and SAT verify endpoint availability",
        "certificate_verify_failed": "check local CA trust store without disabling TLS verification",
        "proxy_connect_failed": "check proxy or firewall policy for outbound SAT HTTPS POST",
        "connection_reset_during_post": "verify POST connection was reset before an HTTP response",
        "remote_closed_connection": "verify POST remote closed the connection before an HTTP response",
        "timeout": "verify POST timed out before an HTTP response",
        "client_configuration_error": "verify POST client configuration failed before a trustworthy HTTP result",
    }.get(error_kind, "unexpected verify POST transport result; do not copy raw body")
