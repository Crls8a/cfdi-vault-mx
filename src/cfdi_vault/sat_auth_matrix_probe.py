"""No-credential SAT auth transport parity matrix probe."""

from __future__ import annotations

import errno
import os
import shutil
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass
from typing import Mapping, Protocol
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from uuid import uuid4

from cfdi_vault.sat_auth_endpoints import RedactedEndpoint, auth_wsdl_endpoint, describe_endpoint, resolve_auth_endpoint
from cfdi_vault.sat_auth_post_probe import AUTH_POST_PROBE_BODY, AUTH_POST_PROBE_HEADERS

DEFAULT_TIMEOUT_SECONDS = 10
EMPTY_POST_BODY = b""
PYTHON_CLIENT_KIND = "python"


@dataclass(frozen=True)
class AuthMatrixHttpResponse:
    status_code: int
    body: bytes = b""


@dataclass(frozen=True)
class SatAuthMatrixProbeResult:
    client_kind: str
    method: str
    logical_endpoint: str
    check: str
    scheme: str
    host: str
    port: int
    path: str
    sni_host: str
    tls_result: str
    status: str
    error_kind: str
    safe_hint: str
    timeout_seconds: float
    proxy_detected: bool
    ca_mode: str
    query_present: bool = False
    http_status: int | None = None
    soap_fault_present: bool | None = None
    exception_class: str | None = None
    exception_errno: int | None = None
    duration_ms: int = 0
    correlation_id: str = ""


class SatAuthMatrixClient(Protocol):
    def request(self, method: str, url: str, *, body: bytes | None, headers: Mapping[str, str], timeout_seconds: float) -> AuthMatrixHttpResponse:
        """Perform one HTTP request or raise a transport error."""


class DefaultSatAuthMatrixClient:
    def request(self, method: str, url: str, *, body: bytes | None, headers: Mapping[str, str], timeout_seconds: float) -> AuthMatrixHttpResponse:
        request = urllib_request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            with urllib_request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - explicit guarded SAT probe
                return AuthMatrixHttpResponse(status_code=response.getcode(), body=response.read(8192))
        except HTTPError as exc:
            return AuthMatrixHttpResponse(status_code=exc.code, body=exc.read(8192))


def run_sat_auth_matrix_probe(
    *,
    client: SatAuthMatrixClient | None = None,
    endpoint: str | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    include_external: bool = True,
    env: Mapping[str, str] | None = None,
) -> tuple[SatAuthMatrixProbeResult, ...]:
    resolved = endpoint or resolve_auth_endpoint(env)
    endpoint_info = describe_endpoint("auth", resolved)
    matrix_client = client or DefaultSatAuthMatrixClient()
    specs = (
        ("GET", "service_page", resolved, None, {"User-Agent": "cfdi-vault-auth-matrix"}),
        ("GET", "single_wsdl", auth_wsdl_endpoint(resolved), None, {"User-Agent": "cfdi-vault-auth-matrix"}),
        ("POST", "dummy_envelope", resolved, AUTH_POST_PROBE_BODY, AUTH_POST_PROBE_HEADERS),
        ("POST", "empty_body", resolved, EMPTY_POST_BODY, {"Content-Type": "text/xml;charset=UTF-8", "User-Agent": "cfdi-vault-auth-matrix"}),
    )
    results = [_python_probe(matrix_client, endpoint_info, spec, timeout_seconds=timeout_seconds, env=env) for spec in specs]
    external = _external_probe(endpoint_info, resolved, timeout_seconds=timeout_seconds, env=env) if include_external else None
    return tuple([*results, *([external] if external else [])])


def _python_probe(
    client: SatAuthMatrixClient,
    endpoint_info: RedactedEndpoint,
    spec: tuple[str, str, str, bytes | None, Mapping[str, str]],
    *,
    timeout_seconds: float,
    env: Mapping[str, str] | None,
) -> SatAuthMatrixProbeResult:
    method, check, url, body, headers = spec
    started = time.perf_counter()
    try:
        response = client.request(method, url, body=body, headers=headers, timeout_seconds=timeout_seconds)
    except Exception as exc:
        kind, layer, klass, err_no = _classify_exception(exc)
        return _row(endpoint_info, PYTHON_CLIENT_KIND, method, check, "failed" if layer == "tls" else "unknown", kind, timeout_seconds, env, klass=klass, err_no=err_no, duration_ms=_elapsed_ms(started))
    return _row(endpoint_info, PYTHON_CLIENT_KIND, method, check, "ok", _classify_response(response), timeout_seconds, env, response=response, duration_ms=_elapsed_ms(started))


def _classify_response(response: AuthMatrixHttpResponse) -> str:
    if b"fault" in response.body.lower():
        return "soap_fault"
    if not 200 <= response.status_code < 300:
        return "http_status_error"
    return "unexpected_http_response"


def _classify_exception(exc: BaseException) -> tuple[str, str, str, int | None]:
    root = _root_exception(exc)
    marker = f"{type(root).__module__} {type(root).__name__} {root}".lower()
    klass, err_no = type(root).__name__, _exception_errno(root)
    if isinstance(root, socket.gaierror):
        return "dns_failed", "network", klass, err_no
    if isinstance(root, ssl.SSLCertVerificationError):
        return "certificate_verify_failed", "tls", klass, err_no
    if isinstance(root, ssl.SSLError):
        return "tls_handshake_failed", "tls", klass, err_no
    if isinstance(root, (TimeoutError, socket.timeout)) or err_no in {errno.ETIMEDOUT, getattr(errno, "WSAETIMEDOUT", -1)}:
        return "timeout", "network", klass, err_no
    if isinstance(root, ConnectionResetError) or err_no in {errno.ECONNRESET, getattr(errno, "WSAECONNRESET", -1)} or "reset" in marker:
        return "connection_reset_during_post", "network", klass, err_no
    if "remote end closed" in marker or "remote host closed" in marker or "connection closed" in marker:
        return "remote_closed_connection", "network", klass, err_no
    if "proxy" in marker or "tunnel" in marker or "firewall" in marker:
        return "proxy_connect_failed", "proxy", klass, err_no
    return "client_configuration_error", "client", klass, err_no


def _external_probe(endpoint_info: RedactedEndpoint, endpoint: str, *, timeout_seconds: float, env: Mapping[str, str] | None) -> SatAuthMatrixProbeResult | None:
    curl_path = shutil.which("curl.exe") or shutil.which("curl")
    if not curl_path:
        return None
    started = time.perf_counter()
    completed = subprocess.run(
        [
            curl_path,
            "--silent",
            "--show-error",
            "--output",
            os.devnull,
            "--write-out",
            "%{http_code}",
            "--max-time",
            str(max(1, int(timeout_seconds))),
            "--request",
            "POST",
            "--header",
            "Content-Type: text/xml;charset=UTF-8",
            "--header",
            f"SOAPAction: {AUTH_POST_PROBE_HEADERS['SOAPAction']}",
            "--data-binary",
            "@-",
            endpoint,
        ],
        input=AUTH_POST_PROBE_BODY,
        capture_output=True,
        check=False,
        env=dict(os.environ if env is None else env),
    )
    status = _parse_http_status(completed.stdout)
    if status is not None:
        response = AuthMatrixHttpResponse(status_code=status)
        return _row(endpoint_info, "curl", "POST", "dummy_envelope_external", "ok", _classify_response(response), timeout_seconds, env, response=response, duration_ms=_elapsed_ms(started))
    kind, tls = _classify_curl_exit(completed.returncode)
    return _row(endpoint_info, "curl", "POST", "dummy_envelope_external", tls, kind, timeout_seconds, env, klass="CurlExit", err_no=completed.returncode, duration_ms=_elapsed_ms(started))


def _row(
    endpoint_info: RedactedEndpoint,
    client_kind: str,
    method: str,
    check: str,
    tls_result: str,
    error_kind: str,
    timeout_seconds: float,
    env: Mapping[str, str] | None,
    *,
    response: AuthMatrixHttpResponse | None = None,
    klass: str | None = None,
    err_no: int | None = None,
    duration_ms: int = 0,
) -> SatAuthMatrixProbeResult:
    return SatAuthMatrixProbeResult(
        client_kind=client_kind,
        method=method,
        logical_endpoint=endpoint_info.logical_endpoint,
        check=check,
        scheme=endpoint_info.scheme,
        host=endpoint_info.host,
        port=endpoint_info.port,
        path=endpoint_info.path,
        sni_host=endpoint_info.host,
        tls_result=tls_result,
        status="ok" if error_kind in {"http_status_error", "soap_fault", "unexpected_http_response"} else "failed",
        error_kind=error_kind,
        safe_hint=_safe_hint(error_kind),
        timeout_seconds=timeout_seconds,
        proxy_detected=_proxy_detected(env),
        ca_mode="default",
        query_present=endpoint_info.query_present,
        http_status=response.status_code if response else None,
        soap_fault_present=(b"fault" in response.body.lower()) if response else None,
        exception_class=klass,
        exception_errno=err_no,
        duration_ms=duration_ms,
        correlation_id=f"authmatrix-{uuid4().hex[:12]}",
    )


def _root_exception(exc: BaseException) -> BaseException:
    if isinstance(exc, URLError) and isinstance(exc.reason, BaseException):
        return _root_exception(exc.reason)
    for attr in ("__cause__", "__context__"):
        nested = getattr(exc, attr, None)
        if isinstance(nested, BaseException):
            return _root_exception(nested)
    return exc


def _exception_errno(exc: BaseException) -> int | None:
    value = getattr(exc, "errno", None)
    return value if isinstance(value, int) else None


def _parse_http_status(value: bytes) -> int | None:
    text = value.decode("ascii", errors="ignore").strip()
    return int(text) if len(text) == 3 and text.isdigit() and text != "000" else None


def _classify_curl_exit(returncode: int) -> tuple[str, str]:
    return {
        35: ("tls_handshake_failed", "failed"),
        60: ("certificate_verify_failed", "failed"),
        28: ("timeout", "unknown"),
        52: ("remote_closed_connection", "ok"),
        56: ("remote_closed_connection", "ok"),
        5: ("dns_failed", "unknown"),
        6: ("dns_failed", "unknown"),
        7: ("connection_reset_during_post", "unknown"),
        55: ("connection_reset_during_post", "unknown"),
    }.get(returncode, ("client_configuration_error", "unknown"))


def _proxy_detected(env: Mapping[str, str] | None) -> bool:
    source = os.environ if env is None else env
    names = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy")
    return any(name in source and source[name].strip() for name in names)


def _safe_hint(error_kind: str) -> str:
    return {
        "http_status_error": "request reached HTTP and returned a non-success status",
        "soap_fault": "request reached SOAP handling and returned a fault",
        "unexpected_http_response": "request reached HTTP with a success status but unexpected body shape",
        "dns_failed": "check DNS resolution for the auth host",
        "tls_handshake_failed": "check TLS handshake, SNI, proxy, and SAT auth endpoint availability",
        "certificate_verify_failed": "check local CA trust store without disabling TLS verification",
        "proxy_connect_failed": "check proxy or firewall policy for outbound SAT HTTPS",
        "connection_reset_during_post": "connection reset during POST before an HTTP response",
        "remote_closed_connection": "remote closed the connection before an HTTP response",
        "timeout": "request timed out before an HTTP response",
        "client_configuration_error": "client configuration failed before a trustworthy HTTP result",
    }.get(error_kind, "unexpected auth matrix result; do not copy raw body")


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.perf_counter() - started) * 1000))
