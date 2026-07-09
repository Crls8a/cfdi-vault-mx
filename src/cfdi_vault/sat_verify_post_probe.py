"""Redacted SAT verify POST transport probe.

This module is diagnostic-only: it sends a redacted verify POST shape with a
placeholder Authorization value and a placeholder IdSolicitud. It can build the
legacy synthetic body or an offline production-signed equivalent with fake
material, but it must not be used as the production SAT verification path.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection, HTTPSConnection, RemoteDisconnected
import hashlib
import socket
import ssl
import time
from typing import Mapping, Protocol
from urllib.parse import urlsplit
from uuid import uuid4
from xml.etree import ElementTree

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from cfdi_vault.sat_auth_endpoints import RedactedEndpoint, describe_endpoint
from cfdi_vault.sat_auth_http import build_soap11_headers
from cfdi_vault.sat_live_smoke import DEFAULT_VERIFY_ENDPOINT, SAT_REQUEST_NS, VERIFY_ACTION, SatEfirmMaterial, _build_verify_envelope
from cfdi_vault.sat_verify_envelope_lint import lint_verify_envelope

SOAP11_NS = "http://schemas.xmlsoap.org/soap/envelope/"
VERIFY_POST_PROBE_BODY = f'''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="{SOAP11_NS}" xmlns:des="{SAT_REQUEST_NS}">
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
VERIFY_POST_PROBE_VARIANTS = (
    "default",
    "keep-alive",
    "connection-close",
    "explicit-content-length",
    "no-expect",
    "apache-like-ua",
)
VERIFY_POST_PROBE_ENVELOPE_SOURCES = ("synthetic", "production-signed")
VERIFY_POST_PROBE_REQUEST_ID = "DUMMY-VERIFY-REQUEST"
VERIFY_POST_PROBE_RFC = "XAXX010101000"


@dataclass(frozen=True)
class VerifyPostProbeBodyShape:
    source: str
    body_shape_verified: bool
    operation: str
    soap_envelope: bool
    soap_body: bool
    has_id_solicitud: bool
    has_rfc_solicitante: bool
    has_signature: bool
    has_signed_info: bool
    has_signature_value: bool
    has_key_info: bool
    has_x509_issuer_serial: bool
    has_x509_certificate: bool
    signature_placement: str
    signed_target: str
    canonicalization: str
    transform: str
    reference_uri: str
    digest_method: str
    signature_method: str
    has_authorization_wrap: bool
    authorization_in_body: bool
    content_type: str
    soap_action_present: bool
    request_size_bytes: int
    request_body_sha256_redacted: str
    redaction_active: bool = True


@dataclass(frozen=True, repr=False)
class VerifyPostProbeEnvelope:
    source: str
    body: bytes
    headers: dict[str, str]
    shape: VerifyPostProbeBodyShape

    def __repr__(self) -> str:
        return f"VerifyPostProbeEnvelope(source={self.source!r}, body=<redacted>, headers=<redacted>, shape={self.shape!r})"


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
    envelope_source: str = "synthetic"
    body_shape_verified: bool = False
    operation: str = ""
    has_id_solicitud: bool = False
    has_rfc_solicitante: bool = False
    has_signature: bool = False
    has_signed_info: bool = False
    has_signature_value: bool = False
    has_key_info: bool = False
    has_x509_issuer_serial: bool = False
    has_x509_certificate: bool = False
    signature_placement: str = ""
    signed_target: str = ""
    canonicalization: str = ""
    transform: str = ""
    reference_uri: str = ""
    digest_method: str = ""
    signature_method: str = ""
    has_authorization_wrap: bool = False
    authorization_in_body: bool = False
    content_type: str = ""
    soap_action_present: bool = False
    request_body_sha256_redacted: str = ""
    redaction_active: bool = True
    variant: str = "default"
    method: str = "POST"
    soap_action: str = VERIFY_ACTION
    post_attempted: bool = True
    response_received: bool = False
    soap_fault_detected: bool = False
    timeout_stage: str = "none"
    exception_stage: str = "none"
    request_size_bytes: int = 0
    response_size_bytes: int | None = None
    connect_timeout_seconds: float = 10
    read_timeout_seconds: float = 10
    raw_soap_printed: bool = False
    real_authorization_value_used: bool = False
    real_request_id_used: bool = False


@dataclass(frozen=True)
class VerifyPostProbeHttpResponse:
    status_code: int
    body: bytes = b""


class SatVerifyPostProbeClient(Protocol):
    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        connect_timeout_seconds: float,
        read_timeout_seconds: float,
    ) -> VerifyPostProbeHttpResponse:
        """Perform one diagnostic verify POST or raise a classified transport error."""


class VerifyPostProbeTransportError(RuntimeError):
    """Transport error tagged with the stage where it happened."""

    def __init__(self, stage: str, cause: BaseException) -> None:
        self.stage = stage
        self.cause = cause
        super().__init__(f"verify-post-probe-{stage}-failed")


class DefaultSatVerifyPostProbeClient:
    def post(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        connect_timeout_seconds: float,
        read_timeout_seconds: float,
    ) -> VerifyPostProbeHttpResponse:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise VerifyPostProbeTransportError("connect", ValueError("invalid-endpoint"))
        port = parts.port or (443 if parts.scheme == "https" else 80)
        connection_class = HTTPSConnection if parts.scheme == "https" else HTTPConnection
        connection = connection_class(parts.hostname, port=port, timeout=connect_timeout_seconds)
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        try:
            try:
                connection.connect()
            except Exception as exc:  # noqa: BLE001 - stage-preserving transport boundary.
                raise VerifyPostProbeTransportError("connect", exc) from exc
            if connection.sock is not None:
                connection.sock.settimeout(read_timeout_seconds)
            try:
                connection.request("POST", target, body=body, headers=dict(headers))
            except Exception as exc:  # noqa: BLE001 - stage-preserving transport boundary.
                raise VerifyPostProbeTransportError("write", exc) from exc
            try:
                response = connection.getresponse()
                return VerifyPostProbeHttpResponse(status_code=response.status, body=response.read(8192))
            except Exception as exc:  # noqa: BLE001 - stage-preserving transport boundary.
                raise VerifyPostProbeTransportError("read", exc) from exc
        finally:
            connection.close()


def run_sat_verify_post_probe(
    *,
    client: SatVerifyPostProbeClient | None = None,
    endpoint: str = DEFAULT_VERIFY_ENDPOINT,
    variant: str = "default",
    envelope_source: str = "synthetic",
    timeout_seconds: float | None = None,
    connect_timeout_seconds: float | None = None,
    read_timeout_seconds: float | None = None,
    dry_run: bool = False,
) -> SatVerifyPostProbeResult:
    normalized_variant = _normalize_variant(variant)
    envelope = build_verify_post_probe_envelope(envelope_source=envelope_source, variant=normalized_variant)
    connect_timeout = _resolve_timeout(connect_timeout_seconds, timeout_seconds)
    read_timeout = _resolve_timeout(read_timeout_seconds, timeout_seconds)
    endpoint_info = describe_endpoint("verify", endpoint)
    if dry_run:
        return _result(
            endpoint_info=endpoint_info,
            error_kind="none",
            duration_ms=0,
            envelope=envelope,
            variant=normalized_variant,
            post_attempted=False,
            connect_timeout_seconds=connect_timeout,
            read_timeout_seconds=read_timeout,
            status_override="dry_run",
        )
    probe_client = client or DefaultSatVerifyPostProbeClient()
    started = time.perf_counter()
    try:
        response = probe_client.post(endpoint, envelope.body, envelope.headers, connect_timeout, read_timeout)
    except Exception as exc:  # noqa: BLE001 - diagnostic boundary returns redacted stage data.
        return _result(
            endpoint_info=endpoint_info,
            error_kind=_classify_exception(exc),
            duration_ms=_elapsed_ms(started),
            envelope=envelope,
            variant=normalized_variant,
            post_attempted=True,
            connect_timeout_seconds=connect_timeout,
            read_timeout_seconds=read_timeout,
            exception_stage=_exception_stage(exc),
            timeout_stage=_timeout_stage(exc),
        )
    response_error_kind, soap_fault_detected = _classify_response(response)
    return _result(
        endpoint_info=endpoint_info,
        error_kind=response_error_kind,
        duration_ms=_elapsed_ms(started),
        envelope=envelope,
        variant=normalized_variant,
        post_attempted=True,
        connect_timeout_seconds=connect_timeout,
        read_timeout_seconds=read_timeout,
        response=response,
        soap_fault_detected=soap_fault_detected,
        exception_stage=response_error_kind if response_error_kind in {"http_status", "soap_fault", "parse"} else "none",
    )


def build_verify_post_probe_envelope(*, envelope_source: str = "synthetic", variant: str = "default") -> VerifyPostProbeEnvelope:
    source = _normalize_envelope_source(envelope_source)
    if source == "synthetic":
        body = VERIFY_POST_PROBE_BODY
    elif source == "production-signed":
        body = _build_verify_envelope(VERIFY_POST_PROBE_REQUEST_ID, VERIFY_POST_PROBE_RFC, _synthetic_efirma_material())
    else:  # pragma: no cover - _normalize_envelope_source is exhaustive.
        raise ValueError("unsupported-verify-post-probe-envelope-source")
    headers = build_verify_post_probe_headers(variant, body=body)
    shape = validate_verify_post_probe_body_shape(body, headers, envelope_source=source)
    return VerifyPostProbeEnvelope(source=source, body=body, headers=headers, shape=shape)


def build_verify_post_probe_headers(variant: str = "default", *, body: bytes = VERIFY_POST_PROBE_BODY) -> dict[str, str]:
    normalized_variant = _normalize_variant(variant)
    headers = dict(VERIFY_POST_PROBE_HEADERS)
    if normalized_variant == "keep-alive":
        headers["Connection"] = "keep-alive"
    elif normalized_variant == "connection-close":
        headers["Connection"] = "close"
    elif normalized_variant == "explicit-content-length":
        headers["Content-Length"] = str(len(body))
    elif normalized_variant == "no-expect":
        headers.pop("Expect", None)
    elif normalized_variant == "apache-like-ua":
        headers["User-Agent"] = "Apache-HttpClient/4.5.14 (Java/1.8.0)"
    return headers


def validate_verify_post_probe_body_shape(
    body: bytes,
    headers: Mapping[str, str],
    *,
    envelope_source: str = "synthetic",
) -> VerifyPostProbeBodyShape:
    source = _normalize_envelope_source(envelope_source)
    try:
        lint = lint_verify_envelope(body)
        operation = lint.operation_name or "unknown"
        soap_envelope = lint.soap_envelope
        soap_body = lint.soap_body
        has_id_solicitud = lint.solicitud_has_id
        has_rfc_solicitante = lint.solicitud_has_rfc
        has_signature = lint.signature_inside_solicitud
        has_signed_info = lint.signed_info
        has_signature_value = lint.signature_value
        has_key_info = lint.key_info
        has_x509_issuer_serial = lint.x509_issuer_serial
        has_x509_certificate = lint.x509_certificate
        signature_placement = lint.signature_placement
        signed_target = lint.signed_target
        canonicalization = _algorithm_profile(lint.c14n_algorithm)
        transform = _transform_profile(lint.reference_transform_algorithms)
        reference_uri = lint.reference_uri_shape
        digest_method = _algorithm_profile(lint.digest_algorithms[0] if lint.digest_algorithms else "")
        signature_method = _algorithm_profile(lint.signature_algorithm)
    except Exception:  # noqa: BLE001 - malformed diagnostic body must stay redacted.
        operation = "unknown"
        soap_envelope = soap_body = False
        has_id_solicitud = has_rfc_solicitante = False
        has_signature = has_signed_info = has_signature_value = has_key_info = False
        has_x509_issuer_serial = has_x509_certificate = False
        signature_placement = signed_target = canonicalization = transform = reference_uri = digest_method = signature_method = "unknown"
    content_type = _header_value(headers, "Content-Type") or ""
    soap_action = _header_value(headers, "SOAPAction") or ""
    authorization = _header_value(headers, "Authorization") or ""
    body_text = body.decode("utf-8", errors="ignore")
    authorization_in_body = "WRAP " in body_text or ("access_" + "token") in body_text or "Authorization" in body_text
    has_authorization_wrap = authorization.strip().lower().startswith("wrap ")
    soap_action_present = bool(soap_action)
    request_size_threshold_ok = len(body) >= len(VERIFY_POST_PROBE_BODY)
    signature_required = source == "production-signed"
    body_shape_verified = all(
        (
            soap_envelope,
            soap_body,
            operation == "VerificaSolicitudDescarga",
            has_id_solicitud,
            has_rfc_solicitante,
            has_authorization_wrap,
            not authorization_in_body,
            content_type == "text/xml; charset=utf-8",
            soap_action_present,
            request_size_threshold_ok,
            (not signature_required)
            or (
                has_signature
                and has_signed_info
                and has_signature_value
                and has_key_info
                and has_x509_issuer_serial
                and has_x509_certificate
                and signature_placement == "inside_solicitud"
                and signed_target == "operation_wrapper"
                and canonicalization == "exclusive_c14n"
                and transform == "exclusive_c14n"
                and reference_uri == "empty"
                and digest_method == "sha1"
                and signature_method == "rsa_sha1"
            ),
        )
    )
    return VerifyPostProbeBodyShape(
        source=source,
        body_shape_verified=body_shape_verified,
        operation=operation or "unknown",
        soap_envelope=soap_envelope,
        soap_body=soap_body,
        has_id_solicitud=has_id_solicitud,
        has_rfc_solicitante=has_rfc_solicitante,
        has_signature=has_signature,
        has_signed_info=has_signed_info,
        has_signature_value=has_signature_value,
        has_key_info=has_key_info,
        has_x509_issuer_serial=has_x509_issuer_serial,
        has_x509_certificate=has_x509_certificate,
        signature_placement=signature_placement,
        signed_target=signed_target,
        canonicalization=canonicalization,
        transform=transform,
        reference_uri=reference_uri,
        digest_method=digest_method,
        signature_method=signature_method,
        has_authorization_wrap=has_authorization_wrap,
        authorization_in_body=authorization_in_body,
        content_type=content_type,
        soap_action_present=soap_action_present,
        request_size_bytes=len(body),
        request_body_sha256_redacted=f"sha256:{hashlib.sha256(body).hexdigest()[:12]}...",
    )


def _classify_response(response: VerifyPostProbeHttpResponse) -> tuple[str, bool]:
    try:
        soap_fault_detected = _detect_soap_fault(response.body)
    except ElementTree.ParseError:
        return "parse", False
    if soap_fault_detected:
        return "soap_fault", True
    if not 200 <= response.status_code < 300:
        return "http_status", False
    return "none", False


def _detect_soap_fault(body: bytes) -> bool:
    stripped = body.strip()
    if not stripped:
        return False
    if not stripped.startswith(b"<"):
        return False
    root = ElementTree.fromstring(stripped)
    for node in root.iter():
        if _local_name(node.tag).lower() == "fault":
            return True
    return False


def _classify_exception(exc: BaseException) -> str:
    stage = _exception_stage(exc)
    return stage if stage in {"connect", "write", "read"} else "unknown"


def _exception_stage(exc: BaseException) -> str:
    tagged = _tagged_error(exc)
    if tagged is not None:
        return tagged.stage if tagged.stage in {"connect", "write", "read"} else "unknown"
    root = _root_exception(exc)
    if isinstance(root, (socket.gaierror, ssl.SSLError, ConnectionError)):
        return "connect"
    if isinstance(root, (TimeoutError, socket.timeout, RemoteDisconnected, EOFError)):
        return "read"
    return "unknown"


def _timeout_stage(exc: BaseException) -> str:
    tagged = _tagged_error(exc)
    stage = tagged.stage if tagged is not None else _exception_stage(exc)
    root = _root_exception(tagged.cause if tagged is not None else exc)
    marker = f"{type(root).__module__} {type(root).__name__} {root}".lower()
    if isinstance(root, (TimeoutError, socket.timeout)) or "timed out" in marker or "timeout" in marker:
        return stage if stage in {"connect", "write", "read"} else "unknown"
    return "none"


def _tagged_error(exc: BaseException) -> VerifyPostProbeTransportError | None:
    if isinstance(exc, VerifyPostProbeTransportError):
        return exc
    for attr in ("__cause__", "__context__"):
        nested = getattr(exc, attr, None)
        if isinstance(nested, BaseException):
            tagged = _tagged_error(nested)
            if tagged is not None:
                return tagged
    return None


def _root_exception(exc: BaseException) -> BaseException:
    if isinstance(exc, VerifyPostProbeTransportError):
        return _root_exception(exc.cause)
    for attr in ("__cause__", "__context__"):
        nested = getattr(exc, attr, None)
        if isinstance(nested, BaseException):
            return _root_exception(nested)
    return exc


def _result(
    *,
    endpoint_info: RedactedEndpoint,
    error_kind: str,
    duration_ms: int,
    envelope: VerifyPostProbeEnvelope,
    variant: str,
    post_attempted: bool,
    connect_timeout_seconds: float,
    read_timeout_seconds: float,
    response: VerifyPostProbeHttpResponse | None = None,
    soap_fault_detected: bool = False,
    exception_stage: str = "none",
    timeout_stage: str = "none",
    status_override: str | None = None,
) -> SatVerifyPostProbeResult:
    response_size = len(response.body) if response else None
    status = status_override or ("ok" if error_kind in {"none", "http_status", "soap_fault"} else "failed")
    shape = envelope.shape
    return SatVerifyPostProbeResult(
        endpoint=endpoint_info.logical_endpoint,
        check="post",
        host=endpoint_info.host,
        status=status,
        error_kind=error_kind,
        safe_hint="dry run built a redacted verify POST envelope without network I/O"
        if status == "dry_run"
        else _safe_hint(error_kind, timeout_stage=timeout_stage),
        http_status=response.status_code if response else None,
        payload_size=response_size,
        duration_ms=duration_ms,
        correlation_id=f"verifypost-{uuid4().hex[:12]}",
        scheme=endpoint_info.scheme,
        port=endpoint_info.port,
        path=endpoint_info.path,
        query_present=endpoint_info.query_present,
        request_body_bytes_len=len(envelope.body),
        has_authorization=_header_value(envelope.headers, "Authorization") is not None,
        envelope_source=envelope.source,
        body_shape_verified=shape.body_shape_verified,
        operation=shape.operation,
        has_id_solicitud=shape.has_id_solicitud,
        has_rfc_solicitante=shape.has_rfc_solicitante,
        has_signature=shape.has_signature,
        has_signed_info=shape.has_signed_info,
        has_signature_value=shape.has_signature_value,
        has_key_info=shape.has_key_info,
        has_x509_issuer_serial=shape.has_x509_issuer_serial,
        has_x509_certificate=shape.has_x509_certificate,
        signature_placement=shape.signature_placement,
        signed_target=shape.signed_target,
        canonicalization=shape.canonicalization,
        transform=shape.transform,
        reference_uri=shape.reference_uri,
        digest_method=shape.digest_method,
        signature_method=shape.signature_method,
        has_authorization_wrap=shape.has_authorization_wrap,
        authorization_in_body=shape.authorization_in_body,
        content_type=shape.content_type,
        soap_action_present=shape.soap_action_present,
        request_body_sha256_redacted=shape.request_body_sha256_redacted,
        redaction_active=shape.redaction_active,
        variant=variant,
        method="POST",
        soap_action=VERIFY_ACTION,
        post_attempted=post_attempted,
        response_received=response is not None,
        soap_fault_detected=soap_fault_detected,
        timeout_stage=timeout_stage,
        exception_stage=exception_stage,
        request_size_bytes=len(envelope.body),
        response_size_bytes=response_size,
        connect_timeout_seconds=connect_timeout_seconds,
        read_timeout_seconds=read_timeout_seconds,
        raw_soap_printed=False,
        real_authorization_value_used=False,
        real_request_id_used=False,
    )


def _safe_hint(error_kind: str, *, timeout_stage: str) -> str:
    if timeout_stage != "none":
        return f"verify POST timed out during {timeout_stage}; compare transport variant and proxy behavior without printing SOAP"
    return {
        "none": "verify POST returned a successful HTTP response without a SOAP fault",
        "http_status": "verify POST reached the server and returned an HTTP status; compare with real verify timeout safely",
        "soap_fault": "verify POST reached SOAP handling and returned a fault; compare with real verify timeout safely",
        "parse": "verify POST returned XML-like data that could not be parsed; do not copy raw body",
        "connect": "verify POST failed before a request write; check DNS, TLS, proxy, and endpoint reachability",
        "write": "verify POST failed while writing the request; check proxy, connection reuse, and server close behavior",
        "read": "verify POST failed while waiting for a response; check WCF read timeout and proxy buffering",
        "unknown": "unexpected verify POST transport result; do not copy raw body",
    }.get(error_kind, "unexpected verify POST transport result; do not copy raw body")


def _normalize_variant(value: str) -> str:
    normalized = str(value or "default").strip().lower()
    if normalized not in VERIFY_POST_PROBE_VARIANTS:
        raise ValueError("unsupported-verify-post-probe-variant")
    return normalized


def _normalize_envelope_source(value: str) -> str:
    normalized = str(value or "synthetic").strip().lower()
    if normalized not in VERIFY_POST_PROBE_ENVELOPE_SOURCES:
        raise ValueError("unsupported-verify-post-probe-envelope-source")
    return normalized


def _resolve_timeout(specific: float | None, fallback: float | None) -> float:
    value = 10 if specific is None and fallback is None else (specific if specific is not None else fallback)
    assert value is not None
    if value <= 0:
        raise ValueError("timeout-must-be-positive")
    return float(value)


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _header_value(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _algorithm_profile(value: str) -> str:
    return {
        "http://www.w3.org/2001/10/xml-exc-c14n#": "exclusive_c14n",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315": "inclusive_c14n",
        "http://www.w3.org/2000/09/xmldsig#sha1": "sha1",
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1": "rsa_sha1",
    }.get(value, value or "missing")


def _transform_profile(values: tuple[str, ...]) -> str:
    if values == ("http://www.w3.org/2001/10/xml-exc-c14n#",):
        return "exclusive_c14n"
    if "http://www.w3.org/2000/09/xmldsig#enveloped-signature" in values:
        return "enveloped_signature"
    if values == ("http://www.w3.org/TR/2001/REC-xml-c14n-20010315",):
        return "inclusive_c14n"
    return ",".join(_algorithm_profile(value) for value in values) if values else "missing"


def _synthetic_efirma_material() -> SatEfirmMaterial:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SYNTHETIC CFDI VAULT")])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    certificate_der_b64 = base64.b64encode(certificate.public_bytes(serialization.Encoding.DER)).decode("ascii")
    return SatEfirmMaterial(
        private_key=private_key,
        certificate_pem=certificate_pem,
        certificate_der_b64=certificate_der_b64,
    )


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.perf_counter() - started) * 1000))
