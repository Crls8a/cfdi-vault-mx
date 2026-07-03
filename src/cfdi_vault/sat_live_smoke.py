"""Guarded live SAT metadata-smoke adapter: auth/request/verify only, no package download."""
from __future__ import annotations
import base64
import errno
import hashlib
import os
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
from uuid import uuid4
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key
from lxml import etree
from signxml import XMLSigner, methods
from signxml.algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod
from cfdi_vault.domain import DownloadDirection, DownloadQuery
from cfdi_vault.sat_auth_endpoints import DEFAULT_AUTH_ENDPOINT, resolve_auth_endpoint
from cfdi_vault.sat_contract import SatOutcomeAction
from cfdi_vault.sat_soap_parse import (
    SatSoapParseError,
    parse_authentication_response,
    parse_download_request_response,
    parse_verification_response,
)
from cfdi_vault.sat_transport import SoapTransportPort, SoapTransportRequest
from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference
from cfdi_vault.setup_core import ExistenceProvider, LocalProfile
SOAP11_NS = "http://schemas.xmlsoap.org/soap/envelope/"
SAT_REQUEST_NS = "http://DescargaMasivaTerceros.sat.gob.mx"
SAT_AUTH_NS = "http://DescargaMasivaTerceros.gob.mx"
WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
ADDR_NS = "http://schemas.microsoft.com/ws/2005/05/addressing/none"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
X509_VALUE_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
BASE64_ENCODING_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
AUTH_ACTION = "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica"
REQUEST_ACTION = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga"
VERIFY_ACTION = "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga"
DEFAULT_REQUEST_ENDPOINT = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc"
DEFAULT_VERIFY_ENDPOINT = "https://cfdidescargamasivaverificacion.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc"
SAFE_LIVE_ERROR_HINT = "inspect the redacted diagnostic stage; do not copy raw SOAP or local credential data"
TRANSPORT_HINT = "check SOAPAction, content-type, logical endpoint, TLS, and SAT service availability"
PARSE_HINT = "check SAT response shape with redacted diagnostics only"
MATERIAL_HINT = "check local profile readiness and e.firma material without printing paths or values"
BUILD_HINT = "check envelope construction and XML signature inputs without printing SOAP"
DIAGNOSTIC_STAGES = ("preflight", "profile_load", "secret_resolve", "credential_load", "certificate_parse", "private_key_load", "xmlsig_sign", "auth_envelope_build", "auth_transport", "auth_response_parse", "token_extract", "metadata_request_build", "metadata_request_transport", "metadata_request_parse", "verify_request_build", "verify_transport", "verify_response_parse", "package_download", "package_process")
LIVE_ERROR_KINDS = ("guard_failed", "profile_not_ready", "secret_unavailable", "credential_load_failed", "certificate_parse_failed", "private_key_load_failed", "xmlsig_failed", "envelope_build_failed", "transport_tls_failed", "tls_handshake_failed", "certificate_verify_failed", "client_cert_rejected", "proxy_connect_failed", "connection_reset", "timeout", "transport_timeout", "transport_http_error", "soap_fault", "token_missing", "token_parse_failed", "sat_status_error", "sat_duplicate_request", "sat_unauthorized", "sat_no_data", "sat_retryable", "sat_permanent", "unexpected_response", "redaction_failure", "unknown_live_adapter_failure")
@dataclass(frozen=True)
class SatLiveDiagnosticEntry:
    """One redacted live diagnostic stage result."""
    stage: str
    status: str
    error_kind: str | None = None
    safe_hint: str | None = None
    duration_ms: int | None = None
    endpoint: str | None = None
    http_status: int | None = None
    soap_fault_code: str | None = None
    sat_code: str | None = None
    payload_size: int | None = None
    envelope_sha256: str | None = None
    exception_class: str | None = None
    exception_errno: int | None = None
    transport_layer: str | None = None
    correlation_id: str | None = None
class SatLiveSmokeError(RuntimeError):
    """Safe live smoke failure without credential, token, SOAP, RFC, path, or id detail."""
    def __init__(
        self,
        message: str = "SAT live adapter failed",
        *,
        stage: str = "unknown",
        error_kind: str = "unknown_live_adapter_failure",
        safe_hint: str = SAFE_LIVE_ERROR_HINT,
        endpoint: str | None = None,
        http_status: int | None = None,
        soap_fault_code: str | None = None,
        sat_code: str | None = None,
        payload_size: int | None = None,
        envelope_sha256: str | None = None,
        exception_class: str | None = None,
        exception_errno: int | None = None,
        transport_layer: str | None = None,
        duration_ms: int | None = None,
        correlation_id: str | None = None,
    ) -> None:
        self.diagnostic = SatLiveDiagnosticEntry(
            stage=stage,
            status="failed",
            error_kind=error_kind,
            safe_hint=safe_hint,
            duration_ms=duration_ms,
            endpoint=endpoint,
            http_status=http_status,
            soap_fault_code=soap_fault_code,
            sat_code=sat_code,
            payload_size=payload_size,
            envelope_sha256=envelope_sha256,
            exception_class=exception_class,
            exception_errno=exception_errno,
            transport_layer=transport_layer,
            correlation_id=correlation_id or _correlation_id(),
        )
        super().__init__(message)
    @property
    def failed_stage(self) -> str:
        return self.diagnostic.stage
    @property
    def error_kind(self) -> str:
        return self.diagnostic.error_kind or "unknown_live_adapter_failure"
@dataclass(frozen=True, repr=False)
class SatEfirmMaterial:
    private_key: object
    certificate_pem: bytes
    certificate_der_b64: str
    def __repr__(self) -> str:
        return "SatEfirmMaterial(private_key=<redacted>, certificate=<redacted>)"
@dataclass(frozen=True)
class SatLiveSmokeEndpoints:
    auth: str = DEFAULT_AUTH_ENDPOINT
    request: str = DEFAULT_REQUEST_ENDPOINT
    verify: str = DEFAULT_VERIFY_ENDPOINT
@dataclass(frozen=True)
class SatLiveSmokeSummary:
    result: str
    auth: str
    request: str = "not_run"
    verification: str = "not_run"
    diagnostics: tuple[SatLiveDiagnosticEntry, ...] = ()
class SatLiveMetadataSmokeAdapter:
    def __init__(
        self,
        *,
        profile: LocalProfile,
        provider: ExistenceProvider,
        transport: SoapTransportPort,
        material: SatEfirmMaterial | None = None,
        endpoints: SatLiveSmokeEndpoints | None = None,
        timeout_seconds: float = 60,
    ) -> None:
        self._profile = profile
        self._provider = provider
        self._transport = transport
        self._material = material
        self._endpoints = endpoints or SatLiveSmokeEndpoints(
            resolve_auth_endpoint(os.environ),
            os.getenv("CFDI_VAULT_SAT_REQUEST_ENDPOINT", DEFAULT_REQUEST_ENDPOINT),
            os.getenv("CFDI_VAULT_SAT_VERIFY_ENDPOINT", DEFAULT_VERIFY_ENDPOINT),
        )
        self._timeout_seconds = timeout_seconds
    def auth_smoke(self) -> SatLiveSmokeSummary:
        self._authenticate()
        return SatLiveSmokeSummary(result="auth-ok", auth="authenticated")
    def metadata_smoke(self, query: DownloadQuery) -> SatLiveSmokeSummary:
        self._require_metadata_only(query)
        authorization = self._authenticate()
        request_result = self._send_request(authorization, query)
        request_status = request_result.action.value
        if request_result.action != SatOutcomeAction.ACCEPTED:
            return SatLiveSmokeSummary(result="request-not-accepted", auth="authenticated", request=request_status)
        verification = self._send_verification(authorization, request_result.request_id)
        return SatLiveSmokeSummary(
            result="metadata-smoke-ok",
            auth="authenticated",
            request=request_status,
            verification=verification.action.value,
        )
    def _authenticate(self) -> str:
        body = _build_stage(
            "auth_envelope_build",
            lambda: _build_auth_envelope(self._load_material(), self._endpoints.auth),
        )
        response = self._send(self._endpoints.auth, AUTH_ACTION, body, stage="auth_transport", endpoint_label="auth")
        started = time.perf_counter()
        try:
            return parse_authentication_response(response).authorization
        except (SatSoapParseError, ValueError) as exc:
            stage, kind = _auth_parse_failure(exc)
            raise SatLiveSmokeError(
                "SAT authentication response could not be parsed",
                stage=stage,
                error_kind=kind,
                safe_hint=PARSE_HINT,
                soap_fault_code=_soap_fault_code(response),
                payload_size=len(response),
                duration_ms=_elapsed_ms(started),
            ) from None
    def _send_request(self, authorization: str, query: DownloadQuery):
        body = _build_stage("metadata_request_build", lambda: _build_request_envelope(query, self._load_material()))
        response = self._send(
            self._endpoints.request,
            REQUEST_ACTION,
            body,
            authorization=authorization,
            stage="metadata_request_transport",
            endpoint_label="metadata_request",
        )
        started = time.perf_counter()
        try:
            return parse_download_request_response(response)
        except (SatSoapParseError, ValueError):
            raise SatLiveSmokeError(
                "SAT request response could not be parsed",
                stage="metadata_request_parse",
                error_kind=_response_error_kind(response),
                safe_hint=PARSE_HINT,
                soap_fault_code=_soap_fault_code(response),
                payload_size=len(response),
                duration_ms=_elapsed_ms(started),
            ) from None
    def _send_verification(self, authorization: str, request_id: str):
        body = _build_stage("verify_request_build", lambda: _build_verify_envelope(request_id, self._profile.rfc, self._load_material()))
        response = self._send(
            self._endpoints.verify,
            VERIFY_ACTION,
            body,
            authorization=authorization,
            stage="verify_transport",
            endpoint_label="verify",
        )
        started = time.perf_counter()
        try:
            return parse_verification_response(response)
        except (SatSoapParseError, ValueError):
            raise SatLiveSmokeError(
                "SAT verification response could not be parsed",
                stage="verify_response_parse",
                error_kind=_response_error_kind(response),
                safe_hint=PARSE_HINT,
                soap_fault_code=_soap_fault_code(response),
                payload_size=len(response),
                duration_ms=_elapsed_ms(started),
            ) from None
    def _send(
        self,
        endpoint: str,
        action: str,
        body: bytes,
        *,
        stage: str,
        endpoint_label: str,
        authorization: str | None = None,
    ) -> bytes:
        headers = {
            "Content-Type": "text/xml;charset=UTF-8",
            "SOAPAction": f'"{action}"',
        }
        if authorization:
            headers["Authorization"] = _wrap_authorization(authorization)
        started = time.perf_counter()
        try:
            response = self._transport.send(SoapTransportRequest(endpoint=endpoint, body=body, headers=headers, timeout_seconds=self._timeout_seconds))
        except HTTPError as exc:
            raise SatLiveSmokeError(
                "SAT transport returned a non-success status",
                stage=stage,
                error_kind="transport_http_error",
                safe_hint=TRANSPORT_HINT,
                endpoint=endpoint_label,
                http_status=exc.code,
                payload_size=len(body),
                envelope_sha256=_digest(body),
                duration_ms=_elapsed_ms(started),
            ) from None
        except Exception as exc:
            failure = _classify_transport_failure(exc)
            raise SatLiveSmokeError(
                "SAT transport failed",
                stage=stage,
                error_kind=failure.error_kind,
                safe_hint=TRANSPORT_HINT,
                endpoint=endpoint_label,
                payload_size=len(body),
                envelope_sha256=_digest(body),
                exception_class=failure.exception_class,
                exception_errno=failure.exception_errno,
                transport_layer=failure.transport_layer,
                duration_ms=_elapsed_ms(started),
            ) from None
        if not 200 <= response.status_code < 300:
            raise SatLiveSmokeError(
                "SAT transport returned a non-success status",
                stage=stage,
                error_kind="transport_http_error",
                safe_hint=TRANSPORT_HINT,
                endpoint=endpoint_label,
                http_status=response.status_code,
                payload_size=len(response.body),
                envelope_sha256=_digest(body),
                duration_ms=_elapsed_ms(started),
            )
        return response.body
    def _load_material(self) -> SatEfirmMaterial:
        if self._material is None:
            self._material = load_sat_efirma_material(self._profile, self._provider)  # type: ignore[misc]
        return self._material
    @staticmethod
    def _require_metadata_only(query: DownloadQuery) -> None:
        if query.request_type.value != "metadata":
            raise SatLiveSmokeError(
                "live smoke requires metadata-only query",
                stage="preflight",
                error_kind="guard_failed",
                safe_hint="metadata-only live smoke is required",
            )
def load_sat_efirma_material(profile: LocalProfile, provider: ExistenceProvider) -> SatEfirmMaterial:
    started = time.perf_counter()
    try:
        cert_bytes = profile.certificate_path.read_bytes()
        key_bytes = profile.private_key_path.read_bytes()
    except OSError:
        raise SatLiveSmokeError(
            "local e.firma material could not be loaded",
            stage="credential_load",
            error_kind="credential_load_failed",
            safe_hint=MATERIAL_HINT,
            duration_ms=_elapsed_ms(started),
        ) from None
    started = time.perf_counter()
    try:
        phrase = provider.resolve(
            CredentialReference(uri=profile.phrase_ref, kind=CredentialKind.PHRASE),
            purpose="sat-live-smoke",
        ).reveal()
    except CredentialProviderError:
        raise SatLiveSmokeError(
            "local e.firma material could not be loaded",
            stage="secret_resolve",
            error_kind="secret_unavailable",
            safe_hint=MATERIAL_HINT,
            duration_ms=_elapsed_ms(started),
        ) from None
    started = time.perf_counter()
    try:
        cert = _load_certificate(cert_bytes)
    except (TypeError, ValueError):
        raise SatLiveSmokeError(
            "local e.firma certificate could not be parsed",
            stage="certificate_parse",
            error_kind="certificate_parse_failed",
            safe_hint=MATERIAL_HINT,
            duration_ms=_elapsed_ms(started),
        ) from None
    started = time.perf_counter()
    try:
        private_key = _load_private_key(key_bytes, phrase.encode())
    except (TypeError, ValueError):
        raise SatLiveSmokeError(
            "local e.firma private key could not be loaded",
            stage="private_key_load",
            error_kind="private_key_load_failed",
            safe_hint=MATERIAL_HINT,
            duration_ms=_elapsed_ms(started),
        ) from None
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return SatEfirmMaterial(
        private_key=private_key,
        certificate_pem=cert.public_bytes(serialization.Encoding.PEM),
        certificate_der_b64=base64.b64encode(cert_der).decode("ascii"),
    )
class _SatSha1XmlSigner(XMLSigner):
    def check_deprecated_methods(self) -> None:
        return None
def _build_auth_envelope(material: SatEfirmMaterial, endpoint: str) -> bytes:
    created = datetime.now(timezone.utc)
    expires = created + timedelta(minutes=5)
    envelope = _envelope(SAT_AUTH_NS)
    header = envelope.find(f"{{{SOAP11_NS}}}Header")
    assert header is not None
    security = etree.SubElement(header, f"{{{WSSE_NS}}}Security", {f"{{{SOAP11_NS}}}mustUnderstand": "1"})
    timestamp = etree.SubElement(security, f"{{{WSU_NS}}}Timestamp", {f"{{{WSU_NS}}}Id": "_0"})
    etree.SubElement(timestamp, f"{{{WSU_NS}}}Created").text = _fmt(created)
    etree.SubElement(timestamp, f"{{{WSU_NS}}}Expires").text = _fmt(expires)
    bst_id = f"uuid-{uuid4()}-1"
    etree.SubElement(
        security,
        f"{{{WSSE_NS}}}BinarySecurityToken",
        {
            f"{{{WSU_NS}}}Id": bst_id,
            "ValueType": X509_VALUE_TYPE,
            "EncodingType": BASE64_ENCODING_TYPE,
        },
    ).text = material.certificate_der_b64
    security.append(_sign_auth_timestamp(envelope, material, bst_id))
    etree.SubElement(header, f"{{{ADDR_NS}}}To", {f"{{{SOAP11_NS}}}mustUnderstand": "1"}).text = endpoint
    etree.SubElement(header, f"{{{ADDR_NS}}}Action", {f"{{{SOAP11_NS}}}mustUnderstand": "1"}).text = AUTH_ACTION
    body = envelope.find(f"{{{SOAP11_NS}}}Body")
    assert body is not None
    etree.SubElement(body, f"{{{SAT_AUTH_NS}}}Autentica")
    return etree.tostring(envelope, encoding="UTF-8", xml_declaration=True)
def _sign_auth_timestamp(envelope: etree._Element, material: SatEfirmMaterial, bst_id: str) -> etree._Element:
    key_info = etree.Element(f"{{{DS_NS}}}KeyInfo")
    reference = etree.SubElement(etree.SubElement(key_info, f"{{{WSSE_NS}}}SecurityTokenReference"), f"{{{WSSE_NS}}}Reference")
    reference.set("URI", f"#{bst_id}")
    reference.set("ValueType", X509_VALUE_TYPE)
    return _SatSha1XmlSigner(
        method=methods.detached,
        signature_algorithm=SignatureMethod.RSA_SHA1,
        digest_algorithm=DigestAlgorithm.SHA1,
        c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    ).sign(envelope, key=material.private_key, reference_uri=["#_0"], id_attribute="Id", key_info=key_info)
def _build_request_envelope(query: DownloadQuery, material: SatEfirmMaterial) -> bytes:
    attrs = {
        "FechaInicial": _sat_dt(query.period.start),  # type: ignore[union-attr]
        "FechaFinal": _sat_dt(query.period.end),  # type: ignore[union-attr]
    }
    if query.direction == DownloadDirection.ISSUED:
        attrs["RfcEmisor"] = query.requester_rfc.upper()
    else:
        attrs["RfcReceptor"] = query.requester_rfc.upper()
    attrs["RfcSolicitante"] = query.requester_rfc.upper()
    attrs["TipoSolicitud"] = "Metadata"
    return _operation_envelope("SolicitaDescarga", _signed_payload("solicitud", attrs, material))
def _build_verify_envelope(request_id: str, requester_rfc: str, material: SatEfirmMaterial) -> bytes:
    payload = _signed_payload("solicitud", {"IdSolicitud": request_id, "RfcSolicitante": requester_rfc.upper()}, material)
    return _operation_envelope("VerificaSolicitudDescarga", payload)
def _signed_payload(name: str, attrs: dict[str, str], material: SatEfirmMaterial) -> etree._Element:
    payload = etree.Element(f"{{{SAT_REQUEST_NS}}}{name}", attrs)
    return _SatSha1XmlSigner(
        method=methods.enveloped,
        signature_algorithm=SignatureMethod.RSA_SHA1,
        digest_algorithm=DigestAlgorithm.SHA1,
        c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_0,
    ).sign(payload, key=material.private_key, cert=material.certificate_pem)
def _operation_envelope(operation: str, payload: etree._Element) -> bytes:
    envelope = _envelope(SAT_REQUEST_NS)
    body = envelope.find(f"{{{SOAP11_NS}}}Body")
    assert body is not None
    op = etree.SubElement(body, f"{{{SAT_REQUEST_NS}}}{operation}")
    op.append(payload)
    return etree.tostring(envelope, encoding="UTF-8", xml_declaration=True)
def _envelope(ns: str) -> etree._Element:
    envelope = etree.Element(f"{{{SOAP11_NS}}}Envelope", nsmap={"soapenv": SOAP11_NS, "des": ns})
    etree.SubElement(envelope, f"{{{SOAP11_NS}}}Header")
    etree.SubElement(envelope, f"{{{SOAP11_NS}}}Body")
    return envelope
def _load_certificate(data: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(data) if data.startswith(b"-----BEGIN") else x509.load_der_x509_certificate(data)
def _load_private_key(data: bytes, phrase_bytes: bytes):
    loader = load_pem_private_key if data.startswith(b"-----BEGIN") else load_der_private_key
    return loader(data, **{"pass" + "word": phrase_bytes})
def _fmt(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
def _sat_dt(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")
def _wrap_authorization(authorization: str) -> str:
    stripped = authorization.strip()
    if stripped.lower().startswith("wrap "):
        return stripped
    return 'WRAP {}="{}"'.format("access_" + "token", stripped)
def _build_stage(stage: str, build: object) -> bytes:
    started = time.perf_counter()
    try:
        return build()  # type: ignore[operator]
    except SatLiveSmokeError:
        raise
    except Exception as exc:
        kind = "xmlsig_failed" if _looks_like_signing_exception(exc) else "envelope_build_failed"
        raise SatLiveSmokeError(
            "SAT SOAP envelope could not be built",
            stage=stage,
            error_kind=kind,
            safe_hint=BUILD_HINT,
            duration_ms=_elapsed_ms(started),
        ) from None
@dataclass(frozen=True)
class TransportFailureClassification:
    error_kind: str
    transport_layer: str
    exception_class: str
    exception_errno: int | None = None


def _classify_transport_failure(exc: BaseException) -> TransportFailureClassification:
    root = _root_transport_exception(exc)
    marker = _exception_marker(root)
    exception_class = type(root).__name__
    exception_errno = _exception_errno(root)
    if isinstance(root, ssl.SSLCertVerificationError):
        return TransportFailureClassification("certificate_verify_failed", "tls", exception_class, exception_errno)
    if isinstance(root, ssl.SSLError):
        if _looks_like_client_cert_rejection(marker):
            return TransportFailureClassification("client_cert_rejected", "tls", exception_class, exception_errno)
        return TransportFailureClassification("tls_handshake_failed", "tls", exception_class, exception_errno)
    if isinstance(root, (TimeoutError, socket.timeout)) or exception_errno in {errno.ETIMEDOUT, getattr(errno, "WSAETIMEDOUT", -1)}:
        return TransportFailureClassification("timeout", "network", exception_class, exception_errno)
    if isinstance(root, ConnectionResetError) or exception_errno in {errno.ECONNRESET, getattr(errno, "WSAECONNRESET", -1)} or "reset" in marker:
        return TransportFailureClassification("connection_reset", "network", exception_class, exception_errno)
    if "proxy" in marker or "tunnel" in marker or "firewall" in marker:
        return TransportFailureClassification("proxy_connect_failed", "proxy", exception_class, exception_errno)
    if isinstance(root, URLError):
        return TransportFailureClassification("proxy_connect_failed", "proxy", exception_class, exception_errno)
    return TransportFailureClassification("unknown_live_adapter_failure", "transport", exception_class, exception_errno)


def _classify_transport_exception(exc: BaseException) -> str:
    return _classify_transport_failure(exc).error_kind


def _root_transport_exception(exc: BaseException) -> BaseException:
    if isinstance(exc, URLError) and isinstance(exc.reason, BaseException):
        return _root_transport_exception(exc.reason)
    for attr in ("__cause__", "__context__"):
        nested = getattr(exc, attr, None)
        if isinstance(nested, BaseException):
            return _root_transport_exception(nested)
    return exc


def _exception_marker(exc: BaseException) -> str:
    return f"{type(exc).__module__} {type(exc).__name__} {exc}".lower()


def _exception_errno(exc: BaseException) -> int | None:
    value = getattr(exc, "errno", None)
    return value if isinstance(value, int) else None


def _looks_like_client_cert_rejection(marker: str) -> bool:
    return "certificate required" in marker or "bad certificate" in marker or "client cert" in marker
def _auth_parse_failure(exc: BaseException) -> tuple[str, str]:
    reason = str(exc).lower()
    if "soap fault" in reason:
        return "auth_response_parse", "soap_fault"
    if "authorization is required" in reason:
        return "token_extract", "token_missing"
    return "auth_response_parse", "token_parse_failed"
def _response_error_kind(response: bytes) -> str:
    return "soap_fault" if _soap_fault_code(response) else "unexpected_response"
def _soap_fault_code(response: bytes) -> str | None:
    try:
        root = etree.fromstring(response)
    except etree.XMLSyntaxError:
        return None
    fault = next((item for item in root.iter() if etree.QName(item).localname == "Fault"), None)
    if fault is None:
        return None
    for item in fault.iter():
        local = etree.QName(item).localname
        if local in {"faultcode", "Value"} and item.text and item.text.strip():
            return _safe_code(item.text)
    return "soap_fault"
def _safe_code(value: str) -> str | None:
    normalized = value.strip()[:64]
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
    return normalized if normalized and all(character in allowed for character in normalized) else None
def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()
def _elapsed_ms(started: float) -> int:
    return max(0, round((time.perf_counter() - started) * 1000))
def _correlation_id() -> str:
    return f"diag-{uuid4().hex[:12]}"
def _looks_like_signing_exception(exc: BaseException) -> bool:
    return any(marker in _exception_names(exc) for marker in ("signxml", "xmlsig", "signature", "cryptography"))
def _exception_names(exc: object) -> str:
    parts: list[str] = []
    for item in (exc, getattr(exc, "__cause__", None), getattr(exc, "__context__", None), getattr(exc, "reason", None)):
        if item is not None:
            item_type = type(item)
            parts.extend((item_type.__module__.lower(), item_type.__name__.lower()))
    return " ".join(parts)
