"""Guarded live SAT metadata adapter: auth/request/verify/package with explicit CLI gates."""
from __future__ import annotations
import base64
from copy import deepcopy
import errno
import hashlib
from http.client import RemoteDisconnected
import os
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from urllib.error import HTTPError, URLError
from uuid import uuid4
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key
from lxml import etree
from signxml import XMLSigner, methods
from signxml.algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod
from cfdi_vault.domain import DownloadDirection, DownloadQuery
from cfdi_vault.sat_auth_constants import (
    AUTH_ACCEPT,
    AUTH_CONTENT_TYPE,
    AUTH_ENVELOPE_VARIANTS,
    AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    AUTH_ENVELOPE_VARIANT_SECURITY_ONLY,
    AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION,
    AUTH_NAMESPACE,
    AUTH_OPERATION,
    AUTH_SOAP_ACTION,
    DEFAULT_AUTH_ENVELOPE_VARIANT,
)
from cfdi_vault.sat_auth_endpoints import DEFAULT_AUTH_ENDPOINT, resolve_auth_endpoint
from cfdi_vault.sat_auth_http import build_soap11_headers
from cfdi_vault.sat_contract import SatOutcomeAction, SatRequestResult, SatVerificationResult
from cfdi_vault.sat_soap_parse import (
    SatSoapParseError,
    parse_authentication_response,
    parse_download_request_response,
    parse_package_download_response,
    parse_verification_response,
)
from cfdi_vault.sat_transport import SoapTransportPort, SoapTransportRequest
from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference
from cfdi_vault.setup_core import ExistenceProvider, LocalProfile
SOAP11_NS = "http://schemas.xmlsoap.org/soap/envelope/"
SAT_REQUEST_NS = "http://DescargaMasivaTerceros.sat.gob.mx"
SAT_AUTH_NS = AUTH_NAMESPACE
WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
ADDR_NS = "http://schemas.microsoft.com/ws/2005/05/addressing/none"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
VERIFY_EXCLUSIVE_C14N = CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0.value
X509_VALUE_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
BASE64_ENCODING_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
AUTH_ACTION = AUTH_SOAP_ACTION
REQUEST_ACTION_BASE = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService"
VERIFY_ACTION = "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga"
DOWNLOAD_ACTION = "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar"
DEFAULT_REQUEST_ENDPOINT = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc"
DEFAULT_VERIFY_ENDPOINT = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc"
DEFAULT_DOWNLOAD_ENDPOINT = "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc"
SAFE_LIVE_ERROR_HINT = "inspect the redacted diagnostic stage; do not copy raw SOAP or local credential data"
TRANSPORT_HINT = "check SOAPAction, content-type, logical endpoint, TLS, and SAT service availability"
PARSE_HINT = "check SAT response shape with redacted diagnostics only"
MATERIAL_HINT = "check local profile readiness and e.firma material without printing paths or values"
BUILD_HINT = "check envelope construction and XML signature inputs without printing SOAP"
READINESS_HINT = "check auth SOAPAction, content-type, namespace, WS-Security, signature, and non-empty signed body"
DIAGNOSTIC_STAGES = ("preflight", "profile_load", "secret_resolve", "credential_load", "certificate_parse", "private_key_load", "xmlsig_sign", "auth_envelope_build", "auth_request_readiness", "auth_transport", "auth_response_parse", "token_extract", "metadata_request_build", "metadata_request_transport", "metadata_request_parse", "verify_request_build", "verify_request_readiness", "verify_transport", "verify_response_parse", "package_download", "package_process")
LIVE_ERROR_KINDS = ("guard_failed", "profile_not_ready", "secret_unavailable", "credential_load_failed", "certificate_parse_failed", "private_key_load_failed", "xmlsig_failed", "envelope_build_failed", "transport_tls_failed", "tls_handshake_failed", "certificate_verify_failed", "client_cert_rejected", "proxy_connect_failed", "connection_reset", "connection_reset_during_post", "remote_closed_connection", "timeout", "verify_read_timeout", "transport_timeout", "transport_http_error", "http_status_error", "soap_fault", "token_missing", "token_parse_failed", "sat_status_error", "sat_duplicate_request", "sat_unauthorized", "sat_no_data", "sat_retryable", "sat_permanent", "unexpected_response", "unexpected_http_response", "client_configuration_error", "redaction_failure", "unknown_live_adapter_failure")
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
    request_body_bytes_len: int | None = None
    soap_action: str | None = None
    content_type: str | None = None
    timestamp_window_seconds: int | None = None
    has_ws_security: bool | None = None
    has_bst: bool | None = None
    cert_der_bytes_len: int | None = None
    signature_method: str | None = None
    digest_method: str | None = None
    signed_reference_count: int | None = None
    signed_reference_targets_exist: bool | None = None
    has_header_action: bool | None = None
    header_action_value_ok: bool | None = None
    header_action_must_understand: bool | None = None
    header_action_order: str | None = None
    security_must_understand: bool | None = None
    operation: str | None = None
    has_authorization: bool | None = None
    authorization_value_len: int | None = None
    has_id_solicitud: bool | None = None
    id_solicitud_redacted: str | None = None
    has_rfc_solicitante: bool | None = None
    has_signature: bool | None = None
    endpoint_url_ok: bool | None = None
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
        request_body_bytes_len: int | None = None,
        soap_action: str | None = None,
        content_type: str | None = None,
        timestamp_window_seconds: int | None = None,
        has_ws_security: bool | None = None,
        has_bst: bool | None = None,
        cert_der_bytes_len: int | None = None,
        signature_method: str | None = None,
        digest_method: str | None = None,
        signed_reference_count: int | None = None,
        signed_reference_targets_exist: bool | None = None,
        has_header_action: bool | None = None,
        header_action_value_ok: bool | None = None,
        header_action_must_understand: bool | None = None,
        header_action_order: str | None = None,
        security_must_understand: bool | None = None,
        operation: str | None = None,
        has_authorization: bool | None = None,
        authorization_value_len: int | None = None,
        has_id_solicitud: bool | None = None,
        id_solicitud_redacted: str | None = None,
        has_rfc_solicitante: bool | None = None,
        has_signature: bool | None = None,
        endpoint_url_ok: bool | None = None,
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
            request_body_bytes_len=request_body_bytes_len,
            soap_action=soap_action,
            content_type=content_type,
            timestamp_window_seconds=timestamp_window_seconds,
            has_ws_security=has_ws_security,
            has_bst=has_bst,
            cert_der_bytes_len=cert_der_bytes_len,
            signature_method=signature_method,
            digest_method=digest_method,
            signed_reference_count=signed_reference_count,
            signed_reference_targets_exist=signed_reference_targets_exist,
            has_header_action=has_header_action,
            header_action_value_ok=header_action_value_ok,
            header_action_must_understand=header_action_must_understand,
            header_action_order=header_action_order,
            security_must_understand=security_must_understand,
            operation=operation,
            has_authorization=has_authorization,
            authorization_value_len=authorization_value_len,
            has_id_solicitud=has_id_solicitud,
            id_solicitud_redacted=id_solicitud_redacted,
            has_rfc_solicitante=has_rfc_solicitante,
            has_signature=has_signature,
            endpoint_url_ok=endpoint_url_ok,
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


class SatV15RequestOperation(StrEnum):
    """SAT v1.5 specialized request operations used by live metadata smoke."""

    ISSUED = "SolicitaDescargaEmitidos"
    RECEIVED = "SolicitaDescargaRecibidos"
    FOLIO = "SolicitaDescargaFolio"


@dataclass(frozen=True)
class SatLiveRequestAttempt:
    """Redacted metadata request attempt details safe for CLI output."""

    result: SatRequestResult
    operation: SatV15RequestOperation
    request_body_bytes_len: int
    envelope_sha256: str
    signed_reference_count: int


@dataclass(frozen=True)
class AuthRequestReadiness:
    request_body_bytes_len: int
    envelope_sha256: str
    soap_action: str
    content_type: str
    timestamp_window_seconds: int | None
    has_ws_security: bool
    has_bst: bool
    cert_der_bytes_len: int | None
    signature_method: str | None
    digest_method: str | None
    signed_reference_count: int
    signed_reference_targets_exist: bool
    has_header_action: bool
    header_action_value_ok: bool
    header_action_must_understand: bool
    header_action_order: str
    security_must_understand: bool

    def error_fields(self) -> dict[str, object]:
        return {
            "request_body_bytes_len": self.request_body_bytes_len,
            "envelope_sha256": self.envelope_sha256,
            "soap_action": self.soap_action,
            "content_type": self.content_type,
            "timestamp_window_seconds": self.timestamp_window_seconds,
            "has_ws_security": self.has_ws_security,
            "has_bst": self.has_bst,
            "cert_der_bytes_len": self.cert_der_bytes_len,
            "signature_method": self.signature_method,
            "digest_method": self.digest_method,
            "signed_reference_count": self.signed_reference_count,
            "signed_reference_targets_exist": self.signed_reference_targets_exist,
            "has_header_action": self.has_header_action,
            "header_action_value_ok": self.header_action_value_ok,
            "header_action_must_understand": self.header_action_must_understand,
            "header_action_order": self.header_action_order,
            "security_must_understand": self.security_must_understand,
        }


@dataclass(frozen=True)
class VerifyRequestReadiness:
    request_body_bytes_len: int
    envelope_sha256: str
    soap_action: str
    content_type: str
    has_authorization: bool
    authorization_value_len: int
    has_id_solicitud: bool
    id_solicitud_redacted: str
    has_rfc_solicitante: bool
    has_signature: bool
    signed_reference_count: int
    endpoint_url_ok: bool
    operation: str

    def error_fields(self) -> dict[str, object]:
        return {
            "request_body_bytes_len": self.request_body_bytes_len,
            "envelope_sha256": self.envelope_sha256,
            "soap_action": self.soap_action,
            "content_type": self.content_type,
            "has_authorization": self.has_authorization,
            "authorization_value_len": self.authorization_value_len,
            "has_id_solicitud": self.has_id_solicitud,
            "id_solicitud_redacted": self.id_solicitud_redacted,
            "has_rfc_solicitante": self.has_rfc_solicitante,
            "has_signature": self.has_signature,
            "signed_reference_count": self.signed_reference_count,
            "endpoint_url_ok": self.endpoint_url_ok,
            "operation": self.operation,
        }
@dataclass(frozen=True)
class SatLiveSmokeEndpoints:
    auth: str = DEFAULT_AUTH_ENDPOINT
    request: str = DEFAULT_REQUEST_ENDPOINT
    verify: str = DEFAULT_VERIFY_ENDPOINT
    download: str = DEFAULT_DOWNLOAD_ENDPOINT
@dataclass(frozen=True)
class SatLiveSmokeSummary:
    result: str
    auth: str
    request: str = "not_run"
    verification: str = "not_run"
    operation: str = ""
    id_solicitud: str = field(default="", repr=False)
    id_solicitud_redacted: str = ""
    sat_state: str = ""
    sat_code: str = ""
    sat_message: str = ""
    package_count: int = 0
    request_body_bytes_len: int | None = None
    envelope_sha256: str | None = None
    signed_reference_count: int | None = None
    diagnostics: tuple[SatLiveDiagnosticEntry, ...] = ()


def _request_summary(result: str, attempt: SatLiveRequestAttempt) -> SatLiveSmokeSummary:
    return SatLiveSmokeSummary(
        result=result,
        auth="authenticated",
        request=attempt.result.action.value,
        operation=attempt.operation.value,
        id_solicitud=attempt.result.request_id,
        id_solicitud_redacted=_redact_identifier(attempt.result.request_id),
        sat_code=attempt.result.sat_code,
        sat_message=attempt.result.message,
        request_body_bytes_len=attempt.request_body_bytes_len,
        envelope_sha256=attempt.envelope_sha256,
        signed_reference_count=attempt.signed_reference_count,
    )


def _redact_identifier(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"
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
        auth_envelope_variant: str = DEFAULT_AUTH_ENVELOPE_VARIANT,
        wcf_action_header_enabled: bool = True,
    ) -> None:
        self._profile = profile
        self._provider = provider
        self._transport = transport
        self._material = material
        self._endpoints = endpoints or SatLiveSmokeEndpoints(
            resolve_auth_endpoint(os.environ),
            os.getenv("CFDI_VAULT_SAT_REQUEST_ENDPOINT", DEFAULT_REQUEST_ENDPOINT),
            os.getenv("CFDI_VAULT_SAT_VERIFY_ENDPOINT", DEFAULT_VERIFY_ENDPOINT),
            os.getenv("CFDI_VAULT_SAT_DOWNLOAD_ENDPOINT", DEFAULT_DOWNLOAD_ENDPOINT),
        )
        self._timeout_seconds = timeout_seconds
        self._auth_envelope_variant = _validated_auth_envelope_variant(auth_envelope_variant)
        self._wcf_action_header_enabled = wcf_action_header_enabled
    def auth_smoke(self) -> SatLiveSmokeSummary:
        self._authenticate()
        return SatLiveSmokeSummary(result="auth-ok", auth="authenticated")
    def metadata_smoke(self, query: DownloadQuery) -> SatLiveSmokeSummary:
        self._require_metadata_only(query)
        authorization = self._authenticate()
        attempt = self._send_request(authorization, query)
        request_result = attempt.result
        request_status = request_result.action.value
        if request_result.action != SatOutcomeAction.ACCEPTED:
            return _request_summary("request-not-accepted", attempt)
        verification = self._send_verification(authorization, request_result.request_id)
        return SatLiveSmokeSummary(
            result="metadata-smoke-ok",
            auth="authenticated",
            request=request_status,
            verification=verification.action.value,
            operation=attempt.operation.value,
            id_solicitud=request_result.request_id,
            id_solicitud_redacted=_redact_identifier(request_result.request_id),
            sat_state=verification.state.value,
            sat_code=verification.sat_code,
            sat_message=verification.message,
            package_count=len(verification.package_ids),
            request_body_bytes_len=attempt.request_body_bytes_len,
            envelope_sha256=attempt.envelope_sha256,
            signed_reference_count=attempt.signed_reference_count,
        )

    def metadata_request_smoke(self, query: DownloadQuery, *, max_range_days: int = 1) -> SatLiveSmokeSummary:
        """Run guarded auth + SAT v1.5 metadata request only; no verify or package download."""

        self._require_metadata_only(query, max_range_days=max_range_days)
        authorization = self._authenticate()
        attempt = self._send_request(authorization, query)
        result = "metadata-request-submitted" if attempt.result.action == SatOutcomeAction.ACCEPTED else "request-not-accepted"
        return _request_summary(result, attempt)

    def metadata_verify_smoke(self, request_id: str) -> SatLiveSmokeSummary:
        """Run guarded auth + SAT verification for one stored request id; no request/download."""

        verification = self.verify_request(request_id)
        normalized_request_id = request_id.strip()
        return SatLiveSmokeSummary(
            result="metadata-verify-ok",
            auth="authenticated",
            request="not_run",
            verification=verification.action.value,
            operation="VerificaSolicitudDescarga",
            id_solicitud=normalized_request_id,
            id_solicitud_redacted=_redact_identifier(normalized_request_id),
            sat_state=verification.state.value,
            sat_code=verification.sat_code,
            sat_message=verification.message,
            package_count=len(verification.package_ids),
        )

    def verify_request(self, request_id: str) -> SatVerificationResult:
        """Verify one stored request id for the scheduler port; no request/download."""

        normalized_request_id = request_id.strip()
        if not normalized_request_id:
            raise SatLiveSmokeError(
                "live verify requires a stored request id",
                stage="preflight",
                error_kind="guard_failed",
                safe_hint="request-ref must resolve to an IdSolicitud in local state",
            )
        authorization = self._authenticate()
        return self._send_verification(authorization, normalized_request_id)

    def download_package(self, package_id: str):
        """Download one stored package id; no request or verify."""

        normalized_package_id = package_id.strip()
        if not normalized_package_id:
            raise SatLiveSmokeError(
                "live package download requires a stored package id",
                stage="preflight",
                error_kind="guard_failed",
                safe_hint="package-ref must resolve to an IdPaquete in local state",
            )
        authorization = self._authenticate()
        return self._send_package_download(authorization, normalized_package_id)

    def _authenticate(self) -> str:
        body = _build_stage(
            "auth_envelope_build",
            lambda: _build_auth_envelope(
                self._load_material(),
                self._endpoints.auth,
                auth_envelope_variant=self._auth_envelope_variant,
                wcf_action_header_enabled=self._wcf_action_header_enabled,
            ),
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
        operation = resolve_v15_request_operation(query)
        body = _build_stage("metadata_request_build", lambda: _build_request_envelope(query, self._load_material(), operation=operation))
        envelope_sha256 = _digest(body)
        signed_reference_count = _signed_reference_count(body)
        response = self._send(
            self._endpoints.request,
            v15_request_soap_action(operation),
            body,
            authorization=authorization,
            stage="metadata_request_transport",
            endpoint_label="metadata_request",
            operation=operation.value,
        )
        started = time.perf_counter()
        try:
            return SatLiveRequestAttempt(
                result=parse_download_request_response(response),
                operation=operation,
                request_body_bytes_len=len(body),
                envelope_sha256=envelope_sha256,
                signed_reference_count=signed_reference_count,
            )
        except (SatSoapParseError, ValueError):
            raise SatLiveSmokeError(
                "SAT request response could not be parsed",
                stage="metadata_request_parse",
                error_kind=_response_error_kind(response),
                safe_hint=PARSE_HINT,
                soap_fault_code=_soap_fault_code(response),
                payload_size=len(response),
                duration_ms=_elapsed_ms(started),
                operation=operation.value,
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

    def _send_package_download(self, authorization: str, package_id: str):
        body = _build_stage("package_download", lambda: _build_package_download_envelope(package_id, self._profile.rfc, self._load_material()))
        response = self._send(
            self._endpoints.download,
            DOWNLOAD_ACTION,
            body,
            authorization=authorization,
            stage="package_download",
            endpoint_label="package_download",
        )
        started = time.perf_counter()
        try:
            return parse_package_download_response(response, package_id=package_id)
        except (SatSoapParseError, ValueError):
            raise SatLiveSmokeError(
                "SAT package download response could not be parsed",
                stage="package_download",
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
        operation: str | None = None,
    ) -> bytes:
        headers = build_soap11_headers(action)
        if authorization:
            headers["Authorization"] = _wrap_authorization(authorization)
        readiness = None
        if endpoint_label == "auth" and authorization is None:
            readiness = _assert_auth_request_ready(
                body,
                headers,
                auth_envelope_variant=self._auth_envelope_variant,
                wcf_action_header_enabled=self._wcf_action_header_enabled,
            )
        elif endpoint_label == "verify":
            readiness = _assert_verify_request_ready(endpoint, body, headers)
        started = time.perf_counter()
        try:
            response = self._transport.send(SoapTransportRequest(endpoint=endpoint, body=body, headers=headers, timeout_seconds=self._timeout_seconds))
        except HTTPError as exc:
            response_body = exc.read(8192)
            raise SatLiveSmokeError(
                "SAT transport returned a non-success status",
                stage=stage,
                error_kind=_http_response_error_kind(response_body),
                safe_hint=TRANSPORT_HINT,
                endpoint=endpoint_label,
                http_status=exc.code,
                payload_size=len(response_body),
                envelope_sha256=_digest(body),
                duration_ms=_elapsed_ms(started),
                operation=operation,
                **_readiness_error_fields(readiness),
            ) from None
        except Exception as exc:
            failure = _classify_transport_failure(exc)
            error_kind = "verify_read_timeout" if stage == "verify_transport" and failure.error_kind == "timeout" else failure.error_kind
            raise SatLiveSmokeError(
                "SAT transport failed",
                stage=stage,
                error_kind=error_kind,
                safe_hint=TRANSPORT_HINT,
                endpoint=endpoint_label,
                payload_size=len(body),
                envelope_sha256=_digest(body),
                exception_class=failure.exception_class,
                exception_errno=failure.exception_errno,
                transport_layer=failure.transport_layer,
                duration_ms=_elapsed_ms(started),
                operation=operation,
                **_readiness_error_fields(readiness),
            ) from None
        if not 200 <= response.status_code < 300:
            raise SatLiveSmokeError(
                "SAT transport returned a non-success status",
                stage=stage,
                error_kind=_http_response_error_kind(response.body),
                safe_hint=TRANSPORT_HINT,
                endpoint=endpoint_label,
                http_status=response.status_code,
                payload_size=len(response.body),
                envelope_sha256=_digest(body),
                duration_ms=_elapsed_ms(started),
                operation=operation,
                **_readiness_error_fields(readiness),
            )
        return response.body
    def _load_material(self) -> SatEfirmMaterial:
        if self._material is None:
            self._material = load_sat_efirma_material(self._profile, self._provider)  # type: ignore[misc]
        return self._material
    @staticmethod
    def _require_metadata_only(query: DownloadQuery, *, max_range_days: int = 1) -> None:
        if query.request_type.value != "metadata":
            raise SatLiveSmokeError(
                "live smoke requires metadata-only query",
                stage="preflight",
                error_kind="guard_failed",
                safe_hint="metadata-only live smoke is required",
            )
        _validate_v15_live_metadata_query(query, max_range_days=max_range_days)
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
def _build_auth_envelope(
    material: SatEfirmMaterial,
    endpoint: str,
    *,
    auth_envelope_variant: str = DEFAULT_AUTH_ENVELOPE_VARIANT,
    wcf_action_header_enabled: bool = True,
) -> bytes:
    variant = _validated_auth_envelope_variant(auth_envelope_variant)
    created = datetime.now(timezone.utc)
    expires = created + timedelta(minutes=5)
    envelope = _envelope(SAT_AUTH_NS)
    header = envelope.find(f"{{{SOAP11_NS}}}Header")
    assert header is not None
    if wcf_action_header_enabled and variant == AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY:
        _append_wcf_action_header(header)
    security = etree.SubElement(header, f"{{{WSSE_NS}}}Security", {f"{{{SOAP11_NS}}}mustUnderstand": "1"})
    if wcf_action_header_enabled and variant == AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION:
        _append_wcf_action_header(header)
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
    if variant != AUTH_ENVELOPE_VARIANT_SECURITY_ONLY:
        etree.SubElement(header, f"{{{ADDR_NS}}}To", {f"{{{SOAP11_NS}}}mustUnderstand": "1"}).text = endpoint
    body = envelope.find(f"{{{SOAP11_NS}}}Body")
    assert body is not None
    etree.SubElement(body, f"{{{SAT_AUTH_NS}}}{AUTH_OPERATION}")
    return etree.tostring(envelope, encoding="UTF-8", xml_declaration=True)


def _append_wcf_action_header(header: etree._Element) -> None:
    etree.SubElement(header, f"{{{ADDR_NS}}}Action", {f"{{{SOAP11_NS}}}mustUnderstand": "1"}).text = AUTH_ACTION


def _validated_auth_envelope_variant(value: str) -> str:
    if value not in AUTH_ENVELOPE_VARIANTS:
        raise ValueError("invalid-auth-envelope-variant")
    return value
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


def resolve_v15_request_operation(query: DownloadQuery) -> SatV15RequestOperation:
    """Resolve the exact SAT v1.5 request operation; never fall back to legacy."""

    if query.uuid or query.direction == DownloadDirection.FOLIO:
        return SatV15RequestOperation.FOLIO
    if query.direction == DownloadDirection.RECEIVED:
        return SatV15RequestOperation.RECEIVED
    if query.direction == DownloadDirection.ISSUED:
        return SatV15RequestOperation.ISSUED
    raise SatLiveSmokeError(
        "unsupported SAT v1.5 request operation",
        stage="preflight",
        error_kind="guard_failed",
        safe_hint="live metadata smoke requires received, issued, or folio routing",
    )


def v15_request_soap_action(operation: SatV15RequestOperation) -> str:
    return f"{REQUEST_ACTION_BASE}/{operation.value}"


def _validate_v15_live_metadata_query(query: DownloadQuery, *, max_range_days: int = 1) -> None:
    if max_range_days < 1:
        raise _v15_guard_error("live metadata smoke max range must be positive", "invalid-max-range-days")
    operation = resolve_v15_request_operation(query)
    if operation == SatV15RequestOperation.FOLIO:
        if not query.uuid:
            raise _v15_guard_error("folio request requires uuid", "uuid-required-for-folio-request")
        return
    if query.period is None:
        raise _v15_guard_error("live metadata smoke requires a date range", "date-range-required")
    elapsed_seconds = (query.period.end - query.period.start).total_seconds()
    if elapsed_seconds <= 0:
        raise _v15_guard_error("FechaInicial must be before FechaFinal", "fecha-inicial-must-be-before-fecha-final")
    if elapsed_seconds < 2:
        raise _v15_guard_error("v1.5 metadata smoke requires at least 2 seconds", "minimum-two-second-range-required")
    if elapsed_seconds > 86_400 * max_range_days:
        raise _v15_guard_error(f"live metadata smoke range must be at most {max_range_days} day(s)", "range-too-wide")


def _v15_guard_error(message: str, hint: str) -> SatLiveSmokeError:
    return SatLiveSmokeError(
        message,
        stage="preflight",
        error_kind="guard_failed",
        safe_hint=hint,
    )


def _build_request_envelope(query: DownloadQuery, material: SatEfirmMaterial, *, operation: SatV15RequestOperation | None = None) -> bytes:
    resolved_operation = operation or resolve_v15_request_operation(query)
    return _operation_envelope(resolved_operation.value, _signed_payload("solicitud", _request_attrs(query, resolved_operation), material))


def _request_attrs(query: DownloadQuery, operation: SatV15RequestOperation) -> dict[str, str]:
    requester_rfc = query.requester_rfc.upper()
    if operation == SatV15RequestOperation.FOLIO:
        if not query.uuid:
            raise _v15_guard_error("folio request requires uuid", "uuid-required-for-folio-request")
        return {"Folio": query.uuid, "RfcSolicitante": requester_rfc}
    if query.period is None:
        raise _v15_guard_error("live metadata smoke requires a date range", "date-range-required")
    attrs = {
        "FechaInicial": _sat_dt(query.period.start),
        "FechaFinal": _sat_dt(query.period.end),
        "RfcSolicitante": requester_rfc,
        "TipoSolicitud": "Metadata",
    }
    if operation == SatV15RequestOperation.ISSUED:
        attrs["RfcEmisor"] = requester_rfc
    else:
        attrs["RfcReceptor"] = requester_rfc
        if query.issuer_rfc:
            attrs["RfcEmisor"] = query.issuer_rfc.upper()
    if query.document_status:
        attrs["EstadoComprobante"] = query.document_status
    if query.document_type:
        attrs["TipoComprobante"] = query.document_type
    if query.complement:
        attrs["Complemento"] = query.complement
    return attrs
def _build_verify_envelope(request_id: str, requester_rfc: str, material: SatEfirmMaterial) -> bytes:
    operation = etree.Element(f"{{{SAT_REQUEST_NS}}}VerificaSolicitudDescarga", nsmap={"des": SAT_REQUEST_NS})
    solicitud = etree.SubElement(operation, f"{{{SAT_REQUEST_NS}}}solicitud", {"IdSolicitud": request_id, "RfcSolicitante": requester_rfc.upper()})
    solicitud.append(_build_v15_verify_signature(operation, material))
    envelope = _envelope(SAT_REQUEST_NS)
    body = envelope.find(f"{{{SOAP11_NS}}}Body")
    assert body is not None
    body.append(operation)
    return etree.tostring(envelope, encoding="UTF-8", xml_declaration=True)


def _build_package_download_envelope(package_id: str, requester_rfc: str, material: SatEfirmMaterial) -> bytes:
    payload = _signed_payload("peticionDescarga", {"IdPaquete": package_id, "RfcSolicitante": requester_rfc.upper()}, material)
    return _operation_envelope("Descargar", payload)


def _signed_payload(name: str, attrs: dict[str, str], material: SatEfirmMaterial) -> etree._Element:
    payload = etree.Element(f"{{{SAT_REQUEST_NS}}}{name}", attrs)
    return _SatSha1XmlSigner(
        method=methods.enveloped,
        signature_algorithm=SignatureMethod.RSA_SHA1,
        digest_algorithm=DigestAlgorithm.SHA1,
        c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_0,
    ).sign(payload, key=material.private_key, cert=material.certificate_pem)


def _build_v15_verify_signature(operation: etree._Element, material: SatEfirmMaterial) -> etree._Element:
    digest_value = base64.b64encode(hashlib.sha1(_exclusive_c14n(operation)).digest()).decode("ascii")
    signature = etree.Element(f"{{{DS_NS}}}Signature", nsmap={None: DS_NS})
    signed_info = etree.SubElement(signature, f"{{{DS_NS}}}SignedInfo")
    etree.SubElement(signed_info, f"{{{DS_NS}}}CanonicalizationMethod", Algorithm=VERIFY_EXCLUSIVE_C14N)
    etree.SubElement(signed_info, f"{{{DS_NS}}}SignatureMethod", Algorithm=SignatureMethod.RSA_SHA1.value)
    reference = etree.SubElement(signed_info, f"{{{DS_NS}}}Reference", URI="")
    transforms = etree.SubElement(reference, f"{{{DS_NS}}}Transforms")
    etree.SubElement(transforms, f"{{{DS_NS}}}Transform", Algorithm=VERIFY_EXCLUSIVE_C14N)
    etree.SubElement(reference, f"{{{DS_NS}}}DigestMethod", Algorithm=DigestAlgorithm.SHA1.value)
    etree.SubElement(reference, f"{{{DS_NS}}}DigestValue").text = digest_value

    signature_value = material.private_key.sign(_exclusive_c14n(signed_info), padding.PKCS1v15(), hashes.SHA1())
    etree.SubElement(signature, f"{{{DS_NS}}}SignatureValue").text = base64.b64encode(signature_value).decode("ascii")
    signature.append(_verify_key_info(material))
    return signature


def _verify_key_info(material: SatEfirmMaterial) -> etree._Element:
    certificate = _load_certificate(material.certificate_pem)
    key_info = etree.Element(f"{{{DS_NS}}}KeyInfo")
    x509_data = etree.SubElement(key_info, f"{{{DS_NS}}}X509Data")
    issuer_serial = etree.SubElement(x509_data, f"{{{DS_NS}}}X509IssuerSerial")
    etree.SubElement(issuer_serial, f"{{{DS_NS}}}X509IssuerName").text = certificate.issuer.rfc4514_string()
    etree.SubElement(issuer_serial, f"{{{DS_NS}}}X509SerialNumber").text = str(certificate.serial_number)
    etree.SubElement(x509_data, f"{{{DS_NS}}}X509Certificate").text = material.certificate_der_b64
    return key_info


def _exclusive_c14n(node: etree._Element) -> bytes:
    return etree.tostring(node, method="c14n", exclusive=True, with_comments=False)
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


def _assert_auth_request_ready(
    body: bytes | None,
    headers: dict[str, str],
    *,
    auth_envelope_variant: str = DEFAULT_AUTH_ENVELOPE_VARIANT,
    wcf_action_header_enabled: bool = True,
) -> AuthRequestReadiness:
    expected_order = _validated_auth_envelope_variant(auth_envelope_variant)
    readiness = _auth_request_readiness(
        body,
        headers,
    )
    expects_header_action = expected_order != AUTH_ENVELOPE_VARIANT_SECURITY_ONLY
    failures: list[bool] = [
        body is None,
        readiness.request_body_bytes_len <= 500,
        readiness.soap_action != f'"{AUTH_ACTION}"',
        readiness.content_type != AUTH_CONTENT_TYPE,
        _header_value(headers, "Accept") != AUTH_ACCEPT,
        _header_value(headers, "Authorization") is not None,
        not readiness.has_ws_security,
        not readiness.has_bst,
        readiness.cert_der_bytes_len is None or readiness.cert_der_bytes_len <= 0,
        readiness.signature_method is None,
        readiness.digest_method is None,
        readiness.signed_reference_count <= 0,
        not readiness.signed_reference_targets_exist,
        not readiness.security_must_understand,
    ]
    if expects_header_action:
        failures.extend(
            [
                not readiness.has_header_action,
                not readiness.header_action_value_ok,
                not readiness.header_action_must_understand,
                readiness.header_action_order != expected_order,
                not wcf_action_header_enabled,
            ]
        )
    else:
        failures.extend([readiness.has_header_action, readiness.header_action_order != AUTH_ENVELOPE_VARIANT_SECURITY_ONLY])
    if body is None or _contains_placeholder_literals(body):
        failures.append(True)
    if _header_value(headers, "Content-Length") is not None:
        try:
            failures.append(int(_header_value(headers, "Content-Length") or "-1") != readiness.request_body_bytes_len)
        except ValueError:
            failures.append(True)
    if any(failures):
        raise SatLiveSmokeError(
            "SAT auth request failed local readiness checks",
            stage="auth_request_readiness",
            error_kind="client_configuration_error",
            safe_hint=READINESS_HINT,
            payload_size=readiness.request_body_bytes_len,
            **readiness.error_fields(),
        ) from None
    return readiness


def _assert_verify_request_ready(endpoint: str, body: bytes | None, headers: dict[str, str]) -> VerifyRequestReadiness:
    readiness = _verify_request_readiness(endpoint, body, headers)
    placeholders_present = body is None or _contains_placeholder_literals(body)
    failures = [
        not readiness.endpoint_url_ok,
        readiness.soap_action != f'"{VERIFY_ACTION}"',
        readiness.content_type != AUTH_CONTENT_TYPE,
        not readiness.has_authorization,
        readiness.authorization_value_len <= 0,
        readiness.request_body_bytes_len <= 300,
        readiness.operation != "VerificaSolicitudDescarga",
        not readiness.has_id_solicitud,
        not readiness.has_rfc_solicitante,
        not readiness.has_signature,
        readiness.signed_reference_count <= 0,
        placeholders_present,
    ]
    if any(failures):
        fields = readiness.error_fields()
        fields.pop("envelope_sha256", None)
        raise SatLiveSmokeError(
            "SAT verify request failed local readiness checks",
            stage="verify_request_readiness",
            error_kind="client_configuration_error",
            safe_hint="check verify endpoint, SOAPAction, Authorization WRAP, signed solicitud body, and placeholders without printing SOAP",
            payload_size=readiness.request_body_bytes_len,
            envelope_sha256=readiness.envelope_sha256,
            **fields,
        ) from None
    return readiness


def _verify_request_readiness(endpoint: str, body: bytes | None, headers: dict[str, str]) -> VerifyRequestReadiness:
    body_bytes = body or b""
    root = _parse_xml_or_none(body_bytes)
    body_node = _find(root, SOAP11_NS, "Body")
    operation = _find(body_node, SAT_REQUEST_NS, "VerificaSolicitudDescarga")
    solicitud = _find(operation, SAT_REQUEST_NS, "solicitud")
    signature = _find(solicitud, DS_NS, "Signature")
    id_solicitud = solicitud.get("IdSolicitud", "") if solicitud is not None else ""
    rfc_solicitante = solicitud.get("RfcSolicitante", "") if solicitud is not None else ""
    return VerifyRequestReadiness(
        request_body_bytes_len=len(body_bytes),
        envelope_sha256=_digest(body_bytes),
        soap_action=_header_value(headers, "SOAPAction") or "",
        content_type=_header_value(headers, "Content-Type") or "",
        has_authorization=_header_value(headers, "Authorization") is not None,
        authorization_value_len=_authorization_token_len(_header_value(headers, "Authorization") or ""),
        has_id_solicitud=bool(id_solicitud),
        id_solicitud_redacted=_redact_identifier(id_solicitud),
        has_rfc_solicitante=bool(rfc_solicitante),
        has_signature=signature is not None,
        signed_reference_count=_signed_reference_count(body_bytes),
        endpoint_url_ok=endpoint == DEFAULT_VERIFY_ENDPOINT,
        operation=etree.QName(operation).localname if operation is not None else "",
    )


def _authorization_token_len(value: str) -> int:
    prefix = 'WRAP access_token="'
    stripped = value.strip()
    if not stripped.startswith(prefix) or not stripped.endswith('"'):
        return 0
    return len(stripped[len(prefix) : -1])


def _auth_request_readiness(
    body: bytes | None,
    headers: dict[str, str],
) -> AuthRequestReadiness:
    body_bytes = body or b""
    envelope_sha256 = _digest(body_bytes)
    root = _parse_xml_or_none(body_bytes)
    header = _find(root, SOAP11_NS, "Header")
    security = _find(header, WSSE_NS, "Security")
    timestamp = _find(security, WSU_NS, "Timestamp")
    bst = _find(security, WSSE_NS, "BinarySecurityToken")
    signature = _find(security, DS_NS, "Signature")
    body_node = _find(root, SOAP11_NS, "Body")
    operation = _find(body_node, SAT_AUTH_NS, AUTH_OPERATION)
    action = _find(header, ADDR_NS, "Action")
    references = list(signature.findall(f".//{{{DS_NS}}}Reference")) if signature is not None else []
    signature_method = _algorithm(signature, "SignatureMethod")
    digest_method = _algorithm(signature, "DigestMethod")
    header_action_order = _auth_header_action_order(header)
    return AuthRequestReadiness(
        request_body_bytes_len=len(body_bytes),
        envelope_sha256=envelope_sha256,
        soap_action=_header_value(headers, "SOAPAction") or "",
        content_type=_header_value(headers, "Content-Type") or "",
        timestamp_window_seconds=_timestamp_window_seconds(timestamp),
        has_ws_security=security is not None,
        has_bst=bst is not None,
        cert_der_bytes_len=_cert_der_bytes_len(bst),
        signature_method=signature_method,
        digest_method=digest_method,
        signed_reference_count=len(references),
        signed_reference_targets_exist=operation is not None and _references_target_existing_ids(root, references),
        has_header_action=action is not None,
        header_action_value_ok=_text(action) == AUTH_ACTION,
        header_action_must_understand=_must_understand(action),
        header_action_order=header_action_order,
        security_must_understand=_must_understand(security),
    )


def _readiness_error_fields(readiness: AuthRequestReadiness | VerifyRequestReadiness | None) -> dict[str, object]:
    if readiness is None:
        return {}
    fields = readiness.error_fields()
    fields.pop("envelope_sha256", None)
    fields.pop("operation", None)
    return fields


def _header_value(headers: dict[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _parse_xml_or_none(body: bytes) -> etree._Element | None:
    try:
        return etree.fromstring(body)
    except etree.XMLSyntaxError:
        return None


def _signed_reference_count(body: bytes) -> int:
    root = _parse_xml_or_none(body)
    if root is None:
        return 0
    return len(root.findall(f".//{{{DS_NS}}}Reference"))


def _find(node: etree._Element | None, namespace: str, local_name: str) -> etree._Element | None:
    return node.find(f"{{{namespace}}}{local_name}") if node is not None else None


def _algorithm(node: etree._Element | None, local_name: str) -> str | None:
    item = _find(node, DS_NS, "SignedInfo")
    if item is None:
        item = node
    child = item.find(f".//{{{DS_NS}}}{local_name}") if item is not None else None
    return child.get("Algorithm") if child is not None else None


def _timestamp_window_seconds(timestamp: etree._Element | None) -> int | None:
    created = _parse_utc(_text(_find(timestamp, WSU_NS, "Created")))
    expires = _parse_utc(_text(_find(timestamp, WSU_NS, "Expires")))
    if created is None or expires is None:
        return None
    return round((expires - created).total_seconds())


def _parse_utc(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _cert_der_bytes_len(bst: etree._Element | None) -> int | None:
    value = _text(bst)
    if value is None:
        return None
    try:
        return len(base64.b64decode(value.encode("ascii"), validate=True))
    except (ValueError, TypeError):
        return None


def _references_target_existing_ids(root: etree._Element | None, references: list[etree._Element]) -> bool:
    if root is None or not references:
        return False
    ids = {
        value
        for item in root.iter()
        for value in (item.get("Id"), item.get(f"{{{WSU_NS}}}Id"))
        if value
    }
    return all((reference.get("URI") or "").startswith("#") and (reference.get("URI") or "")[1:] in ids for reference in references)


def _must_understand(node: etree._Element | None) -> bool:
    return node is not None and node.get(f"{{{SOAP11_NS}}}mustUnderstand") == "1"


def _auth_header_action_order(header: etree._Element | None) -> str:
    if header is None:
        return "missing_header"
    action_index: int | None = None
    security_index: int | None = None
    for index, child in enumerate(header):
        name = etree.QName(child)
        if name.namespace == ADDR_NS and name.localname == "Action":
            action_index = index
        if name.namespace == WSSE_NS and name.localname == "Security":
            security_index = index
    if action_index is None and security_index is not None:
        return AUTH_ENVELOPE_VARIANT_SECURITY_ONLY
    if action_index is None or security_index is None:
        return "missing_action_or_security"
    return "action_before_security" if action_index < security_index else "security_before_action"


def _contains_placeholder_literals(body: bytes) -> bool:
    root = _parse_xml_or_none(body)
    if root is None:
        return True
    redacted = deepcopy(root)
    for item in redacted.iter():
        if etree.QName(item).localname in {"BinarySecurityToken", "SignatureValue", "DigestValue", "X509Certificate"}:
            item.text = ""
    safe_body = etree.tostring(redacted, encoding="UTF-8")
    return any(marker in safe_body for marker in (b"None", b"null", b"undefined", b"MISSING", b"TODO"))


def _text(node: etree._Element | None) -> str | None:
    return node.text.strip() if node is not None and node.text else None


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
    if isinstance(root, (RemoteDisconnected, EOFError)) or "remote end closed" in marker or "remote host closed" in marker or "connection closed" in marker:
        return TransportFailureClassification("remote_closed_connection", "network", exception_class, exception_errno)
    if isinstance(root, ConnectionResetError) or exception_errno in {errno.ECONNRESET, getattr(errno, "WSAECONNRESET", -1)} or "reset" in marker:
        return TransportFailureClassification("connection_reset_during_post", "network", exception_class, exception_errno)
    if "proxy" in marker or "tunnel" in marker or "firewall" in marker:
        return TransportFailureClassification("proxy_connect_failed", "proxy", exception_class, exception_errno)
    if isinstance(root, URLError):
        return TransportFailureClassification("client_configuration_error", "client", exception_class, exception_errno)
    return TransportFailureClassification("client_configuration_error", "client", exception_class, exception_errno)


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
    return "soap_fault" if _soap_fault_code(response) else "unexpected_http_response"


def _http_response_error_kind(response: bytes) -> str:
    return "soap_fault" if _soap_fault_code(response) else "http_status_error"
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
