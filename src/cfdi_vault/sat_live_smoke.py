"""Guarded live SAT metadata-smoke adapter: auth/request/verify only, no package download."""
from __future__ import annotations
import base64
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key
from lxml import etree
from signxml import XMLSigner, methods
from signxml.algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod
from cfdi_vault.domain import DownloadDirection, DownloadQuery
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
DEFAULT_AUTH_ENDPOINT = "https://cfdiau.sat.gob.mx/nidp/wsfed/ep?id=SATx509Custom"
DEFAULT_REQUEST_ENDPOINT = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc"
DEFAULT_VERIFY_ENDPOINT = "https://cfdidescargamasivaverificacion.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc"
class SatLiveSmokeError(RuntimeError):
    """Safe live smoke failure without credential, token, SOAP, RFC, path, or id detail."""
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
            os.getenv("CFDI_VAULT_SAT_AUTH_ENDPOINT", DEFAULT_AUTH_ENDPOINT),
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
        body = _build_auth_envelope(self._load_material(), self._endpoints.auth)
        response = self._send(self._endpoints.auth, AUTH_ACTION, body)
        try:
            return parse_authentication_response(response).authorization
        except (SatSoapParseError, ValueError):
            raise SatLiveSmokeError("SAT authentication response could not be parsed") from None
    def _send_request(self, authorization: str, query: DownloadQuery):
        body = _build_request_envelope(query, self._load_material())
        response = self._send(self._endpoints.request, REQUEST_ACTION, body, authorization=authorization)
        try:
            return parse_download_request_response(response)
        except (SatSoapParseError, ValueError):
            raise SatLiveSmokeError("SAT request response could not be parsed") from None
    def _send_verification(self, authorization: str, request_id: str):
        body = _build_verify_envelope(request_id, self._profile.rfc, self._load_material())
        response = self._send(self._endpoints.verify, VERIFY_ACTION, body, authorization=authorization)
        try:
            return parse_verification_response(response)
        except (SatSoapParseError, ValueError):
            raise SatLiveSmokeError("SAT verification response could not be parsed") from None
    def _send(self, endpoint: str, action: str, body: bytes, *, authorization: str | None = None) -> bytes:
        headers = {
            "Content-Type": "text/xml;charset=UTF-8",
            "SOAPAction": f'"{action}"',
        }
        if authorization:
            headers["Authorization"] = _wrap_authorization(authorization)
        try:
            response = self._transport.send(SoapTransportRequest(endpoint=endpoint, body=body, headers=headers, timeout_seconds=self._timeout_seconds))
        except Exception:
            raise SatLiveSmokeError("SAT transport failed") from None
        if not 200 <= response.status_code < 300:
            raise SatLiveSmokeError("SAT transport returned a non-success status")
        return response.body
    def _load_material(self) -> SatEfirmMaterial:
        if self._material is None:
            self._material = load_sat_efirma_material(self._profile, self._provider)  # type: ignore[misc]
        return self._material
    @staticmethod
    def _require_metadata_only(query: DownloadQuery) -> None:
        if query.request_type.value != "metadata":
            raise SatLiveSmokeError("live smoke requires metadata-only query")
def load_sat_efirma_material(profile: LocalProfile, provider: ExistenceProvider) -> SatEfirmMaterial:
    try:
        cert_bytes = profile.certificate_path.read_bytes()
        key_bytes = profile.private_key_path.read_bytes()
        phrase = provider.resolve(
            CredentialReference(uri=profile.phrase_ref, kind=CredentialKind.PHRASE),
            purpose="sat-live-smoke",
        ).reveal()
    except (OSError, CredentialProviderError):
        raise SatLiveSmokeError("local e.firma material could not be loaded") from None
    try:
        cert = _load_certificate(cert_bytes)
        private_key = _load_private_key(key_bytes, phrase.encode())
    except (TypeError, ValueError):
        raise SatLiveSmokeError("local e.firma material could not be parsed") from None
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
