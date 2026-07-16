"""Internal SAT v1.5 authentication and operation envelope primitives."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from lxml import etree
from signxml import XMLSigner, methods
from signxml.algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod

from cfdi_vault.sat_auth_constants import (
    AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION,
    AUTH_ENVELOPE_VARIANT_SECURITY_ONLY,
    AUTH_ENVELOPE_VARIANTS,
    AUTH_NAMESPACE,
    AUTH_OPERATION,
    DEFAULT_AUTH_ENVELOPE_VARIANT,
)
from cfdi_vault.sat_v15_contract import AUTH_ACTION, SAT_REQUEST_NS, SatV15RequestOperation

SOAP11_NS = "http://schemas.xmlsoap.org/soap/envelope/"
SAT_AUTH_NS = AUTH_NAMESPACE
WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
ADDR_NS = "http://schemas.microsoft.com/ws/2005/05/addressing/none"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
X509_VALUE_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
BASE64_ENCODING_TYPE = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)
VERIFY_EXCLUSIVE_C14N = CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0.value


@dataclass(frozen=True, repr=False)
class SatEfirmMaterial:
    """In-memory e.firma material whose representation never exposes values."""

    private_key: object
    certificate_pem: bytes
    certificate_der_b64: str

    def __repr__(self) -> str:
        return "SatEfirmMaterial(private_key=<redacted>, certificate=<redacted>)"


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
    reference = etree.SubElement(
        etree.SubElement(key_info, f"{{{WSSE_NS}}}SecurityTokenReference"),
        f"{{{WSSE_NS}}}Reference",
    )
    reference.set("URI", f"#{bst_id}")
    reference.set("ValueType", X509_VALUE_TYPE)
    return _SatSha1XmlSigner(
        method=methods.detached,
        signature_algorithm=SignatureMethod.RSA_SHA1,
        digest_algorithm=DigestAlgorithm.SHA1,
        c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    ).sign(envelope, key=material.private_key, reference_uri=["#_0"], id_attribute="Id", key_info=key_info)


def _build_request_envelope(
    operation: SatV15RequestOperation,
    attributes: dict[str, str],
    material: SatEfirmMaterial,
) -> bytes:
    return _operation_envelope(operation.value, _signed_payload("solicitud", attributes, material))


def _build_verify_envelope(request_id: str, requester_rfc: str, material: SatEfirmMaterial) -> bytes:
    operation = etree.Element(f"{{{SAT_REQUEST_NS}}}VerificaSolicitudDescarga", nsmap={"des": SAT_REQUEST_NS})
    solicitud = etree.SubElement(
        operation,
        f"{{{SAT_REQUEST_NS}}}solicitud",
        {"IdSolicitud": request_id, "RfcSolicitante": requester_rfc.upper()},
    )
    solicitud.append(_build_v15_verify_signature(operation, material))
    envelope = _envelope(SAT_REQUEST_NS)
    body = envelope.find(f"{{{SOAP11_NS}}}Body")
    assert body is not None
    body.append(operation)
    return etree.tostring(envelope, encoding="UTF-8", xml_declaration=True)


def _build_package_download_envelope(package_id: str, requester_rfc: str, material: SatEfirmMaterial) -> bytes:
    operation = etree.Element(f"{{{SAT_REQUEST_NS}}}Descargar", nsmap={"des": SAT_REQUEST_NS})
    peticion = etree.SubElement(
        operation,
        f"{{{SAT_REQUEST_NS}}}peticionDescarga",
        {"IdPaquete": package_id, "RfcSolicitante": requester_rfc.upper()},
    )
    peticion.append(_build_v15_package_download_signature(operation, material))
    envelope = _envelope(SAT_REQUEST_NS)
    body = envelope.find(f"{{{SOAP11_NS}}}Body")
    assert body is not None
    body.append(operation)
    return etree.tostring(envelope, encoding="UTF-8", xml_declaration=True)


def _signed_payload(name: str, attrs: dict[str, str], material: SatEfirmMaterial) -> etree._Element:
    payload = etree.Element(f"{{{SAT_REQUEST_NS}}}{name}", attrs)
    return _SatSha1XmlSigner(
        method=methods.enveloped,
        signature_algorithm=SignatureMethod.RSA_SHA1,
        digest_algorithm=DigestAlgorithm.SHA1,
        c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_0,
    ).sign(payload, key=material.private_key, cert=material.certificate_pem)


def _build_v15_verify_signature(operation: etree._Element, material: SatEfirmMaterial) -> etree._Element:
    return _build_v15_signed_operation_signature(operation, material)


def _build_v15_package_download_signature(operation: etree._Element, material: SatEfirmMaterial) -> etree._Element:
    return _build_v15_signed_operation_signature(operation, material)


def _build_v15_signed_operation_signature(operation: etree._Element, material: SatEfirmMaterial) -> etree._Element:
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


def _load_certificate(data: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(data) if data.startswith(b"-----BEGIN") else x509.load_der_x509_certificate(data)


def _envelope(ns: str) -> etree._Element:
    envelope = etree.Element(f"{{{SOAP11_NS}}}Envelope", nsmap={"soapenv": SOAP11_NS, "des": ns})
    etree.SubElement(envelope, f"{{{SOAP11_NS}}}Header")
    etree.SubElement(envelope, f"{{{SOAP11_NS}}}Body")
    return envelope


def _fmt(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
