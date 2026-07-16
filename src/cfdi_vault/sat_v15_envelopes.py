"""Internal SAT v1.5 authentication-envelope construction primitives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

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
from cfdi_vault.sat_v15_contract import AUTH_ACTION

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


def _envelope(ns: str) -> etree._Element:
    envelope = etree.Element(f"{{{SOAP11_NS}}}Envelope", nsmap={"soapenv": SOAP11_NS, "des": ns})
    etree.SubElement(envelope, f"{{{SOAP11_NS}}}Header")
    etree.SubElement(envelope, f"{{{SOAP11_NS}}}Body")
    return envelope


def _fmt(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
