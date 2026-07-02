"""Offline XMLDSig signing and verification boundary.

This module is intentionally local-only: it performs XMLDSig operations over
bytes already held in memory and does not know about SAT transport, storage, or
credential lookup.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from lxml import etree
from signxml import InvalidCertificate, InvalidDigest, InvalidInput, InvalidSignature
from signxml import XMLSigner, XMLVerifier, methods
from signxml.algorithms import CanonicalizationMethod, DigestAlgorithm, SignatureMethod


_XML_PARSER = etree.XMLParser(resolve_entities=False, no_network=True)


@dataclass(frozen=True, repr=False)
class XmlSigningMaterial:
    """In-memory key and certificate material for local XMLDSig work.

    The signer uses the private key only. The paired certificate is kept for
    local verification without embedding certificate material in the returned
    signed XML bytes.
    """

    private_key: Any
    certificate: Any

    def __repr__(self) -> str:
        return "XmlSigningMaterial(private_key=<redacted>, certificate=<redacted>)"


class OfflineXmlSigner:
    """Signs XML bytes with XMLDSig without exposing key material in reprs."""

    def __init__(self, material: XmlSigningMaterial) -> None:
        self._material = material

    def __repr__(self) -> str:
        return "OfflineXmlSigner(material=<redacted>)"

    def sign(self, xml_payload: bytes) -> bytes:
        """Return an enveloped XMLDSig document for the given XML bytes."""

        document = _parse_xml(xml_payload)
        signed = XMLSigner(
            method=methods.enveloped,
            signature_algorithm=SignatureMethod.RSA_SHA256,
            digest_algorithm=DigestAlgorithm.SHA256,
            c14n_algorithm=CanonicalizationMethod.CANONICAL_XML_1_1,
        ).sign(
            document,
            key=self._material.private_key,
        )
        return etree.tostring(signed, encoding="UTF-8", xml_declaration=True)


class OfflineXmlSignatureVerifier:
    """Verifies XMLDSig signatures locally against a supplied certificate."""

    def __init__(self, certificate: Any) -> None:
        self._certificate = certificate

    def __repr__(self) -> str:
        return "OfflineXmlSignatureVerifier(certificate=<redacted>)"

    def verify(self, signed_xml: bytes) -> bool:
        """Return whether the signed XML is valid for this verifier certificate."""

        try:
            document = _parse_xml(signed_xml)
            result = XMLVerifier().verify(
                document,
                x509_cert=self._certificate,
                validate_schema=False,
            )
        except (
            InvalidCertificate,
            InvalidDigest,
            InvalidInput,
            InvalidSignature,
            etree.XMLSyntaxError,
        ):
            return False
        return _signed_payload_matches_document_root(document, result.signed_xml)


def sign_xml(xml_payload: bytes, material: XmlSigningMaterial) -> bytes:
    """Sign XML bytes with the offline signer boundary."""

    return OfflineXmlSigner(material).sign(xml_payload)


def verify_xml_signature(signed_xml: bytes, certificate: Any) -> bool:
    """Verify XMLDSig bytes with the offline verifier boundary."""

    return OfflineXmlSignatureVerifier(certificate).verify(signed_xml)


def _parse_xml(xml_payload: bytes) -> etree._Element:
    if not isinstance(xml_payload, bytes):
        raise TypeError("xml_payload must be bytes")
    return etree.fromstring(xml_payload, parser=_XML_PARSER)


def _signed_payload_matches_document_root(document: etree._Element, signed_xml: etree._Element) -> bool:
    """Reject XML wrapping by requiring the signed payload to be the document root."""

    root_without_signature = copy.deepcopy(document)
    for signature in root_without_signature.xpath(
        ".//*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#']"
    ):
        parent = signature.getparent()
        if parent is not None:
            parent.remove(signature)
    return _canonical_xml(root_without_signature) == _canonical_xml(signed_xml)


def _canonical_xml(element: etree._Element) -> bytes:
    return etree.tostring(element, method="c14n", exclusive=False, with_comments=False)
