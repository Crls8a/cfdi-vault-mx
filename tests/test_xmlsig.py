from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree

from cfdi_vault.xmlsig import (
    OfflineXmlSignatureVerifier,
    OfflineXmlSigner,
    XmlSigningMaterial,
    sign_xml,
    verify_xml_signature,
)


def test_sign_xml_bytes_round_trips_with_generated_material() -> None:
    material = _generate_dummy_material()
    xml_payload = _sample_xml()

    signed_xml = sign_xml(xml_payload, material)

    assert signed_xml != xml_payload
    assert b"<ds:Signature" in signed_xml
    assert b"X509Certificate" not in signed_xml
    assert verify_xml_signature(signed_xml, material.certificate) is True


def test_verify_xml_signature_rejects_tampered_xml() -> None:
    material = _generate_dummy_material()
    signed_xml = sign_xml(_sample_xml(), material)

    tampered_xml = signed_xml.replace(b"<value>42</value>", b"<value>43</value>")

    assert tampered_xml != signed_xml
    assert verify_xml_signature(tampered_xml, material.certificate) is False


def test_verify_xml_signature_rejects_wrapped_signed_xml() -> None:
    material = _generate_dummy_material()
    signed_xml = sign_xml(_sample_xml(), material)
    signed_document = etree.fromstring(signed_xml)
    wrapper = etree.Element("root")
    evil_document = etree.SubElement(wrapper, "document", Id="evil")
    etree.SubElement(evil_document, "value").text = "43"
    wrapper.append(signed_document)
    wrapped_xml = etree.tostring(wrapper, encoding="UTF-8", xml_declaration=True)

    assert verify_xml_signature(wrapped_xml, material.certificate) is False


def test_verify_xml_signature_rejects_malformed_xml() -> None:
    material = _generate_dummy_material()

    assert verify_xml_signature(b"<document><value>42</document>", material.certificate) is False


def test_signing_boundary_repr_redacts_key_and_certificate_material() -> None:
    material = _generate_dummy_material()
    private_key_text = material.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    certificate_text = material.certificate.public_bytes(serialization.Encoding.PEM).decode(
        "ascii"
    )

    reprs = (
        repr(material),
        repr(OfflineXmlSigner(material)),
        repr(OfflineXmlSignatureVerifier(material.certificate)),
    )

    for rendered in reprs:
        assert private_key_text not in rendered
        assert certificate_text not in rendered
        assert "<redacted>" in rendered


def _sample_xml() -> bytes:
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<document Id="synthetic-document">
  <value>42</value>
</document>
"""


def _generate_dummy_material() -> XmlSigningMaterial:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic XMLDSig Test"),
        ]
    )
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return XmlSigningMaterial(private_key=private_key, certificate=certificate)
