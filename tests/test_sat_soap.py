from __future__ import annotations

from datetime import datetime, timezone
from xml.etree import ElementTree as ET

import pytest

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_soap import (
    SAT_MASS_DOWNLOAD_NS,
    SOAP_ENVELOPE_NS,
    SatPackageDownloadEnvelopeInput,
    SatVerificationEnvelopeInput,
    build_authentication_envelope,
    build_download_request_envelope,
    build_package_download_envelope,
    build_verification_envelope,
)

NS = {"soap": SOAP_ENVELOPE_NS, "sat": SAT_MASS_DOWNLOAD_NS}
SAFE_UUID = "ABCDEF12-0000-4000-8000-000000000001"


class FakeSigner:
    def __init__(self) -> None:
        self.payloads: list[bytes] = []

    def sign(self, xml_payload: bytes) -> bytes:
        self.payloads.append(xml_payload)
        payload = ET.fromstring(xml_payload)
        ET.SubElement(payload, f"{{{SAT_MASS_DOWNLOAD_NS}}}Signature").text = "SYNTHETIC_SIGNATURE"
        return ET.tostring(payload, encoding="utf-8")


def _root(xml: bytes) -> ET.Element:
    return ET.fromstring(xml)


def _required(parent: ET.Element, path: str) -> ET.Element:
    element = parent.find(path, NS)
    assert element is not None
    return element


def _query() -> DownloadQuery:
    return DownloadQuery(
        tenant_id="default",
        requester_rfc="XAXX010101000",
        direction=DownloadDirection.RECEIVED,
        request_type=RequestType.CFDI,
        period=DateTimePeriod(
            start=datetime(2024, 1, 1, 8, 30, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, 18, 45, tzinfo=timezone.utc),
        ),
        issuer_rfc="AAA010101AAA",
        receiver_rfcs=("BBB010101BBB",),
        document_status="Vigente",
        document_type="I",
        complement="SYNTHETIC_COMPLEMENT",
    )


def test_authentication_envelope_uses_soap_and_sat_namespaces_with_placeholder_only() -> None:
    xml = build_authentication_envelope("SYNTHETIC_AUTHORIZATION")
    root = _root(xml)

    assert root.tag == f"{{{SOAP_ENVELOPE_NS}}}Envelope"
    assert _required(root, "soap:Header").tag == f"{{{SOAP_ENVELOPE_NS}}}Header"
    placeholder = _required(root, "soap:Body/sat:Autentica/sat:placeholder")
    assert placeholder.text == "SYNTHETIC_AUTHORIZATION"
    assert b"clouda.sat.gob.mx" not in xml
    assert b"Authorization: WRAP" not in xml


def test_download_request_envelope_maps_synthetic_received_query() -> None:
    root = _root(build_download_request_envelope(_query()))
    request = _required(root, "soap:Body/sat:SolicitaDescarga/sat:solicitud")
    receiver = _required(request, "sat:RfcReceptores/sat:RfcReceptor")

    assert request.attrib == {
        "RfcSolicitante": "XAXX010101000",
        "TipoSolicitud": "CFDI",
        "FechaInicial": "2024-01-01T08:30:00Z",
        "FechaFinal": "2024-01-31T18:45:00Z",
        "RfcReceptor": "XAXX010101000",
        "RfcEmisor": "AAA010101AAA",
        "EstadoComprobante": "Vigente",
        "TipoComprobante": "I",
        "Complemento": "SYNTHETIC_COMPLEMENT",
    }
    assert receiver.text == "BBB010101BBB"


def test_download_request_envelope_maps_folio_query_without_period() -> None:
    query = DownloadQuery(
        tenant_id="default",
        requester_rfc="XAXX010101000",
        direction=DownloadDirection.FOLIO,
        request_type=RequestType.METADATA,
        uuid=SAFE_UUID,
    )

    request = _required(_root(build_download_request_envelope(query)), "soap:Body/sat:SolicitaDescarga/sat:solicitud")

    assert request.attrib["Folio"] == SAFE_UUID
    assert request.attrib["TipoSolicitud"] == "Metadata"
    assert "FechaInicial" not in request.attrib


def test_download_request_envelope_rejects_invalid_query() -> None:
    query = DownloadQuery(
        tenant_id="default",
        requester_rfc="XAXX010101000",
        direction=DownloadDirection.RECEIVED,
        request_type=RequestType.CFDI,
    )

    with pytest.raises(ValueError, match="period is required"):
        build_download_request_envelope(query)


def test_fake_signer_is_injected_without_resolving_anything_else() -> None:
    signer = FakeSigner()

    root = _root(build_verification_envelope(SatVerificationEnvelopeInput("SYN-REQ-001", "XAXX010101000"), signer))
    signature = _required(root, "soap:Body/sat:VerificaSolicitudDescarga/sat:solicitud/sat:Signature")

    assert signature.text == "SYNTHETIC_SIGNATURE"
    assert len(signer.payloads) == 1
    assert b"SYN-REQ-001" in signer.payloads[0]


def test_invalid_verification_and_package_inputs_are_rejected() -> None:
    with pytest.raises(ValueError, match="request_id is required"):
        build_verification_envelope(SatVerificationEnvelopeInput("", "XAXX010101000"))
    with pytest.raises(ValueError, match="package_id is required"):
        build_package_download_envelope(SatPackageDownloadEnvelopeInput("", "XAXX010101000"))


def test_signer_returning_invalid_xml_is_rejected() -> None:
    class BrokenSigner:
        def sign(self, xml_payload: bytes) -> bytes:
            assert b"SYN-REQ-001" in xml_payload
            return b"<broken>"

    with pytest.raises(ValueError, match="signer returned invalid XML"):
        build_verification_envelope(
            SatVerificationEnvelopeInput("SYN-REQ-001", "XAXX010101000"),
            BrokenSigner(),
        )


def test_verification_and_package_download_envelopes_use_synthetic_ids() -> None:
    verification = _root(build_verification_envelope(SatVerificationEnvelopeInput("SYN-REQ-001", "XAXX010101000")))
    package = _root(build_package_download_envelope(SatPackageDownloadEnvelopeInput("SYN-PKG-001", "XAXX010101000")))

    verification_request = _required(verification, "soap:Body/sat:VerificaSolicitudDescarga/sat:solicitud")
    package_request = _required(package, "soap:Body/sat:Descargar/sat:peticionDescarga")

    assert verification_request.attrib == {"IdSolicitud": "SYN-REQ-001", "RfcSolicitante": "XAXX010101000"}
    assert package_request.attrib == {"IdPaquete": "SYN-PKG-001", "RfcSolicitante": "XAXX010101000"}
