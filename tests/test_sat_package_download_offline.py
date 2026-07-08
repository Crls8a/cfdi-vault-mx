from __future__ import annotations

import hashlib

import pytest

from cfdi_vault.domain import SatRequestState
from cfdi_vault.sat_auth_http import build_soap11_headers
from cfdi_vault.sat_download_envelope_lint import (
    EXPECTED_PACKAGE_DOWNLOAD_C14N_METHOD,
    EXPECTED_PACKAGE_DOWNLOAD_DIGEST_METHOD,
    EXPECTED_PACKAGE_DOWNLOAD_OPERATION,
    EXPECTED_PACKAGE_DOWNLOAD_SIGNATURE_METHOD,
    EXPECTED_PACKAGE_DOWNLOAD_TRANSFORMS,
    lint_package_download_envelope,
)
from cfdi_vault.sat_live_smoke import (
    DEFAULT_DOWNLOAD_ENDPOINT,
    DOWNLOAD_ACTION,
    DS_NS,
    SAT_REQUEST_NS,
    SatLiveMetadataSmokeAdapter,
    _build_package_download_envelope,
    _operation_envelope,
    _signed_payload,
)
from cfdi_vault.sat_package_download_offline import (
    PackageDownloadOfflineError,
    build_synthetic_package_download_response,
    build_synthetic_package_zip,
    evaluate_package_download_gate,
    parse_offline_package_download_response,
    require_package_download_gate,
)
from cfdi_vault.sat_transport import FakeSoapTransport, SoapTransportResponse
from cfdi_vault.secrets import DummySecretProvider
from tests.test_sat_live_smoke import _material, _profile, _soap


def test_package_download_envelope_matches_v15_contract_without_sensitive_repr() -> None:
    headers = _download_headers()
    envelope = _build_package_download_envelope("SYN-PKG-001", "XAXX010101000", _material())

    result = lint_package_download_envelope(envelope, headers=headers, endpoint=DEFAULT_DOWNLOAD_ENDPOINT)

    assert result.all_checks_passed is True
    assert result.endpoint_download is True
    assert result.soap_action == f'"{DOWNLOAD_ACTION}"'
    assert result.authorization_header_shape == "wrap-access-token"
    assert result.operation_name == EXPECTED_PACKAGE_DOWNLOAD_OPERATION
    assert result.operation_namespace == SAT_REQUEST_NS
    assert result.peticion_attribute_names == ("IdPaquete", "RfcSolicitante")
    assert result.peticion_attribute_order == "IdPaquete,RfcSolicitante"
    assert result.package_id_redacted == "SYN-...-001"
    assert result.signature_location.endswith("/des:peticionDescarga/ds:Signature")
    assert result.signature_placement == "inside_peticion_descarga"
    assert result.signed_target == "operation_wrapper"
    assert result.key_info_shape == "ds-x509issuer-serial+x509certificate"
    assert result.reference_uri_shape == "empty"
    assert result.reference_transform_algorithms == EXPECTED_PACKAGE_DOWNLOAD_TRANSFORMS
    assert result.c14n_algorithm == EXPECTED_PACKAGE_DOWNLOAD_C14N_METHOD
    assert result.signed_node_path.endswith("/des:Descargar")
    assert result.signature_algorithm == EXPECTED_PACKAGE_DOWNLOAD_SIGNATURE_METHOD
    assert result.digest_algorithms == (EXPECTED_PACKAGE_DOWNLOAD_DIGEST_METHOD,)
    assert result.x509_issuer_serial is True
    assert result.x509_certificate is True
    assert result.no_authorization_in_xml is True
    assert "SYN-PKG-001" not in repr(result)
    assert "XAXX010101000" not in repr(result)
    assert "SYNTHETIC_TOKEN" not in repr(result)


def test_package_download_lint_rejects_previous_peticion_signature_shape() -> None:
    payload = _signed_payload(
        "peticionDescarga",
        {"IdPaquete": "SYN-PKG-001", "RfcSolicitante": "XAXX010101000"},
        _material(),
    )
    envelope = _operation_envelope("Descargar", payload)

    result = lint_package_download_envelope(envelope, headers=_download_headers(), endpoint=DEFAULT_DOWNLOAD_ENDPOINT)

    assert result.all_checks_passed is False
    assert result.signature_inside_peticion is True
    assert result.signed_target == "peticion_descarga"
    assert result.c14n_algorithm == "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    assert "http://www.w3.org/2000/09/xmldsig#enveloped-signature" in result.reference_transform_algorithms
    assert result.x509_issuer_serial is False
    assert result.x509_certificate is True


def test_package_download_gate_requires_finished_state_and_package_ids() -> None:
    not_finished = evaluate_package_download_gate("2", ("SYN-PKG-001",))
    missing_ids = evaluate_package_download_gate(SatRequestState.FINISHED, ())
    ready = require_package_download_gate("3", ("SYN-PKG-001",))

    assert not_finished.allowed is False
    assert not_finished.reason == "estado-solicitud-not-finished"
    assert missing_ids.allowed is False
    assert missing_ids.reason == "ids-paquetes-missing"
    assert ready.allowed is True
    assert ready.reason == "ready"
    assert ready.package_count == 1
    with pytest.raises(PackageDownloadOfflineError, match="estado-solicitud-not-finished"):
        require_package_download_gate("accepted", ("SYN-PKG-001",))


def test_offline_response_parser_decodes_synthetic_paquete_zip_without_xml_or_pdf() -> None:
    package = build_synthetic_package_zip()
    response = build_synthetic_package_download_response(package)

    result = parse_offline_package_download_response(response, package_id="SYN-PKG-001")

    assert result.package_id_redacted == "SYN-...-001"
    assert result.sat_code == "5000"
    assert result.action == "finished"
    assert result.content_length == len(package)
    assert result.content_sha256 == hashlib.sha256(package).hexdigest()
    assert result.zip_valid is True
    assert result.zip_entry_count == 2
    assert result.txt_entry_count == 2
    assert result.xml_entry_count == 0
    assert result.pdf_entry_count == 0
    assert "SYN-PKG-001" not in repr(result)


def test_synthetic_package_zip_rejects_xml_and_pdf_fixtures() -> None:
    with pytest.raises(PackageDownloadOfflineError, match="must-not-contain-xml-or-pdf"):
        build_synthetic_package_zip({"synthetic.xml": b"<synthetic />"})
    with pytest.raises(PackageDownloadOfflineError, match="must-not-contain-xml-or-pdf"):
        build_synthetic_package_zip({"synthetic.pdf": b"synthetic non-fiscal bytes"})


def test_package_download_adapter_sends_split_timeouts_without_request_or_verify(tmp_path) -> None:
    package = build_synthetic_package_zip()
    responses = [
        SoapTransportResponse(200, body=_soap("<sat:AutenticaResult>SYNTHETIC_TOKEN</sat:AutenticaResult>")),
        SoapTransportResponse(200, body=build_synthetic_package_download_response(package)),
    ]
    transport = FakeSoapTransport(responses)

    result = SatLiveMetadataSmokeAdapter(
        profile=_profile(tmp_path),
        provider=DummySecretProvider(),
        transport=transport,
        material=_material(),
        timeout_seconds=180,
        connect_timeout_seconds=15,
        read_timeout_seconds=180,
    ).download_package("SYN-PKG-001")

    assert result.content == package
    assert [request.endpoint for request in transport.requests] == [
        "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc",
        DEFAULT_DOWNLOAD_ENDPOINT,
    ]
    download_request = transport.requests[1]
    assert download_request.headers["SOAPAction"] == f'"{DOWNLOAD_ACTION}"'
    assert download_request.timeout_seconds == 180
    assert download_request.connect_timeout_seconds == 15
    assert download_request.read_timeout_seconds == 180
    lint = lint_package_download_envelope(
        download_request.body,
        headers=dict(download_request.headers),
        endpoint=download_request.endpoint,
    )
    assert lint.all_checks_passed is True
    assert b"SolicitaDescarga" not in download_request.body
    assert b"VerificaSolicitudDescarga" not in download_request.body
    assert b"Descargar" in download_request.body
    assert "SYN-PKG-001" not in repr(download_request)


def _download_headers() -> dict[str, str]:
    headers = build_soap11_headers(DOWNLOAD_ACTION)
    headers["Authorization"] = 'WRAP access_token="SYNTHETIC_TOKEN"'
    return headers
