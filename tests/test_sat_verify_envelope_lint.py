from __future__ import annotations

from pathlib import Path

from lxml import etree

from cfdi_vault.sat_live_smoke import DS_NS, SAT_REQUEST_NS, _build_verify_envelope
from cfdi_vault.sat_verify_envelope_lint import (
    EXPECTED_VERIFY_C14N_METHOD,
    EXPECTED_VERIFY_DIGEST_METHOD,
    EXPECTED_VERIFY_OPERATION,
    EXPECTED_VERIFY_SIGNATURE_METHOD,
    EXPECTED_VERIFY_TRANSFORMS,
    fingerprint_phpcfdi_verify_oracle,
    lint_verify_envelope,
)
from tests.test_sat_live_smoke import _material


def test_lint_verify_envelope_reports_redacted_structural_profile() -> None:
    envelope = _build_verify_envelope("SYN-REQ-123", "XAXX010101000", _material())

    result = lint_verify_envelope(envelope)

    assert result.all_checks_passed is True
    assert result.operation_name == EXPECTED_VERIFY_OPERATION
    assert result.operation_namespace == SAT_REQUEST_NS
    assert result.solicitud_attribute_names == ("IdSolicitud", "RfcSolicitante")
    assert result.solicitud_attribute_order == "IdSolicitud,RfcSolicitante"
    assert result.signature_location.endswith("/des:solicitud/ds:Signature")
    assert result.signature_placement == "inside_solicitud"
    assert result.signed_target == "operation_wrapper"
    assert result.key_info_shape == "ds-x509issuer-serial+x509certificate"
    assert result.reference_uri_shape == "empty"
    assert result.reference_transform_algorithms == EXPECTED_VERIFY_TRANSFORMS
    assert result.c14n_algorithm == EXPECTED_VERIFY_C14N_METHOD
    assert result.signed_node_path.endswith("/des:VerificaSolicitudDescarga")
    assert result.signature_algorithm == EXPECTED_VERIFY_SIGNATURE_METHOD
    assert result.digest_algorithms == (EXPECTED_VERIFY_DIGEST_METHOD,)
    assert result.x509_issuer_serial is True
    assert result.x509_certificate is True
    assert result.no_authorization_in_xml is True
    assert "SYN-REQ-123" not in repr(result)
    assert "XAXX010101000" not in repr(result)


def test_lint_verify_envelope_fails_when_signature_is_missing() -> None:
    root = etree.fromstring(_build_verify_envelope("SYN-REQ-123", "XAXX010101000", _material()))
    signature = root.find(f".//{{{DS_NS}}}Signature")
    assert signature is not None
    signature.getparent().remove(signature)
    envelope = etree.tostring(root, encoding="UTF-8", xml_declaration=True)

    result = lint_verify_envelope(envelope)

    assert result.all_checks_passed is False
    assert result.signature_inside_solicitud is False
    assert result.key_info_shape == "missing_key_info"


def test_lint_verify_envelope_rejects_previous_solicitud_signature_shape() -> None:
    envelope = _previous_solicitud_signed_verify_envelope("SYN-REQ-123", "XAXX010101000")

    result = lint_verify_envelope(envelope)

    assert result.all_checks_passed is False
    assert result.signature_inside_solicitud is True
    assert result.signed_target == "solicitud"
    assert result.c14n_algorithm == "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    assert "http://www.w3.org/2000/09/xmldsig#enveloped-signature" in result.reference_transform_algorithms
    assert result.x509_issuer_serial is False
    assert result.x509_certificate is True


def test_phpcfdi_verify_oracle_reads_only_structural_markers(tmp_path: Path) -> None:
    source = tmp_path / "FielRequestBuilder.php"
    source.write_text(
        """
        public function verify(string $requestId): Request {
            return $this->createRequest('VerificaSolicitudDescarga', [
                'IdSolicitud' => $requestId,
                'RfcSolicitante' => $this->fiel->rfc(),
            ])->sign($this->certificate);
        }
        """,
        encoding="utf-8",
    )

    oracle = fingerprint_phpcfdi_verify_oracle(source)

    assert oracle.available is True
    assert oracle.operation_name == EXPECTED_VERIFY_OPERATION
    assert oracle.solicitud_attribute_names == ("IdSolicitud", "RfcSolicitante")
    assert oracle.signature_location == "des:solicitud/ds:Signature"
    assert oracle.has_auth_wssecurity is False


def _previous_solicitud_signed_verify_envelope(request_id: str, requester_rfc: str) -> bytes:
    from cfdi_vault.sat_live_smoke import _operation_envelope, _signed_payload

    payload = _signed_payload("solicitud", {"IdSolicitud": request_id, "RfcSolicitante": requester_rfc.upper()}, _material())
    return _operation_envelope("VerificaSolicitudDescarga", payload)
