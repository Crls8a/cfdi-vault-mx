from __future__ import annotations

from pathlib import Path

from lxml import etree

from cfdi_vault.sat_live_smoke import DS_NS, SAT_REQUEST_NS, _build_verify_envelope
from cfdi_vault.sat_verify_envelope_lint import (
    EXPECTED_VERIFY_DIGEST_METHOD,
    EXPECTED_VERIFY_OPERATION,
    EXPECTED_VERIFY_SIGNATURE_METHOD,
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
    assert result.key_info_shape == "ds-x509data"
    assert result.reference_uri_shape == "empty"
    assert result.signed_node_path.endswith("/des:VerificaSolicitudDescarga/des:solicitud")
    assert result.signature_algorithm == EXPECTED_VERIFY_SIGNATURE_METHOD
    assert result.digest_algorithms == (EXPECTED_VERIFY_DIGEST_METHOD,)
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
