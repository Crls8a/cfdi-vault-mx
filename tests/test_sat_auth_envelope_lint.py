from lxml import etree
from typer.testing import CliRunner

from cfdi_vault.cli import app
from cfdi_vault.sat_auth_envelope_lint import build_dummy_auth_envelope, lint_auth_envelope


def test_lint_auth_envelope_reports_structure_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")

    result = lint_auth_envelope(envelope)

    assert result.all_checks_passed is True
    assert result.soap_envelope is True
    assert result.ws_security is True
    assert result.bst_der is True
    assert result.signature is True
    assert result.reference_count >= 1
    assert result.references_resolve is True
    rendered = repr(result)
    assert "<soap" not in rendered
    assert "BEGIN CERTIFICATE" not in rendered


def test_lint_auth_envelope_detects_broken_reference_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")
    root = etree.fromstring(envelope)
    reference = root.find(".//{http://www.w3.org/2000/09/xmldsig#}Reference")
    assert reference is not None
    reference.set("URI", "#missing-id")

    result = lint_auth_envelope(etree.tostring(root, encoding="UTF-8", xml_declaration=True))

    assert result.all_checks_passed is False
    assert result.references_resolve is False


def test_lint_auth_envelope_cli_prints_redacted_checks() -> None:
    result = CliRunner().invoke(app, ["sat", "lint-auth-envelope", "--fixture", "dummy"])

    assert result.exit_code == 0, result.output
    assert "mode=auth-envelope-lint" in result.output
    assert "all_checks_passed=yes" in result.output
    assert "check_ws_security=yes" in result.output
    assert "raw_xml_printed=no" in result.output
    assert "certificate_printed=no" in result.output
    assert "signature_value_printed=no" in result.output
    assert "<soap" not in result.output
    assert "BEGIN CERTIFICATE" not in result.output
