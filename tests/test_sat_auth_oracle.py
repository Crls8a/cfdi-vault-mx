from pathlib import Path

from typer.testing import CliRunner

from cfdi_vault.cli import app
from cfdi_vault.sat_auth_envelope_lint import build_dummy_auth_envelope
from cfdi_vault.sat_auth_oracle import fingerprint_auth_envelope, fingerprint_phpcfdi_oracle


def test_auth_envelope_fingerprint_is_redacted_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")

    result = fingerprint_auth_envelope(envelope)

    assert result.envelope_size > 500
    assert result.envelope_sha256
    assert result.has_header_action is True
    assert result.header_action_order == "action_before_security"
    assert result.sec_ref_shape == "wsse-reference-to-bst"
    assert result.bst_length > 0
    assert result.signature_value_length > 0
    assert result.digest_value_lengths
    rendered = repr(result)
    assert "<soap" not in rendered
    assert "BEGIN CERTIFICATE" not in rendered


def test_phpcfdi_oracle_reports_clear_steps_when_source_is_missing() -> None:
    result = fingerprint_phpcfdi_oracle()

    assert result.available is False
    assert result.reason == "phpcfdi-builder-source-not-provided"
    assert result.setup_steps


def test_phpcfdi_oracle_reads_external_builder_source_without_vendor_repo(tmp_path: Path) -> None:
    source = tmp_path / "FielRequestBuilder.php"
    source.write_text(
        """
        <s:Header><wsse:Security s:mustUnderstand="1">...</wsse:Security></s:Header>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <Reference URI="$uri"><DigestValue>$digested</DigestValue></Reference>
        <o:BinarySecurityToken u:Id="$uuid">$certificate</o:BinarySecurityToken>
        <o:SecurityTokenReference><o:Reference URI="#$uuid"/></o:SecurityTokenReference>
        SolicitaDescargaEmitidos SolicitaDescargaRecibidos SolicitaDescargaFolio
        """,
        encoding="utf-8",
    )

    result = fingerprint_phpcfdi_oracle(source)

    assert result.available is True
    assert result.has_header_action is False
    assert result.header_action_order == "security_only"
    assert result.signature_algorithm == "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    assert result.digest_algorithm == "http://www.w3.org/2000/09/xmldsig#sha1"
    assert result.reference_uri_redacted == "#<id>"
    assert result.sec_ref_shape == "wsse-reference-to-bst"
    assert result.request_operations == ("SolicitaDescargaEmitidos", "SolicitaDescargaRecibidos", "SolicitaDescargaFolio")


def test_oracle_auth_fingerprint_cli_prints_safe_unavailable_status() -> None:
    result = CliRunner().invoke(app, ["sat", "oracle-auth-fingerprint", "--fixture", "dummy"])

    assert result.exit_code == 0, result.output
    assert "mode=auth-oracle-fingerprint" in result.output
    assert "local_available=yes" in result.output
    assert "local_has_header_action=yes" in result.output
    assert "phpcfdi_available=no" in result.output
    assert "sat_real_executed=no" in result.output
    assert "raw_xml_printed=no" in result.output
    assert "<soap" not in result.output
    assert "BEGIN CERTIFICATE" not in result.output
