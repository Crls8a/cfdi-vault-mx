from pathlib import Path

from typer.testing import CliRunner

from cfdi_vault.cli import app
from cfdi_vault.sat_auth_constants import AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY
from cfdi_vault.sat_auth_envelope_lint import build_dummy_auth_envelope
from cfdi_vault.sat_auth_oracle import diff_auth_oracle, fingerprint_auth_envelope, fingerprint_phpcfdi_oracle


def test_auth_envelope_fingerprint_is_redacted_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")

    result = fingerprint_auth_envelope(envelope)

    assert result.envelope_size > 500
    assert result.envelope_sha256
    assert result.has_header_action is False
    assert result.header_action_order == "security_only"
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


def test_auth_oracle_diff_reports_action_difference_without_raw_xml(tmp_path: Path) -> None:
    source = tmp_path / "FielRequestBuilder.php"
    source.write_text(
        """
        public function authorization() {
        <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
          <s:Header><o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1"><u:Timestamp u:Id="_0"/><o:BinarySecurityToken u:Id="$uuid" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">$certificate</o:BinarySecurityToken>$signatureData</o:Security></s:Header>
          <s:Body><Autentica xmlns="http://DescargaMasivaTerceros.gob.mx"/></s:Body>
        </s:Envelope>
        <o:SecurityTokenReference><o:Reference URI="#$uuid"/></o:SecurityTokenReference>
        public function query() {}
        <SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="$uri"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/></Reference></SignedInfo>
        createSignature($toDigestXml, '#_0');
        createXmlSecurityTokenId();
        """,
        encoding="utf-8",
    )
    local = fingerprint_auth_envelope(
        build_dummy_auth_envelope(
            "https://auth.example.test/Autenticacion/Autenticacion.svc",
            auth_envelope_variant=AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
        )
    )

    result = diff_auth_oracle(local, fingerprint_phpcfdi_oracle(source))

    action = next(item for item in result.items if item.field == "header_action_present")
    assert action.status == "different"
    assert action.likely_breaking is True
    assert result.recommended_fix == "add no-header-action auth envelope variant"
    rendered = repr(result)
    assert "<s:Envelope" not in rendered
    assert "BEGIN CERTIFICATE" not in rendered


def test_diff_auth_oracle_cli_requires_redacted_and_prints_safe_diff(tmp_path: Path) -> None:
    source = tmp_path / "FielRequestBuilder.php"
    source.write_text("public function authorization() { <s:Header><o:Security s:mustUnderstand=\"1\"><u:Timestamp u:Id=\"_0\"/><o:BinarySecurityToken ValueType=\"x\" EncodingType=\"y\"/></o:Security></s:Header><s:Body><Autentica xmlns=\"http://DescargaMasivaTerceros.gob.mx\"/></s:Body> } public function query() {} <CanonicalizationMethod Algorithm=\"c\"/><SignatureMethod Algorithm=\"s\"/><DigestMethod Algorithm=\"d\"/> createSignature($toDigestXml, '#_0'); SecurityTokenReference BinarySecurityToken createXmlSecurityTokenId();", encoding="utf-8")

    denied = CliRunner().invoke(app, ["sat", "diff-auth-oracle", "--oracle", "phpcfdi", "--fixture", "dummy"])
    result = CliRunner().invoke(app, ["sat", "diff-auth-oracle", "--oracle", "phpcfdi", "--fixture", "dummy", "--redacted", "--phpcfdi-builder-source", str(source)])

    assert denied.exit_code == 1
    assert result.exit_code == 0, result.output
    assert "mode=auth-oracle-diff" in result.output
    assert "diff field=header_action_present" in result.output
    assert "raw_xml_printed=no" in result.output
    assert "raw_xml_saved=no" in result.output
    assert "<s:Header>" not in result.output


def test_oracle_auth_fingerprint_cli_prints_safe_unavailable_status() -> None:
    result = CliRunner().invoke(app, ["sat", "oracle-auth-fingerprint", "--fixture", "dummy"])

    assert result.exit_code == 0, result.output
    assert "mode=auth-oracle-fingerprint" in result.output
    assert "local_available=yes" in result.output
    assert "local_has_header_action=no" in result.output
    assert "phpcfdi_available=no" in result.output
    assert "sat_real_executed=no" in result.output
    assert "raw_xml_printed=no" in result.output
    assert "<soap" not in result.output
    assert "BEGIN CERTIFICATE" not in result.output
