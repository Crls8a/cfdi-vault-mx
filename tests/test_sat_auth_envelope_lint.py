from lxml import etree
from typer.testing import CliRunner

from cfdi_vault import cli as cli_module
from cfdi_vault.cli import app
from cfdi_vault.sat_auth_envelope_lint import (
    EXPECTED_C14N_METHOD,
    EXPECTED_DIGEST_METHOD,
    EXPECTED_HEADER_ACTION_ORDER,
    EXPECTED_SIGNATURE_METHOD,
    EXPECTED_XMLSIG_PROFILE,
    build_dummy_auth_envelope,
    lint_auth_envelope,
)


def test_lint_auth_envelope_reports_structure_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")

    result = lint_auth_envelope(envelope)

    assert result.all_checks_passed is True
    assert result.xmlsig_profile == EXPECTED_XMLSIG_PROFILE
    assert result.c14n_algorithm == EXPECTED_C14N_METHOD
    assert result.signature_algorithm == EXPECTED_SIGNATURE_METHOD
    assert result.digest_algorithms == (EXPECTED_DIGEST_METHOD,)
    assert result.reference_uris_redacted == ("#<id>",)
    assert result.reference_transform_algorithms == (EXPECTED_C14N_METHOD,)
    assert result.key_info_reference_uri_redacted == "#<id>"
    assert result.header_action_order == EXPECTED_HEADER_ACTION_ORDER
    assert result.soap_envelope is True
    assert result.action_header_present is True
    assert result.action_header_value is True
    assert result.action_header_namespace is True
    assert result.action_header_must_understand is True
    assert result.action_header_before_security is True
    assert result.security_must_understand is True
    assert result.ws_security is True
    assert result.bst_der is True
    assert result.bst_id_present is True
    assert result.bst_no_pem is True
    assert result.bst_value_type is True
    assert result.bst_encoding_type is True
    assert result.timestamp_id_present is True
    assert result.timestamp_created_utc_z is True
    assert result.timestamp_expires_utc_z is True
    assert result.timestamp_window_seconds == 300
    assert result.signature is True
    assert result.c14n_method is True
    assert result.signature_method is True
    assert result.digest_method is True
    assert result.reference_transforms is True
    assert result.reference_count >= 1
    assert result.reference_uris is True
    assert result.references_resolve is True
    assert result.references_use_wsu_id is True
    assert result.signed_nodes_exist is True
    assert result.local_signature_verify is True
    assert result.sec_ref_uri is True
    assert result.sec_ref_value_type is True
    assert result.sec_ref_resolves_bst is True
    rendered = repr(result)
    assert "<soap" not in rendered
    assert "BEGIN CERTIFICATE" not in rendered
    assert "SignatureValue" not in rendered


def test_lint_auth_envelope_requires_wcf_action_header_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")
    root = etree.fromstring(envelope)
    action = root.find(".//{http://schemas.microsoft.com/ws/2005/05/addressing/none}Action")
    assert action is not None
    action.getparent().remove(action)

    result = lint_auth_envelope(etree.tostring(root, encoding="UTF-8", xml_declaration=True))

    assert result.all_checks_passed is False
    assert result.action_header_present is False
    assert result.action_header_value is False
    assert result.action_header_namespace is False
    assert result.action_header_must_understand is False
    assert result.action_header_before_security is False
    assert result.header_action_order == "missing_action_or_security"
    assert "<soap" not in repr(result)


def test_lint_auth_envelope_rejects_wrong_wcf_action_shape_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")
    root = etree.fromstring(envelope)
    header = root.find("{http://schemas.xmlsoap.org/soap/envelope/}Header")
    action = root.find(".//{http://schemas.microsoft.com/ws/2005/05/addressing/none}Action")
    security = root.find(".//{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security")
    assert header is not None
    assert action is not None
    assert security is not None
    action.text = "urn:wrong-action"
    action.attrib.pop("{http://schemas.xmlsoap.org/soap/envelope/}mustUnderstand")
    header.remove(action)
    header.insert(list(header).index(security) + 1, action)

    result = lint_auth_envelope(etree.tostring(root, encoding="UTF-8", xml_declaration=True))

    assert result.all_checks_passed is False
    assert result.action_header_present is True
    assert result.action_header_value is False
    assert result.action_header_namespace is True
    assert result.action_header_must_understand is False
    assert result.action_header_before_security is False
    assert result.header_action_order == "security_before_action"


def test_lint_auth_envelope_detects_broken_reference_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")
    root = etree.fromstring(envelope)
    reference = root.find(".//{http://www.w3.org/2000/09/xmldsig#}Reference")
    assert reference is not None
    reference.set("URI", "#missing-id")

    result = lint_auth_envelope(etree.tostring(root, encoding="UTF-8", xml_declaration=True))

    assert result.all_checks_passed is False
    assert result.references_resolve is False
    assert result.references_use_wsu_id is False
    assert result.signed_nodes_exist is False
    assert result.local_signature_verify is False


def test_lint_auth_envelope_detects_broken_bst_reference_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")
    root = etree.fromstring(envelope)
    reference = root.find(".//{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}SecurityTokenReference/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Reference")
    assert reference is not None
    reference.set("URI", "#missing-bst")
    reference.set("ValueType", "urn:wrong-value-type")

    result = lint_auth_envelope(etree.tostring(root, encoding="UTF-8", xml_declaration=True))

    assert result.all_checks_passed is False
    assert result.sec_ref_uri is True
    assert result.sec_ref_value_type is False
    assert result.sec_ref_resolves_bst is False
    assert result.local_signature_verify is True


def test_lint_auth_envelope_detects_wrong_signature_methods_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")
    root = etree.fromstring(envelope)
    c14n = root.find(".//{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod")
    signature = root.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureMethod")
    digest = root.find(".//{http://www.w3.org/2000/09/xmldsig#}DigestMethod")
    assert c14n is not None
    assert signature is not None
    assert digest is not None
    c14n.set("Algorithm", "urn:wrong-c14n")
    signature.set("Algorithm", "urn:wrong-signature")
    digest.set("Algorithm", "urn:wrong-digest")

    result = lint_auth_envelope(etree.tostring(root, encoding="UTF-8", xml_declaration=True))

    assert result.all_checks_passed is False
    assert result.c14n_method is False
    assert result.signature_method is False
    assert result.digest_method is False
    assert result.signature_algorithm == "urn:wrong-signature"
    assert result.digest_algorithms == ("urn:wrong-digest",)
    assert result.local_signature_verify is False


def test_lint_auth_envelope_detects_pem_certificate_marker_without_printing_it() -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")
    root = etree.fromstring(envelope)
    bst = root.find(".//{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken")
    assert bst is not None
    bst.text = "-----BEGIN " + "CERTIFICATE-----"

    result = lint_auth_envelope(etree.tostring(root, encoding="UTF-8", xml_declaration=True))

    assert result.all_checks_passed is False
    assert result.bst_der is False
    assert result.bst_no_pem is False
    assert result.bst_value_type is True
    assert result.bst_encoding_type is True
    assert result.local_signature_verify is False
    assert "-----BEGIN" not in repr(result)


def test_lint_auth_envelope_cli_prints_redacted_checks() -> None:
    result = CliRunner().invoke(app, ["sat", "lint-auth-envelope", "--fixture", "dummy"])

    assert result.exit_code == 0, result.output
    assert "mode=auth-envelope-lint" in result.output
    assert "all_checks_passed=yes" in result.output
    assert "request_body_bytes_len=" in result.output
    assert "check_ws_security=yes" in result.output
    assert "check_c14n_method=yes" in result.output
    assert "check_signature_method=yes" in result.output
    assert "check_digest_method=yes" in result.output
    assert f"xmlsig_profile={EXPECTED_XMLSIG_PROFILE}" in result.output
    assert f"c14n_algorithm={EXPECTED_C14N_METHOD}" in result.output
    assert f"signature_algorithm={EXPECTED_SIGNATURE_METHOD}" in result.output
    assert f"digest_algorithms={EXPECTED_DIGEST_METHOD}" in result.output
    assert "reference_uris=#<id>" in result.output
    assert f"reference_transform_algorithms={EXPECTED_C14N_METHOD}" in result.output
    assert "key_info_reference_uri=#<id>" in result.output
    assert f"header_action_order={EXPECTED_HEADER_ACTION_ORDER}" in result.output
    assert "timestamp_window_seconds=300" in result.output
    assert "check_action_header_present=yes" in result.output
    assert "check_action_header_value=yes" in result.output
    assert "check_action_header_namespace=yes" in result.output
    assert "check_action_header_must_understand=yes" in result.output
    assert "check_action_header_before_security=yes" in result.output
    assert "check_security_must_understand=yes" in result.output
    assert "check_timestamp_id_present=yes" in result.output
    assert "check_timestamp_created_utc_z=yes" in result.output
    assert "check_timestamp_expires_utc_z=yes" in result.output
    assert "check_bst_id_present=yes" in result.output
    assert "check_bst_value_type=yes" in result.output
    assert "check_bst_encoding_type=yes" in result.output
    assert "check_sec_ref_uri=yes" in result.output
    assert "check_sec_ref_value_type=yes" in result.output
    assert "check_sec_ref_resolves_bst=yes" in result.output
    assert "check_local_signature_verify=yes" in result.output
    assert "raw_xml_printed=no" in result.output
    assert "certificate_printed=no" in result.output
    assert "signature_value_printed=no" in result.output
    assert "<soap" not in result.output
    assert "BEGIN CERTIFICATE" not in result.output


def test_lint_auth_envelope_profile_requires_redacted(monkeypatch) -> None:
    called = False

    def fail_if_called(_profile: str) -> bytes:
        nonlocal called
        called = True
        return b"SHOULD_NOT_HAPPEN"

    monkeypatch.setattr(cli_module, "_build_profile_auth_envelope", fail_if_called)

    result = CliRunner().invoke(app, ["sat", "lint-auth-envelope", "--profile", "dummy-profile"])

    assert result.exit_code == 1
    assert "reason=redacted-required-for-profile" in result.output
    assert called is False


def test_lint_auth_envelope_profile_redacted_prints_safe_checks(monkeypatch) -> None:
    envelope = build_dummy_auth_envelope("https://auth.example.test/Autenticacion/Autenticacion.svc")
    monkeypatch.setattr(cli_module, "_build_profile_auth_envelope", lambda _profile: envelope)

    result = CliRunner().invoke(app, ["sat", "lint-auth-envelope", "--profile", "dummy-profile", "--redacted"])

    assert result.exit_code == 0, result.output
    assert "fixture=profile-redacted" in result.output
    assert "all_checks_passed=yes" in result.output
    assert "request_body_bytes_len=" in result.output
    assert "<soap" not in result.output
    assert "BEGIN CERTIFICATE" not in result.output
    assert "SignatureValue" not in result.output
