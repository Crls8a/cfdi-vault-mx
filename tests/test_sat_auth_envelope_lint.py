from lxml import etree

from cfdi_vault.sat_auth_constants import (
    AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION,
)
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
    assert result.expected_header_action_order == EXPECTED_HEADER_ACTION_ORDER
    assert result.soap_envelope is True
    assert result.action_header_present is False
    assert result.action_header_value is False
    assert result.action_header_namespace is False
    assert result.action_header_must_understand is False
    assert result.action_header_before_security is False
    assert result.action_header_order_ok is True
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


def test_lint_auth_envelope_accepts_explicit_header_order_variants_without_raw_xml() -> None:
    endpoint = "https://auth.example.test/Autenticacion/Autenticacion.svc"
    action_first = build_dummy_auth_envelope(
        endpoint, auth_envelope_variant=AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY
    )
    security_first = build_dummy_auth_envelope(
        endpoint, auth_envelope_variant=AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION
    )

    result_action_first = lint_auth_envelope(
        action_first, expected_header_action_order=AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY
    )
    result_security_first = lint_auth_envelope(
        security_first, expected_header_action_order=AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION
    )

    assert result_action_first.envelope_sha256 != result_security_first.envelope_sha256
    assert result_action_first.all_checks_passed is True
    assert result_security_first.all_checks_passed is True
    assert result_security_first.header_action_order == AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION
    assert result_security_first.expected_header_action_order == AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION
    assert result_security_first.action_header_before_security is False
    assert result_security_first.action_header_order_ok is True
    rendered = repr(result_security_first)
    assert "<soap" not in rendered
    assert "SignatureValue" not in rendered


def test_lint_auth_envelope_requires_wcf_action_header_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope(
        "https://auth.example.test/Autenticacion/Autenticacion.svc",
        auth_envelope_variant=AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    )
    root = etree.fromstring(envelope)
    action = root.find(".//{http://schemas.microsoft.com/ws/2005/05/addressing/none}Action")
    assert action is not None
    action.getparent().remove(action)

    result = lint_auth_envelope(
        etree.tostring(root, encoding="UTF-8", xml_declaration=True),
        expected_header_action_order=AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    )

    assert result.all_checks_passed is False
    assert result.action_header_present is False
    assert result.action_header_value is False
    assert result.action_header_namespace is False
    assert result.action_header_must_understand is False
    assert result.action_header_before_security is False
    assert result.header_action_order == "security_only"
    assert "<soap" not in repr(result)


def test_lint_auth_envelope_rejects_wrong_wcf_action_shape_without_raw_xml() -> None:
    envelope = build_dummy_auth_envelope(
        "https://auth.example.test/Autenticacion/Autenticacion.svc",
        auth_envelope_variant=AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    )
    root = etree.fromstring(envelope)
    header = root.find("{http://schemas.xmlsoap.org/soap/envelope/}Header")
    action = root.find(".//{http://schemas.microsoft.com/ws/2005/05/addressing/none}Action")
    security = root.find(
        ".//{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security"
    )
    assert header is not None
    assert action is not None
    assert security is not None
    action.text = "urn:wrong-action"
    action.attrib.pop("{http://schemas.xmlsoap.org/soap/envelope/}mustUnderstand")
    header.remove(action)
    header.insert(list(header).index(security) + 1, action)

    result = lint_auth_envelope(
        etree.tostring(root, encoding="UTF-8", xml_declaration=True),
        expected_header_action_order=AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    )

    assert result.all_checks_passed is False
    assert result.action_header_present is True
    assert result.action_header_value is False
    assert result.action_header_namespace is True
    assert result.action_header_must_understand is False
    assert result.action_header_before_security is False
    assert result.action_header_order_ok is False
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
    reference = root.find(
        ".//{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}SecurityTokenReference/{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Reference"
    )
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
    bst = root.find(
        ".//{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken"
    )
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
