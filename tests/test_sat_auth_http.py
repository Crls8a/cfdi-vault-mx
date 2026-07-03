from __future__ import annotations

from cfdi_vault.sat_auth_contract import AuthWsdlContract
from cfdi_vault.sat_auth_http import (
    build_soap11_headers,
    build_soap12_headers,
    validate_auth_headers_for_contract,
)
from cfdi_vault.sat_live_smoke import AUTH_ACTION


def test_builds_soap11_headers_with_quoted_action() -> None:
    headers = build_soap11_headers(AUTH_ACTION, user_agent="cfdi-vault-test")

    assert headers == {
        "Content-Type": "text/xml;charset=UTF-8",
        "SOAPAction": f'"{AUTH_ACTION}"',
        "User-Agent": "cfdi-vault-test",
    }


def test_auth_headers_match_soap11_wsdl_contract() -> None:
    result = validate_auth_headers_for_contract(build_soap11_headers(AUTH_ACTION), _contract("1.1"), body=b"<synthetic/>")

    assert result.all_checks_passed is True
    assert result.media_type == "text/xml"
    assert result.charset == "UTF-8"
    assert result.soap_action == AUTH_ACTION
    assert result.soap_action_quoted is True
    assert result.body_size == len(b"<synthetic/>")


def test_auth_headers_fail_on_soap11_content_type_and_action_mismatch() -> None:
    headers = {
        "Content-Type": f'application/soap+xml;charset=UTF-8;action="{AUTH_ACTION}"',
        "SOAPAction": '"urn:wrong-action"',
    }

    result = validate_auth_headers_for_contract(headers, _contract("1.1"))

    assert result.all_checks_passed is False
    assert result.content_type_ok is False
    assert result.soap_action_ok is False
    assert result.soap_action == "mismatch"


def test_auth_headers_distinguish_soap12_binding_shape() -> None:
    soap11_result = validate_auth_headers_for_contract(build_soap11_headers(AUTH_ACTION), _contract("1.2"))
    soap12_result = validate_auth_headers_for_contract(build_soap12_headers(AUTH_ACTION), _contract("1.2"))

    assert soap11_result.all_checks_passed is False
    assert soap11_result.content_type_ok is False
    assert soap11_result.soap_action_format_ok is False
    assert soap12_result.all_checks_passed is True
    assert soap12_result.media_type == "application/soap+xml"


def test_auth_header_report_redacts_sensitive_header_values() -> None:
    headers = build_soap11_headers(AUTH_ACTION)
    headers["Authorization"] = "SYNTHETIC_VALUE_DO_NOT_PRINT"

    result = validate_auth_headers_for_contract(headers, _contract("1.1"))

    assert result.all_checks_passed is False
    assert result.sensitive_header_count == 1
    assert "SYNTHETIC_VALUE_DO_NOT_PRINT" not in repr(result)


def _contract(soap_version: str) -> AuthWsdlContract:
    return AuthWsdlContract(
        operation_name="Autentica",
        soap_action=AUTH_ACTION,
        soap_version=soap_version,
        binding_transport="http://schemas.xmlsoap.org/soap/http",
        target_namespace="http://DescargaMasivaTerceros.gob.mx",
        endpoint_scheme="https",
        endpoint_host="auth.example.test",
        endpoint_port=443,
        endpoint_path="/Autenticacion/Autenticacion.svc",
        expected_action_uri=AUTH_ACTION,
        wsdl_size=123,
    )
