"""SAT auth SOAP HTTP header helpers and offline parity checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from cfdi_vault.sat_auth_contract import AuthWsdlContract

SOAP11_CONTENT_TYPE = "text/xml; charset=utf-8"
SOAP12_CONTENT_TYPE = "application/soap+xml; charset=utf-8"
SENSITIVE_HEADER_NAMES = frozenset({"authorization", "cookie", "proxy-authorization"})


@dataclass(frozen=True)
class AuthHeaderParityResult:
    soap_version: str
    media_type: str
    charset: str
    soap_action: str
    soap_action_quoted: bool
    content_type_ok: bool
    charset_ok: bool
    soap_action_ok: bool
    soap_action_format_ok: bool
    user_agent_present: bool
    accept_encoding_present: bool
    content_length_present: bool
    body_size: int | None
    sensitive_header_count: int
    all_checks_passed: bool


def build_soap11_headers(action: str, *, user_agent: str | None = None) -> dict[str, str]:
    """Build SOAP 1.1 headers with quoted SOAPAction."""

    normalized_action = action.strip()
    if not normalized_action:
        raise ValueError("soap-action-required")
    headers = {
        "Content-Type": SOAP11_CONTENT_TYPE,
        "SOAPAction": _quote_soap_action(normalized_action),
        "Accept": "text/xml",
    }
    if user_agent:
        headers["User-Agent"] = user_agent
    return headers


def build_soap12_headers(action: str, *, user_agent: str | None = None) -> dict[str, str]:
    """Build SOAP 1.2 headers for parity tests; SAT auth currently advertises SOAP 1.1."""

    normalized_action = action.strip()
    if not normalized_action:
        raise ValueError("soap-action-required")
    headers = {
        "Content-Type": f'{SOAP12_CONTENT_TYPE};action="{normalized_action}"',
    }
    if user_agent:
        headers["User-Agent"] = user_agent
    return headers


def validate_auth_headers_for_contract(
    headers: Mapping[str, str],
    contract: AuthWsdlContract,
    *,
    body: bytes | None = None,
) -> AuthHeaderParityResult:
    """Return a redacted parity result for auth POST headers vs the WSDL binding."""

    normalized = {_canonical_header_name(name): value.strip() for name, value in headers.items()}
    content_type = normalized.get("content-type", "")
    media_type, params = _parse_content_type(content_type)
    expected_action = contract.expected_action_uri or contract.soap_action
    header_action = normalized.get("soapaction", "")
    action_value = _unquote(header_action)
    soap_action_quoted = header_action.startswith('"') and header_action.endswith('"')
    sensitive_count = sum(1 for name in normalized if name in SENSITIVE_HEADER_NAMES)

    if contract.soap_version == "1.2":
        soap12_action = _unquote(params.get("action", ""))
        soap_action_ok = soap12_action == expected_action and not header_action
        soap_action_format_ok = "action" in params and not header_action
        content_type_ok = media_type == "application/soap+xml"
    else:
        soap_action_ok = action_value == expected_action
        soap_action_format_ok = bool(header_action) and soap_action_quoted
        content_type_ok = media_type == "text/xml"

    charset = params.get("charset", "")
    charset_ok = charset.lower() == "utf-8"
    all_checks = all(
        (
            content_type_ok,
            charset_ok,
            soap_action_ok,
            soap_action_format_ok,
            sensitive_count == 0,
        )
    )
    return AuthHeaderParityResult(
        soap_version=contract.soap_version,
        media_type=media_type,
        charset=charset,
        soap_action=expected_action if soap_action_ok else "mismatch",
        soap_action_quoted=soap_action_quoted,
        content_type_ok=content_type_ok,
        charset_ok=charset_ok,
        soap_action_ok=soap_action_ok,
        soap_action_format_ok=soap_action_format_ok,
        user_agent_present="user-agent" in normalized,
        accept_encoding_present="accept-encoding" in normalized,
        content_length_present="content-length" in normalized,
        body_size=len(body) if body is not None else None,
        sensitive_header_count=sensitive_count,
        all_checks_passed=all_checks,
    )


def _quote_soap_action(action: str) -> str:
    return action if action.startswith('"') and action.endswith('"') else f'"{action}"'


def _canonical_header_name(name: str) -> str:
    return name.strip().lower()


def _parse_content_type(value: str) -> tuple[str, dict[str, str]]:
    pieces = [piece.strip() for piece in value.split(";") if piece.strip()]
    media_type = pieces[0].lower() if pieces else ""
    params: dict[str, str] = {}
    for piece in pieces[1:]:
        if "=" not in piece:
            continue
        key, raw_value = piece.split("=", 1)
        params[key.strip().lower()] = _unquote(raw_value.strip())
    return media_type, params


def _unquote(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] == '"':
        return stripped[1:-1]
    return stripped
