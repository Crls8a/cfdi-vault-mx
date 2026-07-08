from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest

from cfdi_vault.domain import SatRequestState
from cfdi_vault.sat_contract import SatOutcomeAction
from cfdi_vault.sat_soap_parse import (
    SatSoapParseError,
    parse_authentication_response,
    parse_download_request_response,
    parse_package_download_response,
    parse_verification_response,
)

SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
SAT_NS = "http://DescargaMasivaTerceros.sat.gob.mx"
SAFE_AUTHORIZATION = "SYNTHETIC_AUTHORIZATION_VALUE"


def _soap(body: str) -> str:
    return f'<soap:Envelope xmlns:soap="{SOAP_NS}" xmlns:sat="{SAT_NS}"><soap:Body>{body}</soap:Body></soap:Envelope>'


def test_parse_authentication_response_redacts_raw_response_and_parses_expiry() -> None:
    response = _soap(
        f"""
        <sat:AutenticaResponse>
          <sat:AutenticaResult>
            <sat:Authorization>{SAFE_AUTHORIZATION}</sat:Authorization>
            <sat:ExpiresAt>2026-07-02T15:45:00Z</sat:ExpiresAt>
          </sat:AutenticaResult>
        </sat:AutenticaResponse>
        """
    )

    result = parse_authentication_response(response)

    assert result.authorization == SAFE_AUTHORIZATION
    assert result.expires_at == datetime(2026, 7, 2, 15, 45, tzinfo=timezone.utc)
    assert result.raw_response["has_authorization"] is True
    assert SAFE_AUTHORIZATION not in repr(result)
    assert "raw_response=<redacted>" in repr(result)
    assert SAFE_AUTHORIZATION not in repr(result.raw_response)


def test_parse_download_request_response_classifies_success_and_error() -> None:
    accepted = parse_download_request_response(
        _soap('<sat:SolicitaDescargaResult IdSolicitud="SYN-REQ-001" CodEstatus="5000" Mensaje="Synthetic accepted" />')
    )
    received = parse_download_request_response(
        _soap('<sat:SolicitaDescargaRecibidosResult IdSolicitud="SYN-REQ-002" CodEstatus="5000" Mensaje="Synthetic accepted" />')
    )
    duplicate = parse_download_request_response(
        _soap('<sat:SolicitaDescargaResult CodEstatus="5005" Mensaje="Synthetic duplicate" />')
    )

    assert accepted.request_id == "SYN-REQ-001"
    assert accepted.action == SatOutcomeAction.ACCEPTED
    assert received.request_id == "SYN-REQ-002"
    assert received.action == SatOutcomeAction.ACCEPTED
    assert duplicate.request_id == ""
    assert duplicate.action == SatOutcomeAction.DUPLICATE


def test_parse_verification_response_maps_state_and_packages() -> None:
    finished = parse_verification_response(
        _soap(
            """
            <sat:VerificaSolicitudDescargaResult IdSolicitud="SYN-REQ-001" CodEstatus="5000" EstadoSolicitud="3" Mensaje="Finished">
              <sat:IdsPaquetes>
                <sat:IdPaquete>SYN-PKG-001</sat:IdPaquete>
                <sat:IdPaquete>SYN-PKG-002</sat:IdPaquete>
              </sat:IdsPaquetes>
            </sat:VerificaSolicitudDescargaResult>
            """
        )
    )
    processing = parse_verification_response(
        _soap('<sat:VerificaSolicitudDescargaResult IdSolicitud="SYN-REQ-002" CodEstatus="5000" EstadoSolicitud="in_process" Mensaje="Working" />')
    )

    assert finished.state == SatRequestState.FINISHED
    assert finished.action == SatOutcomeAction.FINISHED
    assert finished.package_ids == ("SYN-PKG-001", "SYN-PKG-002")
    assert processing.state == SatRequestState.IN_PROCESS
    assert processing.action == SatOutcomeAction.IN_PROGRESS


def test_parse_package_download_response_decodes_content_and_classifies_errors() -> None:
    payload = base64.b64encode(b"SYNTHETIC-PACKAGE::SYN-PKG-001\n").decode("ascii")
    downloaded = parse_package_download_response(
        _soap(f'<sat:DescargaResult IdPaquete="SYN-PKG-001" CodEstatus="5000" Mensaje="Downloaded">{payload}</sat:DescargaResult>')
    )
    documented_shape = parse_package_download_response(
        _soap(f"<sat:RespuestaDescargaMasivaTercerosSalida><sat:Paquete>{payload}</sat:Paquete></sat:RespuestaDescargaMasivaTercerosSalida>"),
        package_id="SYN-PKG-DOCS",
    )
    expired = parse_package_download_response(
        _soap('<sat:DescargaResult IdPaquete="SYN-PKG-002" CodEstatus="5007" Mensaje="Expired" />')
    )

    assert downloaded.package_id == "SYN-PKG-001"
    assert downloaded.action == SatOutcomeAction.FINISHED
    assert downloaded.content == b"SYNTHETIC-PACKAGE::SYN-PKG-001\n"
    assert downloaded.raw_response["content_length"] == len(downloaded.content)
    assert "SYN-PKG-001" not in repr(downloaded)
    assert "SYN-...-001" in repr(downloaded)
    assert "SYNTHETIC-PACKAGE" not in repr(downloaded)
    assert payload not in repr(downloaded)
    assert "content=<redacted>" in repr(downloaded)
    assert documented_shape.package_id == "SYN-PKG-DOCS"
    assert documented_shape.sat_code == "5000"
    assert documented_shape.content == b"SYNTHETIC-PACKAGE::SYN-PKG-001\n"
    assert expired.action == SatOutcomeAction.EXPIRED
    assert expired.content is None


def test_parser_errors_are_clear_for_malformed_or_missing_fields() -> None:
    with pytest.raises(SatSoapParseError, match="invalid SOAP XML"):
        parse_download_request_response("<soap:Envelope>")
    with pytest.raises(SatSoapParseError, match="authorization is required"):
        parse_authentication_response(_soap("<sat:AutenticaResult />"))
    with pytest.raises(SatSoapParseError, match="download request result is required"):
        parse_download_request_response(_soap('<sat:NotDownloadRequestResult IdSolicitud="SYN-REQ-001" CodEstatus="5000" />'))
    with pytest.raises(SatSoapParseError, match="sat_code is required"):
        parse_download_request_response(_soap('<sat:SolicitaDescargaResult IdSolicitud="SYN-REQ-001" />'))
    with pytest.raises(SatSoapParseError, match="state is required"):
        parse_verification_response(_soap('<sat:VerificaSolicitudDescargaResult IdSolicitud="SYN-REQ-001" CodEstatus="5000" />'))
    with pytest.raises(SatSoapParseError, match="invalid base64 package content"):
        parse_package_download_response(
            _soap('<sat:DescargaResult IdPaquete="SYN-PKG-001" CodEstatus="5000">not-base64</sat:DescargaResult>')
        )
