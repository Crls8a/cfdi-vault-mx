"""Offline SOAP response parsers for SAT mass-download operations.

The parsers in this module only normalize XML already provided by a caller.
They do not perform HTTP transport, SAT access, logging, credential handling,
package persistence, or real e.firma work.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from xml.etree import ElementTree as ET

from cfdi_vault.domain import SatRequestState
from cfdi_vault.sat_contract import (
    SatAuthResult,
    SatDownloadResult,
    SatOperation,
    SatOutcomeAction,
    SatRequestResult,
    SatVerificationResult,
    classify_sat_outcome,
)


class SatSoapParseError(ValueError):
    """Raised when a synthetic SOAP response cannot be safely normalized."""


XmlInput = str | bytes


def parse_authentication_response(xml: XmlInput) -> SatAuthResult:
    """Parse a synthetic SAT authentication response into a normalized result."""

    root = _response_root(xml)
    result = _required_element(root, "authentication result", "AutenticaResult", "AuthenticateResult", "AuthenticationResult")
    authorization = (
        _value(result, "Authorization", "Autorizacion", "Token", "AuthenticationToken")
        or _direct_text(result)
    )
    if not authorization:
        raise SatSoapParseError("authorization is required in authentication response")

    expires_raw = _value(result, "ExpiresAt", "Expiration", "Vigencia", "ValidTo")
    expires_at = _parse_datetime(expires_raw) if expires_raw else None
    raw_response = {
        "operation": "authenticate",
        "has_authorization": True,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }
    return SatAuthResult(authorization=authorization, expires_at=expires_at, raw_response=raw_response)


def parse_download_request_response(xml: XmlInput) -> SatRequestResult:
    """Parse a synthetic SAT download-request response."""

    root = _response_root(xml)
    result = _required_element(
        root,
        "download request result",
        "SolicitaDescargaResult",
        "SolicitaDescargaEmitidosResult",
        "SolicitaDescargaRecibidosResult",
        "SolicitaDescargaFolioResult",
        "RequestDownloadResult",
    )
    sat_code = _required_value(result, "sat_code", "CodEstatus", "CodigoEstatus", "StatusCode")
    message = _value(result, "Mensaje", "Message", "StatusMessage") or ""
    request_id = _value(result, "IdSolicitud", "RequestId", "SolicitudId") or ""

    classification = classify_sat_outcome(SatOperation.REQUEST, sat_code=sat_code)
    if classification.action == SatOutcomeAction.ACCEPTED and not request_id:
        raise SatSoapParseError("request_id is required when SAT request is accepted")

    return SatRequestResult(
        request_id=request_id,
        sat_code=sat_code,
        message=message,
        action=classification.action,
        raw_response=_raw("request", sat_code, message, classification.reason),
    )


def parse_verification_response(xml: XmlInput) -> SatVerificationResult:
    """Parse a synthetic SAT request-verification response."""

    root = _response_root(xml)
    result = _required_element(root, "verification result", "VerificaSolicitudDescargaResult", "VerifyRequestResult")
    sat_code = _required_value(result, "sat_code", "CodEstatus", "CodigoEstatus", "StatusCode")
    state = _parse_state(_required_value(result, "state", "EstadoSolicitud", "State", "RequestState"))
    message = _value(result, "Mensaje", "Message", "StatusMessage") or ""
    request_id = _value(result, "IdSolicitud", "RequestId", "SolicitudId") or ""
    package_ids = tuple(_texts(root, "IdPaquete", "IdsPaquetes", "PackageId"))

    classification = classify_sat_outcome(SatOperation.VERIFY, sat_code=sat_code, state=state)
    return SatVerificationResult(
        request_id=request_id,
        state=state,
        sat_code=sat_code,
        message=message,
        package_ids=package_ids,
        action=classification.action,
        raw_response={
            **_raw("verify", sat_code, message, classification.reason),
            "state": state.value,
            "package_count": len(package_ids),
        },
    )


def parse_package_download_response(xml: XmlInput, *, package_id: str | None = None) -> SatDownloadResult:
    """Parse a synthetic SAT package-download response and decode package bytes."""

    root = _response_root(xml)
    result = _required_element(root, "package download result", "DescargaResult", "DescargarResult", "DownloadResult", "RespuestaDescargaMasivaTercerosSalida")
    message = _value(result, "Mensaje", "Message", "StatusMessage") or ""
    normalized_package_id = package_id or _value(result, "IdPaquete", "PackageId") or ""
    if not normalized_package_id:
        raise SatSoapParseError("package_id is required in package download response")
    encoded = _value(result, "Paquete", "Package", "Contenido", "Content") or _direct_text(result)
    sat_code = _value(result, "CodEstatus", "CodigoEstatus", "StatusCode") or ("5000" if encoded else "")
    if not sat_code:
        raise SatSoapParseError("sat_code is required in SOAP response")

    classification = classify_sat_outcome(SatOperation.DOWNLOAD, sat_code=sat_code)
    content = None
    if classification.action == SatOutcomeAction.FINISHED:
        if not encoded:
            raise SatSoapParseError("package content is required when SAT download succeeds")
        content = _decode_base64(encoded)

    return SatDownloadResult(
        package_id=normalized_package_id,
        sat_code=sat_code,
        message=message,
        action=classification.action,
        content=content,
        raw_response={
            **_raw("download", sat_code, message, classification.reason),
            "content_length": len(content) if content is not None else 0,
        },
    )


def _response_root(xml: XmlInput) -> ET.Element:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise SatSoapParseError("invalid SOAP XML") from exc
    fault = _first(root, "Fault")
    if fault is not None:
        raise SatSoapParseError(f"SOAP fault: {_fault_message(fault)}")
    return root


def _fault_message(fault: ET.Element) -> str:
    return _value(fault, "Text", "Reason", "faultstring") or "SAT SOAP fault"


def _parse_datetime(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SatSoapParseError("invalid authentication expiration datetime") from exc


def _parse_state(value: str) -> SatRequestState:
    key = _norm(value)
    aliases = {
        "1": SatRequestState.ACCEPTED,
        "aceptada": SatRequestState.ACCEPTED,
        "accepted": SatRequestState.ACCEPTED,
        "2": SatRequestState.IN_PROCESS,
        "enproceso": SatRequestState.IN_PROCESS,
        "inprocess": SatRequestState.IN_PROCESS,
        "in_process": SatRequestState.IN_PROCESS,
        "3": SatRequestState.FINISHED,
        "terminada": SatRequestState.FINISHED,
        "finished": SatRequestState.FINISHED,
        "4": SatRequestState.ERROR,
        "error": SatRequestState.ERROR,
        "5": SatRequestState.REJECTED,
        "rechazada": SatRequestState.REJECTED,
        "rejected": SatRequestState.REJECTED,
        "6": SatRequestState.EXPIRED,
        "vencida": SatRequestState.EXPIRED,
        "expired": SatRequestState.EXPIRED,
    }
    if key in aliases:
        return aliases[key]
    try:
        return SatRequestState(value)
    except ValueError as exc:
        raise SatSoapParseError(f"unknown SAT request state: {value}") from exc


def _decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode("".join(value.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SatSoapParseError("invalid base64 package content") from exc


def _required_value(element: ET.Element, field: str, *names: str) -> str:
    value = _value(element, *names)
    if not value:
        raise SatSoapParseError(f"{field} is required in SOAP response")
    return value


def _value(element: ET.Element, *names: str) -> str | None:
    targets = {_norm(name) for name in names}
    for current in element.iter():
        for attr_name, attr_value in current.attrib.items():
            if _norm(_local_name(attr_name)) in targets and attr_value.strip():
                return attr_value.strip()
        if _norm(_local_name(current.tag)) in targets:
            text = _direct_text(current)
            if text:
                return text
    return None


def _texts(element: ET.Element, *names: str) -> list[str]:
    targets = {_norm(name) for name in names}
    return [
        text
        for current in element.iter()
        if _norm(_local_name(current.tag)) in targets
        for text in [_direct_text(current)]
        if text
    ]


def _first(element: ET.Element, *names: str) -> ET.Element | None:
    targets = {_norm(name) for name in names}
    return next((current for current in element.iter() if _norm(_local_name(current.tag)) in targets), None)


def _required_element(element: ET.Element, label: str, *names: str) -> ET.Element:
    found = _first(element, *names)
    if found is None:
        raise SatSoapParseError(f"{label} is required in SOAP response")
    return found


def _direct_text(element: ET.Element) -> str | None:
    return element.text.strip() if element.text and element.text.strip() else None


def _raw(operation: str, sat_code: str, message: str, reason: str) -> dict[str, str]:
    return {"operation": operation, "sat_code": sat_code, "message": message, "reason": reason}


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _norm(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())
