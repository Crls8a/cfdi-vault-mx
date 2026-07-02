"""Offline SOAP envelope builders for SAT mass-download operations.

This module builds XML only. It does not resolve credentials, open files,
perform network I/O, or implement live WS-Security/e.firma behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from cfdi_vault.domain import DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.ports import SignerPort

SOAP_ENVELOPE_NS = "http://www.w3.org/2003/05/soap-envelope"
SAT_MASS_DOWNLOAD_NS = "http://DescargaMasivaTerceros.sat.gob.mx"

ET.register_namespace("soap", SOAP_ENVELOPE_NS)
ET.register_namespace("sat", SAT_MASS_DOWNLOAD_NS)


@dataclass(frozen=True)
class SatVerificationEnvelopeInput:
    """Data needed to build an offline SAT verification envelope."""

    request_id: str
    requester_rfc: str

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.request_id:
            errors.append("request_id is required")
        if not self.requester_rfc:
            errors.append("requester_rfc is required")
        return tuple(errors)


@dataclass(frozen=True)
class SatPackageDownloadEnvelopeInput:
    """Data needed to build an offline SAT package-download envelope."""

    package_id: str
    requester_rfc: str

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.package_id:
            errors.append("package_id is required")
        if not self.requester_rfc:
            errors.append("requester_rfc is required")
        return tuple(errors)


def build_authentication_envelope(synthetic_placeholder: str = "SYNTHETIC_AUTHORIZATION") -> bytes:
    """Build an offline authentication SOAP envelope with placeholder content only."""

    if not synthetic_placeholder:
        raise ValueError("synthetic_placeholder is required")
    operation = _operation("Autentica")
    ET.SubElement(operation, _sat_tag("placeholder")).text = synthetic_placeholder
    return _serialize_envelope(operation)


def build_download_request_envelope(query: DownloadQuery, signer: SignerPort | None = None) -> bytes:
    """Build an offline SAT request envelope from a normalized download query."""

    errors = query.validate()
    if errors:
        raise ValueError("invalid download query: " + "; ".join(errors))
    operation = _operation("SolicitaDescarga")
    operation.append(_maybe_sign(_download_request_payload(query), signer))
    return _serialize_envelope(operation)


def build_verification_envelope(
    input: SatVerificationEnvelopeInput,
    signer: SignerPort | None = None,
) -> bytes:
    """Build an offline SAT request-verification envelope."""

    _raise_if_invalid(input.validate(), "invalid verification input")
    operation = _operation("VerificaSolicitudDescarga")
    payload = ET.Element(
        _sat_tag("solicitud"),
        {
            "IdSolicitud": input.request_id,
            "RfcSolicitante": input.requester_rfc.upper(),
        },
    )
    operation.append(_maybe_sign(payload, signer))
    return _serialize_envelope(operation)


def build_package_download_envelope(
    input: SatPackageDownloadEnvelopeInput,
    signer: SignerPort | None = None,
) -> bytes:
    """Build an offline SAT package-download envelope."""

    _raise_if_invalid(input.validate(), "invalid package download input")
    operation = _operation("Descargar")
    payload = ET.Element(
        _sat_tag("peticionDescarga"),
        {
            "IdPaquete": input.package_id,
            "RfcSolicitante": input.requester_rfc.upper(),
        },
    )
    operation.append(_maybe_sign(payload, signer))
    return _serialize_envelope(operation)


def _download_request_payload(query: DownloadQuery) -> ET.Element:
    attrs = {
        "RfcSolicitante": query.requester_rfc.upper(),
        "TipoSolicitud": _request_type_value(query.request_type),
    }
    if query.direction == DownloadDirection.FOLIO:
        attrs["Folio"] = str(query.uuid).upper()
    else:
        assert query.period is not None
        attrs["FechaInicial"] = _format_sat_datetime(query.period.start)
        attrs["FechaFinal"] = _format_sat_datetime(query.period.end)
        if query.direction == DownloadDirection.ISSUED:
            attrs["RfcEmisor"] = (query.issuer_rfc or query.requester_rfc).upper()
        if query.direction == DownloadDirection.RECEIVED:
            attrs["RfcReceptor"] = query.requester_rfc.upper()
            if query.issuer_rfc:
                attrs["RfcEmisor"] = query.issuer_rfc.upper()
    _add_optional(attrs, "EstadoComprobante", query.document_status)
    _add_optional(attrs, "TipoComprobante", query.document_type)
    _add_optional(attrs, "Complemento", query.complement)
    _add_optional(attrs, "RfcACuentaTerceros", query.rfc_on_behalf.upper() if query.rfc_on_behalf else None)

    payload = ET.Element(_sat_tag("solicitud"), attrs)
    if query.receiver_rfcs:
        receivers = ET.SubElement(payload, _sat_tag("RfcReceptores"))
        for rfc in query.receiver_rfcs:
            ET.SubElement(receivers, _sat_tag("RfcReceptor")).text = rfc.upper()
    return payload


def _operation(name: str) -> ET.Element:
    return ET.Element(_sat_tag(name))


def _maybe_sign(payload: ET.Element, signer: SignerPort | None) -> ET.Element:
    if signer is None:
        return payload
    signed_payload = signer.sign(ET.tostring(payload, encoding="utf-8"))
    try:
        return ET.fromstring(signed_payload)
    except ET.ParseError as exc:
        raise ValueError("signer returned invalid XML") from exc


def _serialize_envelope(operation: ET.Element) -> bytes:
    envelope = ET.Element(_soap_tag("Envelope"))
    ET.SubElement(envelope, _soap_tag("Header"))
    body = ET.SubElement(envelope, _soap_tag("Body"))
    body.append(operation)
    return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)


def _request_type_value(request_type: RequestType) -> str:
    if request_type == RequestType.CFDI:
        return "CFDI"
    if request_type == RequestType.METADATA:
        return "Metadata"
    return str(request_type)


def _format_sat_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        return value.isoformat(timespec="seconds")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _add_optional(attrs: dict[str, str], key: str, value: str | None) -> None:
    if value:
        attrs[key] = value


def _raise_if_invalid(errors: tuple[str, ...], prefix: str) -> None:
    if errors:
        raise ValueError(prefix + ": " + "; ".join(errors))


def _soap_tag(name: str) -> str:
    return f"{{{SOAP_ENVELOPE_NS}}}{name}"


def _sat_tag(name: str) -> str:
    return f"{{{SAT_MASS_DOWNLOAD_NS}}}{name}"
