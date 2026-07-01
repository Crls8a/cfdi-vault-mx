"""CFDI XML parsing utilities.

The parser intentionally extracts only the fields needed for this phase. It does
not validate CFDI authenticity, stamp status, certificate chains, or SAT state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
import xml.etree.ElementTree as ET


class CfdiParseError(ValueError):
    """Raised when a CFDI XML cannot be parsed into the phase-one shape."""


@dataclass(frozen=True)
class ParsedCfdi:
    """Parsed CFDI fields persisted by the vault."""

    uuid: str
    issuer_rfc: str
    issuer_name: str
    receiver_rfc: str
    receiver_name: str
    issue_date: datetime
    subtotal: Decimal
    total: Decimal
    currency: str
    comprobante_type: str
    payment_method: str | None
    payment_form: str | None


def parse_cfdi_xml(xml_bytes: bytes) -> ParsedCfdi:
    """Parse a CFDI XML document and return its importable fields.

    The function is namespace-tolerant because CFDI examples may use different
    prefixes while preserving the same local element names.
    """

    _reject_doctype(xml_bytes)

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise CfdiParseError(f"Invalid XML: {exc}") from exc

    if _local_name(root.tag) != "Comprobante":
        raise CfdiParseError("Expected CFDI Comprobante root element")

    issuer = _find_direct_child(root, "Emisor")
    receiver = _find_direct_child(root, "Receptor")
    stamp = _find_descendant(root, "TimbreFiscalDigital")

    if issuer is None:
        raise CfdiParseError("Missing CFDI Emisor element")
    if receiver is None:
        raise CfdiParseError("Missing CFDI Receptor element")
    if stamp is None:
        raise CfdiParseError("Missing TimbreFiscalDigital complement")

    uuid = _required_attr(stamp, "UUID", "TimbreFiscalDigital")
    issue_date = _parse_issue_date(_required_attr(root, "Fecha", "Comprobante"))

    return ParsedCfdi(
        uuid=uuid,
        issuer_rfc=_required_attr(issuer, "Rfc", "Emisor"),
        issuer_name=_required_attr(issuer, "Nombre", "Emisor"),
        receiver_rfc=_required_attr(receiver, "Rfc", "Receptor"),
        receiver_name=_required_attr(receiver, "Nombre", "Receptor"),
        issue_date=issue_date,
        subtotal=_parse_decimal(_required_attr(root, "SubTotal", "Comprobante"), "SubTotal"),
        total=_parse_decimal(_required_attr(root, "Total", "Comprobante"), "Total"),
        currency=_required_attr(root, "Moneda", "Comprobante"),
        comprobante_type=_required_attr(root, "TipoDeComprobante", "Comprobante"),
        payment_method=root.attrib.get("MetodoPago"),
        payment_form=root.attrib.get("FormaPago"),
    )


def _reject_doctype(xml_bytes: bytes) -> None:
    if b"<!DOCTYPE" in xml_bytes[:512].upper():
        raise CfdiParseError("DOCTYPE declarations are not supported")


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _find_direct_child(element: ET.Element, local_name: str) -> ET.Element | None:
    for child in element:
        if _local_name(child.tag) == local_name:
            return child
    return None


def _find_descendant(element: ET.Element, local_name: str) -> ET.Element | None:
    for child in element.iter():
        if _local_name(child.tag) == local_name:
            return child
    return None


def _required_attr(element: ET.Element, attr: str, element_name: str) -> str:
    value = element.attrib.get(attr)
    if value is None or value == "":
        raise CfdiParseError(f"Missing {attr} attribute on {element_name}")
    return value


def _parse_issue_date(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise CfdiParseError(f"Invalid CFDI Fecha value: {value}") from exc


def _parse_decimal(value: str, field_name: str) -> Decimal:
    try:
        return Decimal(value)
    except InvalidOperation as exc:
        raise CfdiParseError(f"Invalid decimal value for {field_name}: {value}") from exc
