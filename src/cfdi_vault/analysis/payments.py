"""Pure normalization of CFDI payment complements held in memory.

This module extracts only payment dates, payment attributes, and related
document counts.  It does not read artifacts, persist rows, contact SAT, or
retain identifiers from ``DoctoRelacionado``.  Unknown CFDI or payment
versions are reported explicitly rather than guessed.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

from cfdi_vault.parser import CfdiParseError

PARSER_STATUS_COMPLETE = "complete"
PARSER_STATUS_EMPTY = "empty"
PARSER_STATUS_PARTIAL = "partial"
PARSER_STATUS_UNSUPPORTED_ERROR = "unsupported-error"
SUPPORTED_CFDI_VERSIONS = frozenset({"3.2", "3.3", "4.0"})
SUPPORTED_PAYMENT_VERSIONS = frozenset({"1.0", "2.0"})
_EXPECTED_PAYMENT_VERSIONS = {"3.2": "1.0", "3.3": "1.0", "4.0": "2.0"}
_MAX_PROVENANCE_LENGTH = 128
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UUID_REF = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
_RFC_REF = re.compile(r"^[A-Z&Ñ]{3,4}[0-9]{6}[A-Z0-9]{3}$", re.IGNORECASE)
_SAT_ID_REF = re.compile(
    r"^(?:SAT|IDSOLICITUD|IDPAQUETE|SOLICITUD|PAQUETE)[-_.:]?[A-Z0-9]+$",
    re.IGNORECASE,
)
_STAMP_COMPLEMENT = "TimbreFiscalDigital"


@dataclass(frozen=True)
class PaymentRecord:
    """One payment without related-document identifiers.

    ``related_document_count`` is deliberately a count rather than a list;
    UUIDs and other attributes from ``DoctoRelacionado`` never enter this
    object.  ``None`` means the source did not durably preserve relation
    evidence and must remain incomplete in downstream summaries.
    ``provenance`` is an opaque, caller-supplied reference.
    """

    payment_date: datetime | None = field(repr=False)
    payment_form: str | None = field(repr=False)
    currency: str | None = field(repr=False)
    amount: Decimal | None = field(repr=False)
    exchange_rate: Decimal | None = field(repr=False)
    related_document_count: int | None
    provenance: str = field(repr=False)

    def __repr__(self) -> str:
        """Return a representation that contains no provenance or values."""

        return "PaymentRecord(<redacted>)"


@dataclass(frozen=True)
class PaymentNormalizationResult(Sequence[PaymentRecord]):
    """Normalized payments plus explicit version and completeness evidence."""

    records: tuple[PaymentRecord, ...]
    cfdi_version: str
    payment_version: str | None
    parser_status: str
    complement_present: bool

    @property
    def version(self) -> str:
        """Return the CFDI root version using the common parser contract."""

        return self.cfdi_version

    @property
    def complement_version(self) -> str | None:
        """Return the payment complement version, when one was present."""

        return self.payment_version

    def __iter__(self) -> Iterator[PaymentRecord]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int | slice) -> PaymentRecord | tuple[PaymentRecord, ...]:
        return self.records[index]


def normalize_payments(
    xml_bytes: bytes,
    *,
    document_ref: str = "document",
) -> PaymentNormalizationResult:
    """Extract direct ``Pago`` entries from a CFDI payment complement.

    CFDI 3.2, 3.3, and 4.0 roots and payment complement versions 1.0 and 2.0
    are recognized.  Older recognized CFDI roots are returned as ``partial``;
    unknown versions return ``unsupported-error`` without inference.  Missing
    payment complements return an explicit ``empty`` result.

    Raises:
        TypeError: if XML or the provenance reference has the wrong type.
        CfdiParseError: for unsafe declarations, malformed XML, invalid root,
            invalid dates, invalid decimal values, or negative values.
        ValueError: if the provenance reference is not an opaque safe value.
    """

    if not isinstance(xml_bytes, bytes):
        raise TypeError("payment-xml-bytes-required")
    provenance = _validate_provenance(document_ref)
    xml_text = _decode_xml(xml_bytes)
    _reject_unsafe_declarations(xml_text)
    root = _parse_root(xml_text)
    if _local_name(root.tag) != "Comprobante":
        raise CfdiParseError("payment-root-invalid")

    cfdi_version = root.attrib.get("Version") or root.attrib.get("version") or "unknown"
    if cfdi_version not in SUPPORTED_CFDI_VERSIONS:
        return PaymentNormalizationResult((), cfdi_version, None, PARSER_STATUS_UNSUPPORTED_ERROR, False)

    complements = _find_payment_complements(root)
    if not complements:
        has_unknown_complement = any(
            _local_name(child.tag) != _STAMP_COMPLEMENT
            for container in _direct_children(root, "Complemento")
            for child in container
        )
        status = PARSER_STATUS_PARTIAL if has_unknown_complement else PARSER_STATUS_EMPTY
        return PaymentNormalizationResult((), cfdi_version, None, status, False)

    if len(complements) > 1:
        versions = {item.attrib.get("Version") or item.attrib.get("version") for item in complements}
        payment_version = versions.pop() if len(versions) == 1 else None
        return PaymentNormalizationResult((), cfdi_version, payment_version, PARSER_STATUS_PARTIAL, True)

    complement = complements[0]

    payment_version = complement.attrib.get("Version") or complement.attrib.get("version")
    if payment_version not in SUPPORTED_PAYMENT_VERSIONS:
        return PaymentNormalizationResult((), cfdi_version, payment_version, PARSER_STATUS_UNSUPPORTED_ERROR, True)
    if payment_version != _EXPECTED_PAYMENT_VERSIONS[cfdi_version]:
        return PaymentNormalizationResult((), cfdi_version, payment_version, PARSER_STATUS_UNSUPPORTED_ERROR, True)

    payment_elements = _direct_children(complement, "Pago")
    totals_elements = _direct_children(complement, "Totales")
    if not payment_elements or (payment_version == "2.0" and len(totals_elements) != 1):
        return PaymentNormalizationResult((), cfdi_version, payment_version, PARSER_STATUS_PARTIAL, True)
    if payment_version == "2.0":
        child_names = tuple(_local_name(child.tag) for child in complement)
        if child_names[0] != "Totales" or any(name != "Pago" for name in child_names[1:]):
            return PaymentNormalizationResult((), cfdi_version, payment_version, PARSER_STATUS_PARTIAL, True)
        try:
            totals_amount = _required_attr(totals_elements[0], "MontoTotalPagos")
        except CfdiParseError:
            return PaymentNormalizationResult((), cfdi_version, payment_version, PARSER_STATUS_PARTIAL, True)
        _decimal(totals_amount, "payment-total-amount")

    records = tuple(_normalize_payment(payment, provenance) for payment in payment_elements)
    valid_children = {"Pago"}
    if payment_version == "2.0":
        valid_children.add("Totales")
    has_unknown_complement = any(
        _local_name(child.tag) not in {_STAMP_COMPLEMENT, "Pagos"}
        for container in _direct_children(root, "Complemento")
        for child in container
    )
    has_unknown_payment_child = any(_local_name(child.tag) not in valid_children for child in complement)
    status = PARSER_STATUS_COMPLETE
    if cfdi_version != "4.0" or has_unknown_complement or has_unknown_payment_child:
        status = PARSER_STATUS_PARTIAL
    return PaymentNormalizationResult(records, cfdi_version, payment_version, status, True)


def _find_payment_complements(root: ET.Element) -> tuple[ET.Element, ...]:
    complements: list[ET.Element] = []
    for container in _direct_children(root, "Complemento"):
        complements.extend(_direct_children(container, "Pagos"))
    return tuple(complements)


def _normalize_payment(element: ET.Element, provenance: str) -> PaymentRecord:
    payment_date = _parse_date(_required_attr(element, "FechaPago"))
    amount = _decimal(_required_attr(element, "Monto"), "payment-amount")
    currency = _required_attr(element, "MonedaP").upper()
    payment_form = _required_attr(element, "FormaDePagoP")
    if currency == "XXX":
        raise CfdiParseError("payment-currency-invalid")
    if payment_form == "99":
        raise CfdiParseError("payment-form-invalid")
    if currency == "MXN" and "TipoCambioP" in element.attrib:
        raise CfdiParseError("payment-exchange-rate-forbidden")
    exchange_rate = _decimal(element.attrib.get("TipoCambioP"), "payment-exchange-rate")
    if currency != "MXN" and exchange_rate is None:
        raise CfdiParseError("payment-exchange-rate-required")
    if exchange_rate is not None and exchange_rate <= 0:
        raise CfdiParseError("payment-exchange-rate-nonpositive")
    related_count = sum(_local_name(child.tag) == "DoctoRelacionado" for child in element)
    return PaymentRecord(
        payment_date=payment_date,
        payment_form=payment_form,
        currency=currency,
        amount=amount,
        exchange_rate=exchange_rate,
        related_document_count=related_count,
        provenance=provenance,
    )


def _required_attr(element: ET.Element, name: str) -> str:
    value = element.attrib.get(name)
    if value is None or not value.strip():
        raise CfdiParseError("payment-required-attribute-missing")
    return value.strip()


def _parse_date(value: str) -> datetime:
    if "T" not in value:
        raise CfdiParseError("payment-date-invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CfdiParseError("payment-date-invalid") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _decimal(value: str | None, field_name: str) -> Decimal | None:
    if value is None or not value.strip():
        return None
    try:
        parsed = Decimal(value.strip())
    except (InvalidOperation, ValueError):
        raise CfdiParseError(f"{field_name}-decimal-invalid") from None
    if not parsed.is_finite():
        raise CfdiParseError(f"{field_name}-decimal-invalid")
    if parsed < 0:
        raise CfdiParseError(f"{field_name}-decimal-negative")
    return parsed


def _validate_provenance(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("payment-document-ref-required")
    if (
        not value
        or len(value) > _MAX_PROVENANCE_LENGTH
        or not _OPAQUE_REF.fullmatch(value)
        or "/" in value
        or "\\" in value
        or re.match(r"^[A-Za-z]:", value)
        or _UUID_REF.fullmatch(value)
        or _RFC_REF.fullmatch(value)
        or _SAT_ID_REF.fullmatch(value)
        or value.isdecimal()
    ):
        raise ValueError("payment-document-ref-invalid")
    return value


def _decode_xml(xml_bytes: bytes) -> str:
    try:
        return xml_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise CfdiParseError("payment-xml-encoding-invalid") from None


def _reject_unsafe_declarations(xml_text: str) -> None:
    upper = xml_text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise CfdiParseError("payment-doctype-rejected")


def _parse_root(xml_text: str) -> ET.Element:
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
        raise CfdiParseError("payment-xml-invalid") from None


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _direct_children(element: ET.Element, local_name: str) -> tuple[ET.Element, ...]:
    return tuple(child for child in element if _local_name(child.tag) == local_name)
