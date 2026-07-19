"""Pure, bounded normalization of CFDI tax lines.

The module extracts only concept-level and comprobante-level tax evidence from
XML already held in memory.  It does not read artifacts, persist rows, contact
SAT, or infer tax liability.  Unknown versions and business complements remain
explicitly partial instead of being guessed.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from cfdi_vault.parser import CfdiParseError

PARSER_STATUS_COMPLETE = "complete"
PARSER_STATUS_PARTIAL = "partial"
PARSER_STATUS_UNSUPPORTED_ERROR = "unsupported-error"
SUPPORTED_CFDI_VERSIONS = frozenset({"3.2", "3.3", "4.0"})
_MAX_PROVENANCE_LENGTH = 128
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UUID_REF = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
_RFC_REF = re.compile(r"^[A-Z&Ñ]{3,4}[0-9]{6}[A-Z0-9]{3}$", re.IGNORECASE)
_SAT_ID_REF = re.compile(r"^(?:SAT|IDSOLICITUD|IDPAQUETE|SOLICITUD|PAQUETE)[-_.:]?[A-Z0-9]+$", re.IGNORECASE)
_KNOWN_TAXES = frozenset({"001", "002", "003"})
_FACTOR_TYPES = {"tasa": "Tasa", "cuota": "Cuota", "exento": "Exento"}
_STAMP_COMPLEMENT = "TimbreFiscalDigital"


@dataclass(frozen=True)
class TaxRecord:
    """One sanitized transferred or withheld tax line.

    ``concept_ordinal`` is set for a tax below a concept and is ``None`` for
    the comprobante summary.  ``document_scope`` is ``concept`` or ``document``.
    Numeric attributes stay as ``Decimal`` values and may be absent when the
    CFDI shape makes them optional (for example a summary withholding line).
    """

    tax_type: str
    tax: str
    factor_type: str | None
    rate_or_quota: Decimal | None
    base: Decimal | None
    amount: Decimal | None
    concept_ordinal: int | None
    document_scope: str
    provenance: str

    def __repr__(self) -> str:
        """Return a redacted representation without fiscal row values."""

        return "TaxRecord(<redacted>)"


@dataclass(frozen=True)
class TaxNormalizationResult(Sequence[TaxRecord]):
    """Normalized tax records plus version and parser-status evidence."""

    records: tuple[TaxRecord, ...]
    version: str
    parser_status: str

    def __iter__(self) -> Iterator[TaxRecord]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int | slice) -> TaxRecord | tuple[TaxRecord, ...]:
        return self.records[index]


def normalize_taxes(
    xml_bytes: bytes,
    *,
    document_ref: str = "document",
) -> TaxNormalizationResult:
    """Extract CFDI concept and document tax lines from in-memory XML.

    Version 4.0 is the complete contract.  Known older versions return an
    empty ``partial`` result, and unknown versions return ``unsupported-error``
    without inference.  Unknown business complements downgrade a 4.0 result
    to ``partial`` while preserving recognized tax lines.

    Raises:
        TypeError: if XML or the provenance reference has the wrong type.
        CfdiParseError: for unsafe declarations, malformed XML, invalid root,
            unknown tax/factor values, invalid decimals, or negative values.
        ValueError: if the provenance reference is not an opaque safe value.
    """

    if not isinstance(xml_bytes, bytes):
        raise TypeError("tax-xml-bytes-required")
    provenance = _validate_provenance(document_ref)
    xml_text = _decode_xml(xml_bytes)
    _reject_unsafe_declarations(xml_text)
    root = _parse_root(xml_text)
    if _local_name(root.tag) != "Comprobante":
        raise CfdiParseError("tax-root-invalid")

    version = root.attrib.get("Version") or root.attrib.get("version") or "unknown"
    if version not in SUPPORTED_CFDI_VERSIONS:
        return TaxNormalizationResult((), version, PARSER_STATUS_UNSUPPORTED_ERROR)
    if version != "4.0":
        return TaxNormalizationResult((), version, PARSER_STATUS_PARTIAL)

    records: list[TaxRecord] = []
    ordinal = 0
    for concepts in _direct_children(root, "Conceptos"):
        for concept in _direct_children(concepts, "Concepto"):
            ordinal += 1
            for taxes in _direct_children(concept, "Impuestos"):
                records.extend(_taxes_in_container(taxes, ordinal, "concept", provenance))

    for taxes in _direct_children(root, "Impuestos"):
        records.extend(_taxes_in_container(taxes, None, "document", provenance))

    has_business_complement = any(
        _local_name(child.tag) != _STAMP_COMPLEMENT
        for container in _direct_children(root, "Complemento")
        for child in container
    )
    status = PARSER_STATUS_PARTIAL if has_business_complement else PARSER_STATUS_COMPLETE
    return TaxNormalizationResult(tuple(records), version, status)


def _taxes_in_container(
    container: ET.Element,
    concept_ordinal: int | None,
    scope: str,
    provenance: str,
) -> tuple[TaxRecord, ...]:
    records: list[TaxRecord] = []
    for group_name, tax_type, item_name in (
        ("Traslados", "transferred", "Traslado"),
        ("Retenciones", "withheld", "Retencion"),
    ):
        for group in _direct_children(container, group_name):
            for item in _direct_children(group, item_name):
                records.append(
                    _normalize_one(
                        item,
                        tax_type,
                        concept_ordinal,
                        scope,
                        provenance,
                        require_factor=scope == "concept" or tax_type == "transferred",
                    )
                )
    return tuple(records)


def _normalize_one(
    element: ET.Element,
    tax_type: str,
    concept_ordinal: int | None,
    scope: str,
    provenance: str,
    *,
    require_factor: bool,
) -> TaxRecord:
    tax = _required_tax(element)
    factor = _factor(element, required=require_factor)
    return TaxRecord(
        tax_type=tax_type,
        tax=tax,
        factor_type=factor,
        rate_or_quota=_decimal(element, "TasaOCuota"),
        base=_decimal(element, "Base"),
        amount=_decimal(element, "Importe"),
        concept_ordinal=concept_ordinal,
        document_scope=scope,
        provenance=provenance,
    )


def _required_tax(element: ET.Element) -> str:
    value = element.attrib.get("Impuesto")
    if value is None or not value.strip():
        raise CfdiParseError("tax-attribute-missing")
    normalized = value.strip()
    if normalized not in _KNOWN_TAXES:
        raise CfdiParseError("tax-unknown")
    return normalized


def _factor(element: ET.Element, *, required: bool) -> str | None:
    value = element.attrib.get("TipoFactor")
    if value is None or not value.strip():
        if required:
            raise CfdiParseError("tax-factor-missing")
        return None
    normalized = _FACTOR_TYPES.get(value.strip().lower())
    if normalized is None:
        raise CfdiParseError("tax-factor-unknown")
    return normalized


def _decimal(element: ET.Element, name: str) -> Decimal | None:
    value = element.attrib.get(name)
    if value is None or not value.strip():
        return None
    try:
        parsed = Decimal(value.strip())
    except (InvalidOperation, ValueError):
        raise CfdiParseError("tax-decimal-invalid") from None
    if not parsed.is_finite():
        raise CfdiParseError("tax-decimal-invalid")
    if parsed < 0:
        raise CfdiParseError("tax-decimal-negative")
    return parsed


def _validate_provenance(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("tax-document-ref-required")
    if (
        not value
        or len(value) > _MAX_PROVENANCE_LENGTH
        or not _OPAQUE_REF.fullmatch(value)
        or _UUID_REF.fullmatch(value)
        or _RFC_REF.fullmatch(value)
        or _SAT_ID_REF.fullmatch(value)
        or value.isdecimal()
    ):
        raise ValueError("tax-document-ref-invalid")
    return value


def _decode_xml(xml_bytes: bytes) -> str:
    try:
        return xml_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise CfdiParseError("tax-xml-encoding-invalid") from None


def _reject_unsafe_declarations(xml_text: str) -> None:
    upper = xml_text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise CfdiParseError("tax-doctype-rejected")


def _parse_root(xml_text: str) -> ET.Element:
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
        raise CfdiParseError("tax-xml-invalid") from None


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _direct_children(element: ET.Element, local_name: str) -> tuple[ET.Element, ...]:
    return tuple(child for child in element if _local_name(child.tag) == local_name)
