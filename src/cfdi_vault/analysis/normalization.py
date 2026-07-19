"""Pure, bounded normalization of CFDI concept lines.

The module owns only in-memory extraction of direct ``Conceptos/Concepto``
children.  It does not read artifacts, persist rows, contact SAT, inspect
parties, or infer tax/complement semantics.  Unknown CFDI versions and
business complements remain explicitly partial instead of being guessed.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation

from cfdi_vault.parser import CfdiParseError

PARSER_STATUS_COMPLETE = "complete"
PARSER_STATUS_PARTIAL = "partial"
PARSER_STATUS_UNSUPPORTED_ERROR = "unsupported-error"
SUPPORTED_CFDI_VERSIONS = frozenset({"3.2", "3.3", "4.0"})
_MAX_PROVENANCE_LENGTH = 128
_MAX_TEXT_LENGTH = 4096
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UUID_REF = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
_RFC_REF = re.compile(r"^[A-Z&Ñ]{3,4}[0-9]{6}[A-Z0-9]{3}$", re.IGNORECASE)
_SAT_ID_REF = re.compile(r"^(?:SAT|IDSOLICITUD|IDPAQUETE|SOLICITUD|PAQUETE)[-_.:]?[A-Z0-9]+$", re.IGNORECASE)
_STAMP_COMPLEMENT = "TimbreFiscalDigital"


@dataclass(frozen=True)
class ConceptRecord:
    """One sanitized CFDI concept line.

    ``provenance`` is an opaque caller-supplied reference only; it is not
    copied from the XML and must not contain an RFC, UUID, path, or SAT id.
    Monetary and quantity values remain ``Decimal`` instances so no binary
    floating-point rounding is introduced.
    """

    product_service_key: str = field(repr=False)
    unit_key: str = field(repr=False)
    description: str = field(repr=False)
    quantity: Decimal = field(repr=False)
    unit_value: Decimal = field(repr=False)
    amount: Decimal = field(repr=False)
    discount: Decimal | None = field(repr=False)
    tax_object: str = field(repr=False)
    ordinal: int
    provenance: str = field(repr=False)


@dataclass(frozen=True)
class ConceptNormalizationResult(Sequence[ConceptRecord]):
    """Normalized concepts plus version/status evidence.

    The sequence behavior keeps callers that only need records convenient,
    while ``version`` and ``parser_status`` prevent an empty result from being
    mistaken for a successfully parsed document.
    """

    records: tuple[ConceptRecord, ...]
    version: str
    parser_status: str

    def __iter__(self) -> Iterator[ConceptRecord]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int | slice) -> ConceptRecord | tuple[ConceptRecord, ...]:
        return self.records[index]


def normalize_concepts(
    xml_bytes: bytes,
    *,
    document_ref: str = "document",
) -> ConceptNormalizationResult:
    """Extract direct CFDI concept lines from XML held in memory.

    Version ``4.0`` is the only complete contract.  Known older versions are
    returned as ``partial`` without inference; unknown or missing versions are
    returned as ``unsupported-error`` with no records.  Unknown direct business
    complements downgrade the result to ``partial`` but never alter concepts.

    Raises:
        TypeError: if XML or the provenance reference has the wrong type.
        CfdiParseError: for unsafe declarations, malformed XML, invalid root,
            missing required concept attributes, invalid decimals, or negative
            values.
    """

    if not isinstance(xml_bytes, bytes):
        raise TypeError("concept-xml-bytes-required")
    provenance = _validate_provenance(document_ref)
    xml_text = _decode_xml(xml_bytes)
    _reject_unsafe_declarations(xml_text)
    root = _parse_root(xml_text)
    if _local_name(root.tag) != "Comprobante":
        raise CfdiParseError("concept-root-invalid")

    version = root.attrib.get("Version") or root.attrib.get("version") or "unknown"
    if version not in SUPPORTED_CFDI_VERSIONS:
        return ConceptNormalizationResult((), version, PARSER_STATUS_UNSUPPORTED_ERROR)
    if version != "4.0":
        return ConceptNormalizationResult((), version, PARSER_STATUS_PARTIAL)

    records: list[ConceptRecord] = []
    ordinal = 0
    for concepts in _direct_children(root, "Conceptos"):
        for concept in _direct_children(concepts, "Concepto"):
            ordinal += 1
            records.append(_normalize_one(concept, ordinal, provenance))

    has_business_complement = any(
        _local_name(child.tag) != _STAMP_COMPLEMENT
        for container in _direct_children(root, "Complemento")
        for child in container
    )
    status = PARSER_STATUS_PARTIAL if has_business_complement else PARSER_STATUS_COMPLETE
    return ConceptNormalizationResult(tuple(records), version, status)


def _normalize_one(element: ET.Element, ordinal: int, provenance: str) -> ConceptRecord:
    return ConceptRecord(
        product_service_key=_required_text(element, "ClaveProdServ"),
        unit_key=_required_text(element, "ClaveUnidad"),
        description=_required_text(element, "Descripcion"),
        quantity=_decimal(element, "Cantidad", required=True),
        unit_value=_decimal(element, "ValorUnitario", required=True),
        amount=_decimal(element, "Importe", required=True),
        discount=_decimal(element, "Descuento", required=False),
        tax_object=_required_text(element, "ObjetoImp"),
        ordinal=ordinal,
        provenance=provenance,
    )


def _required_text(element: ET.Element, name: str) -> str:
    value = element.attrib.get(name)
    if value is None or not value.strip():
        raise CfdiParseError("concept-required-attribute-missing")
    normalized = value.strip()
    if len(normalized) > _MAX_TEXT_LENGTH:
        raise CfdiParseError("concept-text-too-long")
    return normalized


def _decimal(element: ET.Element, name: str, *, required: bool) -> Decimal | None:
    value = element.attrib.get(name)
    if value is None or not value.strip():
        if required:
            raise CfdiParseError("concept-required-attribute-missing")
        return None
    try:
        parsed = Decimal(value.strip())
    except (InvalidOperation, ValueError):
        raise CfdiParseError("concept-decimal-invalid") from None
    if not parsed.is_finite():
        raise CfdiParseError("concept-decimal-invalid")
    if parsed < 0:
        raise CfdiParseError("concept-decimal-negative")
    return parsed


def _validate_provenance(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("concept-document-ref-required")
    if (
        not value
        or len(value) > _MAX_PROVENANCE_LENGTH
        or not _OPAQUE_REF.fullmatch(value)
        or "/" in value
        or "\\" in value
        or re.match(r"^[A-Za-z]:", value)
        or _UUID_REF.fullmatch(value)
        or _RFC_REF.fullmatch(value)
        or value.isdecimal()
        or _SAT_ID_REF.fullmatch(value)
    ):
        raise ValueError("concept-document-ref-invalid")
    return value


def _decode_xml(xml_bytes: bytes) -> str:
    try:
        return xml_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise CfdiParseError("concept-xml-encoding-invalid") from None


def _reject_unsafe_declarations(xml_text: str) -> None:
    upper = xml_text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise CfdiParseError("concept-doctype-rejected")


def _parse_root(xml_text: str) -> ET.Element:
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
        raise CfdiParseError("concept-xml-invalid") from None


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _direct_children(element: ET.Element, local_name: str) -> tuple[ET.Element, ...]:
    return tuple(child for child in element if _local_name(child.tag) == local_name)
