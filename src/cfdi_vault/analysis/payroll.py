"""Strict, redacted normalization of CFDI ``Nomina`` complements.

Only period/type, direct totals, and child counts are exposed; identifiers,
raw payloads, persistence, SAT access, and fiscal classification are excluded.
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
SUPPORTED_PAYROLL_VERSIONS = frozenset({"1.1", "1.2"})
EXPECTED_PAYROLL_VERSIONS = {"3.2": "1.1", "3.3": "1.1", "4.0": "1.2"}
NOMINA_NAMESPACE = "http://www.sat.gob.mx/nomina"

_MAX_PROVENANCE_LENGTH = 128
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_UUID_REF = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
_RFC_REF = re.compile(r"^[A-Z&Ñ]{3,4}[0-9]{6}[A-Z0-9]{3}$", re.IGNORECASE)
_SAT_ID_REF = re.compile(
    r"^(?:SAT|IDSOLICITUD|IDPAQUETE|SOLICITUD|PAQUETE)[-_.:]?[A-Z0-9]+$",
    re.IGNORECASE,
)
_VERSION_PATTERN = re.compile(r"^\d{1,2}\.\d{1,2}$")


@dataclass(frozen=True)
class PayrollRecord:
    """One payroll complement with identifier-free numeric evidence."""

    payroll_type: str = field(repr=False)
    payment_date: datetime = field(repr=False)
    period_start: datetime = field(repr=False)
    period_end: datetime = field(repr=False)
    paid_days: Decimal | None = field(repr=False)
    total_perceptions: Decimal | None = field(repr=False)
    total_deductions: Decimal | None = field(repr=False)
    total_other_payments: Decimal | None = field(repr=False)
    perception_count: int
    deduction_count: int
    other_payment_count: int
    incomplete_count: int
    provenance: str = field(repr=False)

    def __repr__(self) -> str:
        """Return a representation that contains no fiscal details."""

        return "PayrollRecord(<redacted>)"

    def as_dict(self) -> dict[str, object]:
        """Return a safe aggregate projection without provenance."""

        return {
            "payroll_type": self.payroll_type,
            "payment_date": self.payment_date.isoformat(),
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "paid_days": _decimal_text(self.paid_days),
            "total_perceptions": _decimal_text(self.total_perceptions),
            "total_deductions": _decimal_text(self.total_deductions),
            "total_other_payments": _decimal_text(self.total_other_payments),
            "perception_count": self.perception_count,
            "deduction_count": self.deduction_count,
            "other_payment_count": self.other_payment_count,
            "incomplete_count": self.incomplete_count,
        }


@dataclass(frozen=True)
class PayrollNormalizationResult(Sequence[PayrollRecord]):
    """Normalized payroll records plus explicit version/status evidence."""

    records: tuple[PayrollRecord, ...]
    cfdi_version: str
    payroll_version: str | None
    namespace: str | None
    parser_status: str
    complement_present: bool

    def __iter__(self) -> Iterator[PayrollRecord]:
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, index: int | slice) -> PayrollRecord | tuple[PayrollRecord, ...]:
        return self.records[index]

    def __repr__(self) -> str:
        """Return a redacted representation with no payroll rows."""

        return (
            "PayrollNormalizationResult(records=<redacted>, "
            f"cfdi_version={self.cfdi_version!r}, payroll_version={self.payroll_version!r}, "
            f"parser_status={self.parser_status!r})"
        )

    def as_dict(self) -> dict[str, object]:
        """Return aggregate-safe metadata and records without source refs."""

        return {
            "cfdi_version": self.cfdi_version,
            "payroll_version": self.payroll_version,
            "namespace": self.namespace,
            "parser_status": self.parser_status,
            "complement_present": self.complement_present,
            "records": [record.as_dict() for record in self.records],
        }


def normalize_payroll(
    xml_bytes: bytes,
    *,
    document_ref: str = "document",
) -> PayrollNormalizationResult:
    """Normalize Nomina period, totals, and counts without retaining IDs.

    Unknown versions/namespaces, malformed XML, unsafe declarations, invalid
    dates/types, and non-finite/negative numbers never produce inferred rows.
    """

    if not isinstance(xml_bytes, bytes):
        raise TypeError("payroll-xml-bytes-required")
    provenance = _validate_provenance(document_ref)
    xml_text = _decode_xml(xml_bytes)
    _reject_unsafe_declarations(xml_text)
    root = _parse_root(xml_text)
    if _local_name(root.tag) != "Comprobante":
        raise CfdiParseError("payroll-root-invalid")

    cfdi_version = _safe_version(root.attrib.get("Version") or root.attrib.get("version"))
    if cfdi_version not in SUPPORTED_CFDI_VERSIONS:
        return PayrollNormalizationResult((), cfdi_version, None, None, PARSER_STATUS_UNSUPPORTED_ERROR, False)

    candidates = _find_nomina_candidates(root)
    if not candidates:
        unknown_business = any(
            _local_name(child.tag) != "TimbreFiscalDigital"
            for container in _direct_children(root, "Complemento")
            for child in container
        )
        status = PARSER_STATUS_PARTIAL if unknown_business else PARSER_STATUS_EMPTY
        return PayrollNormalizationResult((), cfdi_version, None, None, status, False)
    if len(candidates) > 1:
        return PayrollNormalizationResult((), cfdi_version, None, None, PARSER_STATUS_PARTIAL, True)

    nomina = candidates[0]
    namespace = _namespace(nomina.tag)
    payroll_version = _safe_version(nomina.attrib.get("Version") or nomina.attrib.get("version"))
    safe_namespace = NOMINA_NAMESPACE if namespace == NOMINA_NAMESPACE else "unknown"
    if namespace != NOMINA_NAMESPACE or payroll_version not in SUPPORTED_PAYROLL_VERSIONS:
        return PayrollNormalizationResult(
            (), cfdi_version, payroll_version, safe_namespace, PARSER_STATUS_UNSUPPORTED_ERROR, True
        )
    expected_version = EXPECTED_PAYROLL_VERSIONS[cfdi_version]
    if payroll_version != expected_version:
        return PayrollNormalizationResult(
            (), cfdi_version, payroll_version, safe_namespace, PARSER_STATUS_UNSUPPORTED_ERROR, True
        )
    known_child_names = {
        "Percepciones",
        "Deducciones",
        "OtrosPagos",
        "Incapacidades",
        "AccionesOT",
        "Emisor",
        "Receptor",
    }
    if any(
        _local_name(child.tag) in known_child_names and _namespace(child.tag) != NOMINA_NAMESPACE for child in nomina
    ):
        return PayrollNormalizationResult(
            (), cfdi_version, payroll_version, safe_namespace, PARSER_STATUS_UNSUPPORTED_ERROR, True
        )
    if any(len(_direct_children(nomina, name)) > 1 for name in ("Percepciones", "Deducciones", "OtrosPagos")):
        return PayrollNormalizationResult(
            (), cfdi_version, payroll_version, safe_namespace, PARSER_STATUS_PARTIAL, True
        )

    record = _normalize_record(nomina, provenance)
    allowed_children = {
        "Percepciones",
        "Deducciones",
        "OtrosPagos",
        "Incapacidades",
        "AccionesOT",
        "Emisor",
        "Receptor",
    }
    has_unknown_child = any(_local_name(child.tag) not in allowed_children for child in nomina)
    has_unknown_nested = _has_unknown_nested(nomina)
    status = PARSER_STATUS_COMPLETE
    if cfdi_version != "4.0" or record.incomplete_count or has_unknown_child or has_unknown_nested:
        status = PARSER_STATUS_PARTIAL
    return PayrollNormalizationResult((record,), cfdi_version, payroll_version, safe_namespace, status, True)


def _find_nomina_candidates(root: ET.Element) -> tuple[ET.Element, ...]:
    return tuple(
        child
        for container in _direct_children(root, "Complemento")
        for child in container
        if _local_name(child.tag) == "Nomina"
    )


def _normalize_record(nomina: ET.Element, provenance: str) -> PayrollRecord:
    payroll_type = _required_attr(nomina, "TipoNomina")
    if payroll_type not in {"O", "E"}:
        raise CfdiParseError("payroll-type-invalid")
    payment_date = _parse_date(_required_attr(nomina, "FechaPago"), "payroll-payment-date")
    period_start = _parse_date(_required_attr(nomina, "FechaInicialPago"), "payroll-period-start")
    period_end = _parse_date(_required_attr(nomina, "FechaFinalPago"), "payroll-period-end")
    if period_end < period_start:
        raise CfdiParseError("payroll-period-invalid")
    paid_days = _decimal(nomina.attrib.get("NumDiasPagados"), "payroll-paid-days")
    if paid_days is None:
        raise CfdiParseError("payroll-required-attribute-missing")

    perceptions = _single_child(nomina, "Percepciones")
    deductions = _single_child(nomina, "Deducciones")
    other_payments = _single_child(nomina, "OtrosPagos")
    perception_count, perception_missing = _child_amount_count(
        perceptions, "Percepcion", ("ImporteGravado", "ImporteExento")
    )
    deduction_count, deduction_missing = _child_amount_count(deductions, "Deduccion", ("Importe",))
    other_count, other_missing = _child_amount_count(other_payments, "OtroPago", ("Importe",))
    incomplete = perception_missing + deduction_missing + other_missing
    totals = {
        "total_perceptions": _decimal(nomina.attrib.get("TotalPercepciones"), "payroll-total-perceptions"),
        "total_deductions": _decimal(nomina.attrib.get("TotalDeducciones"), "payroll-total-deductions"),
        "total_other_payments": _decimal(nomina.attrib.get("TotalOtrosPagos"), "payroll-total-other-payments"),
    }
    for value in totals.values():
        if value is None:
            incomplete += 1
    return PayrollRecord(
        payroll_type=payroll_type,
        payment_date=payment_date,
        period_start=period_start,
        period_end=period_end,
        paid_days=paid_days,
        perception_count=perception_count,
        deduction_count=deduction_count,
        other_payment_count=other_count,
        incomplete_count=incomplete,
        provenance=provenance,
        **totals,
    )


def _single_child(element: ET.Element, local_name: str) -> ET.Element | None:
    children = _direct_children(element, local_name)
    return children[0] if children else None


def _child_amount_count(
    container: ET.Element | None,
    local_name: str,
    amount_names: tuple[str, ...],
) -> tuple[int, int]:
    if container is None:
        return 0, 0
    count = 0
    incomplete = 0
    for child in container:
        if _local_name(child.tag) != local_name:
            continue
        if _namespace(child.tag) != NOMINA_NAMESPACE:
            incomplete += 1
            continue
        count += 1
        for amount_name in amount_names:
            value = child.attrib.get(amount_name)
            if value is not None:
                _decimal(value, f"payroll-{local_name.lower()}-{amount_name.lower()}")
            elif local_name == "Percepcion":
                incomplete += 1
            else:
                incomplete += 1
    return count, incomplete


def _has_unknown_nested(nomina: ET.Element) -> bool:
    expected = {"Percepciones": "Percepcion", "Deducciones": "Deduccion", "OtrosPagos": "OtroPago"}
    return any(
        _local_name(child.tag) != child_name
        for container_name, child_name in expected.items()
        for container in _direct_children(nomina, container_name)
        for child in container
    )


def _required_attr(element: ET.Element, name: str) -> str:
    value = element.attrib.get(name)
    if value is None or not value.strip():
        raise CfdiParseError("payroll-required-attribute-missing")
    return value.strip()


def _safe_version(value: str | None) -> str:
    return value.strip() if isinstance(value, str) and _VERSION_PATTERN.fullmatch(value.strip()) else "unknown"


def _parse_date(value: str, field_name: str) -> datetime:
    if "T" not in value:
        raise CfdiParseError(f"{field_name}-invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise CfdiParseError(f"{field_name}-invalid") from None
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
        raise TypeError("payroll-document-ref-required")
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
        raise ValueError("payroll-document-ref-invalid")
    return value


def _decode_xml(xml_bytes: bytes) -> str:
    try:
        return xml_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise CfdiParseError("payroll-xml-encoding-invalid") from None


def _reject_unsafe_declarations(xml_text: str) -> None:
    upper = xml_text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise CfdiParseError("payroll-doctype-rejected")


def _parse_root(xml_text: str) -> ET.Element:
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError:
        raise CfdiParseError("payroll-xml-invalid") from None


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _namespace(tag: str) -> str | None:
    if "}" not in tag or not tag.startswith("{"):
        return None
    return tag[1:].split("}", 1)[0]


def _direct_children(element: ET.Element, local_name: str) -> tuple[ET.Element, ...]:
    return tuple(child for child in element if _local_name(child.tag) == local_name)


def _decimal_text(value: Decimal | None) -> str | None:
    return None if value is None else str(value)
