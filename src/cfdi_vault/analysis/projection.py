"""Pure in-memory dispatch of one stored CFDI XML into analysis normalizers.

This module owns only the bounded handoff from already stored XML bytes to the
concept, tax, payment, and payroll normalizers.  It returns typed records and
aggregate parser evidence without writing PostgreSQL, publishing a queue job,
reading the filesystem, contacting SAT, or retaining raw XML.  The optional
dispatcher de-duplicates only for the lifetime of one process; durable
idempotency belongs to the database/worker boundary.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from cfdi_vault.analysis.normalization import ConceptRecord, normalize_concepts
from cfdi_vault.analysis.payments import PaymentRecord, normalize_payments
from cfdi_vault.analysis.payroll import PayrollRecord, normalize_payroll
from cfdi_vault.analysis.taxes import TaxRecord, normalize_taxes
from cfdi_vault.parser import CfdiParseError

__all__ = [
    "AccountingDispatch",
    "AccountingProjection",
    "AccountingProjectionDispatcher",
    "project_accounting_xml",
]

_PARSER_KEYS = ("concepts", "taxes", "payments", "payroll")
_PARSER_STATUSES = frozenset({"complete", "partial", "empty", "unsupported-error"})
_COMPLETENESS = frozenset({"complete", "partial", "empty", "unsupported"})
_OPAQUE_REF = re.compile(r"^[a-z][a-z0-9-]{0,31}-[0-9a-f]{16,64}$")
_IDEMPOTENCY_REF = re.compile(r"^accounting-v1-[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class AccountingProjection:
    """Typed records and redacted parser evidence for one XML document.

    ``source_ref`` and ``idempotency_key`` are deterministic SHA-256-derived
    opaque references available to a private caller.  The records and those
    references remain out of :meth:`as_dict`, which emits counts and statuses
    only.  No constructor or method stores the source bytes after the
    normalizers return.
    """

    source_ref: str
    idempotency_key: str
    concepts: tuple[ConceptRecord, ...]
    taxes: tuple[TaxRecord, ...]
    payments: tuple[PaymentRecord, ...]
    payroll: tuple[PayrollRecord, ...]
    parser_statuses: Mapping[str, str]
    record_counts: Mapping[str, int]
    completeness: str

    def __post_init__(self) -> None:
        if _OPAQUE_REF.fullmatch(self.source_ref) is None:
            raise ValueError("accounting-projection-source-ref-invalid")
        if _IDEMPOTENCY_REF.fullmatch(self.idempotency_key) is None:
            raise ValueError("accounting-projection-idempotency-key-invalid")
        for name in ("concepts", "taxes", "payments", "payroll"):
            values = getattr(self, name)
            if not isinstance(values, tuple):
                raise TypeError("accounting-projection-records-required")
        if not isinstance(self.parser_statuses, Mapping):
            raise TypeError("accounting-projection-statuses-required")
        statuses = dict(self.parser_statuses)
        if tuple(statuses) != _PARSER_KEYS or any(value not in _PARSER_STATUSES for value in statuses.values()):
            raise ValueError("accounting-projection-statuses-invalid")
        if not isinstance(self.record_counts, Mapping):
            raise TypeError("accounting-projection-counts-required")
        counts = dict(self.record_counts)
        if tuple(counts) != _PARSER_KEYS or any(type(value) is not int or value < 0 for value in counts.values()):
            raise ValueError("accounting-projection-counts-invalid")
        expected = {
            "concepts": len(self.concepts),
            "taxes": len(self.taxes),
            "payments": len(self.payments),
            "payroll": len(self.payroll),
        }
        if counts != expected:
            raise ValueError("accounting-projection-counts-mismatch")
        if self.completeness not in _COMPLETENESS:
            raise ValueError("accounting-projection-completeness-invalid")
        object.__setattr__(self, "parser_statuses", MappingProxyType(statuses))
        object.__setattr__(self, "record_counts", MappingProxyType(counts))

    def as_dict(self) -> dict[str, Any]:
        """Return only deterministic aggregate evidence, never parser rows."""

        return {
            "completeness": self.completeness,
            "parser_statuses": dict(self.parser_statuses),
            "record_counts": dict(self.record_counts),
        }

    def __repr__(self) -> str:
        """Return a representation that cannot expose XML-derived values."""

        return "AccountingProjection(<redacted>)"


@dataclass(frozen=True, slots=True)
class AccountingDispatch:
    """One in-memory dispatch result and whether it reused a prior projection."""

    projection: AccountingProjection
    duplicate: bool

    def __post_init__(self) -> None:
        if not isinstance(self.projection, AccountingProjection):
            raise TypeError("accounting-dispatch-projection-required")
        if type(self.duplicate) is not bool:
            raise TypeError("accounting-dispatch-duplicate-required")

    def as_dict(self) -> dict[str, Any]:
        """Return the projection aggregates plus a process-local duplicate flag."""

        values = self.projection.as_dict()
        values["duplicate"] = self.duplicate
        return values

    def __repr__(self) -> str:
        """Return a redacted representation without projection contents."""

        return "AccountingDispatch(<redacted>)"


class AccountingProjectionDispatcher:
    """De-duplicate projections in memory until this dispatcher is discarded.

    This cache is intentionally process-local and bounded by the number of
    distinct inputs handed to it.  It is a test/offline helper, not durable
    idempotency; the worker must persist the key before any external effect.
    """

    __slots__ = ("_projections",)

    def __init__(self) -> None:
        self._projections: dict[str, AccountingProjection] = {}

    def dispatch(self, xml_bytes: bytes) -> AccountingDispatch:
        """Normalize one XML value and reuse an identical prior result."""

        projection = project_accounting_xml(xml_bytes)
        previous = self._projections.get(projection.idempotency_key)
        if previous is not None:
            return AccountingDispatch(previous, True)
        self._projections[projection.idempotency_key] = projection
        return AccountingDispatch(projection, False)


def project_accounting_xml(xml_bytes: bytes) -> AccountingProjection:
    """Run all accounting normalizers over one stored XML byte sequence.

    Raises:
        TypeError: if ``xml_bytes`` is not ``bytes``.
        CfdiParseError: if the bytes are not strict UTF-8 or contain a
            ``DOCTYPE``/``ENTITY`` declaration; malformed or unsupported
            normalizer shapes use the normalizer's typed errors/statuses.
    """

    _validate_source(xml_bytes)
    digest = hashlib.sha256(xml_bytes).hexdigest()
    source_ref = f"xml-{digest[:24]}"
    idempotency_key = f"accounting-v1-{digest}"
    concepts = normalize_concepts(xml_bytes, document_ref=source_ref)
    taxes = normalize_taxes(xml_bytes, document_ref=source_ref)
    payments = normalize_payments(xml_bytes, document_ref=source_ref)
    payroll = normalize_payroll(xml_bytes, document_ref=source_ref)
    records = {
        "concepts": tuple(concepts.records),
        "taxes": tuple(taxes.records),
        "payments": tuple(payments.records),
        "payroll": tuple(payroll.records),
    }
    statuses = {
        "concepts": concepts.parser_status,
        "taxes": taxes.parser_status,
        "payments": payments.parser_status,
        "payroll": payroll.parser_status,
    }
    return AccountingProjection(
        source_ref=source_ref,
        idempotency_key=idempotency_key,
        concepts=records["concepts"],
        taxes=records["taxes"],
        payments=records["payments"],
        payroll=records["payroll"],
        parser_statuses=statuses,
        record_counts={name: len(values) for name, values in records.items()},
        completeness=_aggregate_completeness(statuses, records),
    )


def _validate_source(xml_bytes: bytes) -> None:
    if not isinstance(xml_bytes, bytes):
        raise TypeError("accounting-projection-xml-bytes-required")
    try:
        text = xml_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise CfdiParseError("accounting-projection-xml-encoding-invalid") from None
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise CfdiParseError("accounting-projection-unsafe-declaration")


def _aggregate_completeness(
    statuses: Mapping[str, str],
    records: Mapping[str, tuple[object, ...]],
) -> str:
    if any(status == "unsupported-error" for status in statuses.values()):
        return "unsupported"
    if any(status == "partial" for status in statuses.values()):
        return "partial"
    if not any(records.values()):
        return "empty"
    return "complete"
