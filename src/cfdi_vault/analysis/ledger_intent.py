"""Pure, redacted write intents for a future normalized ledger mapper.

No SQL, storage, queue, SAT, XML, or raw payload side effects occur here.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, ClassVar, Generic, TypeVar

from cfdi_vault.analysis.normalization import ConceptRecord
from cfdi_vault.analysis.payments import PaymentRecord
from cfdi_vault.analysis.payroll import PayrollRecord
from cfdi_vault.analysis.projection import AccountingProjection
from cfdi_vault.analysis.taxes import TaxRecord

__all__ = [
    "ConceptLedgerIntent",
    "LedgerSourceEvidenceIntent",
    "LedgerWriteContext",
    "LedgerWriteIntent",
    "PayrollLedgerIntent",
    "PaymentLedgerIntent",
    "TaxLedgerIntent",
    "build_ledger_write_intent",
]

_SAFE_REF = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,63}$")
_GENERATION = re.compile(r"^[a-z][a-z0-9._-]{0,31}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
_RFC = re.compile(r"^[A-Z&Ñ]{3,4}[0-9]{6}[A-Z0-9]{3}$", re.IGNORECASE)
_SAT_ID = re.compile(r"^(?:SAT|IDSOLICITUD|IDPAQUETE|SOLICITUD|PAQUETE)[-_.:]?[A-Z0-9]+$", re.IGNORECASE)
_KEY_PREFIX = "ledger-v1-"
_FAMILIES = ("concepts", "taxes", "payments", "payroll")
_PARSER_STATUSES = frozenset({"complete", "partial", "empty", "unsupported-error"})
_T = TypeVar("_T", ConceptRecord, TaxRecord, PaymentRecord, PayrollRecord)


@dataclass(frozen=True, slots=True)
class LedgerWriteContext:
    """Opaque tenant/work scope supplied by an internal mapper."""

    tenant_ref: str
    work_ref: str

    def __post_init__(self) -> None:
        _validate_opaque_ref(self.tenant_ref)
        _validate_opaque_ref(self.work_ref)

    def __repr__(self) -> str:
        return "LedgerWriteContext(<redacted>)"


@dataclass(frozen=True, slots=True)
class LedgerSourceEvidenceIntent:
    """Private source-evidence anchor and aggregate parser evidence."""

    source_ref: str
    source_sha256: str
    parser_statuses: Mapping[str, str]
    record_counts: Mapping[str, int]
    completeness: str
    idempotency_key: str

    def __post_init__(self) -> None:
        _validate_source_ref(self.source_ref)
        if _SHA256.fullmatch(self.source_sha256) is None:
            raise ValueError("ledger-intent-source-hash-invalid")
        if self.source_ref != f"xml-{self.source_sha256[:24]}":
            raise ValueError("ledger-intent-source-ref-mismatch")
        _validate_key(self.idempotency_key)
        if not isinstance(self.parser_statuses, Mapping) or not isinstance(self.record_counts, Mapping):
            raise TypeError("ledger-intent-source-mappings-required")
        statuses = dict(self.parser_statuses)
        counts = dict(self.record_counts)
        if tuple(statuses) != _FAMILIES:
            raise ValueError("ledger-intent-statuses-invalid")
        if tuple(counts) != _FAMILIES or any(type(value) is not int or value < 0 for value in counts.values()):
            raise ValueError("ledger-intent-counts-invalid")
        if any(value not in _PARSER_STATUSES for value in statuses.values()):
            raise ValueError("ledger-intent-statuses-invalid")
        if self.completeness not in {"complete", "partial", "empty", "unsupported"}:
            raise ValueError("ledger-intent-completeness-invalid")
        _validate_evidence_consistency(self.completeness, statuses, counts)
        object.__setattr__(self, "parser_statuses", MappingProxyType(statuses))
        object.__setattr__(self, "record_counts", MappingProxyType(counts))

    def __repr__(self) -> str:
        return "LedgerSourceEvidenceIntent(<redacted>)"


@dataclass(frozen=True, slots=True)
class _FamilyLedgerIntent(Generic[_T]):
    record: _T
    ordinal: int
    idempotency_key: str

    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or self.ordinal <= 0:
            raise ValueError("ledger-intent-ordinal-invalid")
        _validate_key(self.idempotency_key)
        record_type = getattr(type(self), "_record_type", None)
        if record_type is not None and not isinstance(self.record, record_type):
            raise TypeError("ledger-intent-record-type-invalid")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ConceptLedgerIntent(_FamilyLedgerIntent[ConceptRecord]):
    """One concept-row write intent for a future mapper."""

    _record_type: ClassVar[type[ConceptRecord]] = ConceptRecord


@dataclass(frozen=True, slots=True, repr=False)
class TaxLedgerIntent(_FamilyLedgerIntent[TaxRecord]):
    """One tax-row write intent for a future mapper."""

    _record_type: ClassVar[type[TaxRecord]] = TaxRecord


@dataclass(frozen=True, slots=True, repr=False)
class PaymentLedgerIntent(_FamilyLedgerIntent[PaymentRecord]):
    """One payment-row write intent for a future mapper."""

    _record_type: ClassVar[type[PaymentRecord]] = PaymentRecord


@dataclass(frozen=True, slots=True, repr=False)
class PayrollLedgerIntent(_FamilyLedgerIntent[PayrollRecord]):
    """One payroll-row write intent for a future mapper."""

    _record_type: ClassVar[type[PayrollRecord]] = PayrollRecord


@dataclass(frozen=True, slots=True)
class LedgerWriteIntent:
    """Non-persistent typed write plan; internal rows and keys stay private."""

    context: LedgerWriteContext
    normalization_generation: str
    source: LedgerSourceEvidenceIntent
    concepts: tuple[ConceptLedgerIntent, ...]
    taxes: tuple[TaxLedgerIntent, ...]
    payments: tuple[PaymentLedgerIntent, ...]
    payroll: tuple[PayrollLedgerIntent, ...]
    completeness: str
    idempotency_key: str

    def __post_init__(self) -> None:
        if not isinstance(self.context, LedgerWriteContext):
            raise TypeError("ledger-intent-context-required")
        _validate_generation(self.normalization_generation)
        if not isinstance(self.source, LedgerSourceEvidenceIntent):
            raise TypeError("ledger-intent-source-required")
        family_types = {
            "concepts": ConceptLedgerIntent,
            "taxes": TaxLedgerIntent,
            "payments": PaymentLedgerIntent,
            "payroll": PayrollLedgerIntent,
        }
        actual_counts: dict[str, int] = {}
        for family, intent_type in family_types.items():
            values = getattr(self, family)
            if not isinstance(values, tuple):
                raise TypeError("ledger-intent-family-required")
            if any(not isinstance(value, intent_type) for value in values):
                raise TypeError("ledger-intent-family-type-invalid")
            actual_counts[family] = len(values)
        if dict(self.source.record_counts) != actual_counts:
            raise ValueError("ledger-intent-counts-mismatch")
        expected_source_key = _derive_key(
            self.context,
            self.source.source_sha256,
            self.normalization_generation,
            "source",
            0,
        )
        if self.source.idempotency_key != expected_source_key:
            raise ValueError("ledger-intent-source-key-mismatch")
        expected_batch_key = _derive_key(
            self.context,
            self.source.source_sha256,
            self.normalization_generation,
            "batch",
            0,
        )
        if self.idempotency_key != expected_batch_key:
            raise ValueError("ledger-intent-batch-key-mismatch")
        family_kinds = {
            "concepts": "concept",
            "taxes": "tax",
            "payments": "payment",
            "payroll": "payroll",
        }
        for family, kind in family_kinds.items():
            for value in getattr(self, family):
                expected_key = _derive_key(
                    self.context,
                    self.source.source_sha256,
                    self.normalization_generation,
                    kind,
                    value.ordinal,
                )
                if value.idempotency_key != expected_key:
                    raise ValueError("ledger-intent-family-key-mismatch")
        if self.completeness not in {"complete", "partial", "empty", "unsupported"}:
            raise ValueError("ledger-intent-completeness-invalid")
        if self.completeness != self.source.completeness:
            raise ValueError("ledger-intent-completeness-mismatch")
        _validate_key(self.idempotency_key)

    def as_dict(self) -> dict[str, Any]:
        return {
            "completeness": self.completeness,
            "parser_statuses": dict(self.source.parser_statuses),
            "record_counts": dict(self.source.record_counts),
        }

    def __repr__(self) -> str:
        return "LedgerWriteIntent(<redacted>)"


def build_ledger_write_intent(
    projection: AccountingProjection,
    *,
    context: LedgerWriteContext,
    normalization_generation: str,
) -> LedgerWriteIntent:
    """Build deterministic family intents without persistence or I/O."""

    if not isinstance(projection, AccountingProjection):
        raise TypeError("ledger-intent-projection-required")
    if not isinstance(context, LedgerWriteContext):
        raise TypeError("ledger-intent-context-required")
    _validate_generation(normalization_generation)
    source_sha256 = _projection_hash(projection)
    batch_key = _derive_key(context, source_sha256, normalization_generation, "batch", 0)
    source = LedgerSourceEvidenceIntent(
        source_ref=projection.source_ref,
        source_sha256=source_sha256,
        parser_statuses=projection.parser_statuses,
        record_counts=projection.record_counts,
        completeness=projection.completeness,
        idempotency_key=_derive_key(context, source_sha256, normalization_generation, "source", 0),
    )
    concepts = _family(
        projection.concepts,
        ConceptRecord,
        ConceptLedgerIntent,
        context,
        source_sha256,
        normalization_generation,
        "concept",
        ordinals=(record.ordinal for record in projection.concepts),
    )
    taxes = _family(
        projection.taxes,
        TaxRecord,
        TaxLedgerIntent,
        context,
        source_sha256,
        normalization_generation,
        "tax",
        ordinals=range(1, len(projection.taxes) + 1),
    )
    payments = _family(
        projection.payments,
        PaymentRecord,
        PaymentLedgerIntent,
        context,
        source_sha256,
        normalization_generation,
        "payment",
        ordinals=range(1, len(projection.payments) + 1),
    )
    payroll = _family(
        projection.payroll,
        PayrollRecord,
        PayrollLedgerIntent,
        context,
        source_sha256,
        normalization_generation,
        "payroll",
        ordinals=range(1, len(projection.payroll) + 1),
    )
    return LedgerWriteIntent(
        context=context,
        normalization_generation=normalization_generation,
        source=source,
        concepts=concepts,
        taxes=taxes,
        payments=payments,
        payroll=payroll,
        completeness=projection.completeness,
        idempotency_key=batch_key,
    )


def _family(
    records: tuple[_T, ...],
    record_type: type[_T],
    intent_type: type[_FamilyLedgerIntent[_T]],
    context: LedgerWriteContext,
    source_sha256: str,
    generation: str,
    kind: str,
    *,
    ordinals: Any,
) -> tuple[_FamilyLedgerIntent[_T], ...]:
    values = tuple(ordinals)
    if len(values) != len(records) or len(set(values)) != len(values):
        raise ValueError("ledger-intent-ordinal-duplicate")
    result: list[_FamilyLedgerIntent[_T]] = []
    for record, ordinal in zip(records, values, strict=True):
        if not isinstance(record, record_type):
            raise TypeError("ledger-intent-record-type-invalid")
        result.append(
            intent_type(
                record=record,
                ordinal=ordinal,
                idempotency_key=_derive_key(context, source_sha256, generation, kind, ordinal),
            )
        )
    return tuple(result)


def _projection_hash(projection: AccountingProjection) -> str:
    prefix = "accounting-v1-"
    value = projection.idempotency_key
    if not value.startswith(prefix):
        raise ValueError("ledger-intent-source-hash-invalid")
    source_hash = value[len(prefix) :]
    if _SHA256.fullmatch(source_hash) is None:
        raise ValueError("ledger-intent-source-hash-invalid")
    return source_hash


def _derive_key(context: LedgerWriteContext, source_sha256: str, generation: str, kind: str, ordinal: int) -> str:
    material = "\x1f".join((context.tenant_ref, context.work_ref, source_sha256, generation, kind, str(ordinal)))
    return _KEY_PREFIX + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _validate_generation(value: str) -> None:
    if not isinstance(value, str) or _GENERATION.fullmatch(value) is None:
        raise ValueError("ledger-intent-generation-required")


def _validate_opaque_ref(value: str) -> None:
    if (
        not isinstance(value, str)
        or _SAFE_REF.fullmatch(value) is None
        or value.isdecimal()
        or _UUID.fullmatch(value) is not None
        or _RFC.fullmatch(value) is not None
        or _SAT_ID.fullmatch(value) is not None
    ):
        raise ValueError("ledger-intent-context-invalid")


def _validate_source_ref(value: str) -> None:
    if not isinstance(value, str) or _SAFE_REF.fullmatch(value) is None:
        raise ValueError("ledger-intent-source-ref-invalid")


def _validate_evidence_consistency(
    completeness: str,
    statuses: Mapping[str, str],
    counts: Mapping[str, int],
) -> None:
    total = sum(counts.values())
    has_partial = any(value == "partial" for value in statuses.values())
    has_unsupported = any(value == "unsupported-error" for value in statuses.values())
    if completeness == "unsupported" and not has_unsupported:
        raise ValueError("ledger-intent-completeness-inconsistent")
    if completeness == "partial" and (not has_partial or has_unsupported):
        raise ValueError("ledger-intent-completeness-inconsistent")
    if completeness == "empty" and (total or has_partial or has_unsupported):
        raise ValueError("ledger-intent-completeness-inconsistent")
    if completeness == "complete" and (not total or has_partial or has_unsupported):
        raise ValueError("ledger-intent-completeness-inconsistent")


def _validate_key(value: str) -> None:
    suffix = value[len(_KEY_PREFIX) :] if isinstance(value, str) and value.startswith(_KEY_PREFIX) else ""
    if _SHA256.fullmatch(suffix) is None:
        raise ValueError("ledger-intent-idempotency-key-invalid")
