"""Internal SQLAlchemy V5 ledger writes and sanitized aggregate reads."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Callable

from sqlalchemy import Column, Integer, MetaData, Numeric, Select, String, Table, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

SessionFactory = Callable[[], AbstractContextManager[Session]]
_HEX = re.compile(r"^[0-9a-f]{64}$")
_GENERATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_V5_METADATA = MetaData()
# fmt: off
_PROVENANCE = (
    ("tenant_id", String(64)),
    ("source_evidence_id", Integer),
    ("source_sha256", String(64)),
    ("parser_version", String(32)),
    ("parser_status", String(32)),
    ("normalization_generation", String(64)),
    ("idempotency_key", String(192)),
)
_BINDING_FIELDS = ("tenant_id", "document_id", "source_evidence_id", "source_sha256", "parser_version")
def _table(name: str, extra: tuple[tuple[str, Any], ...]) -> Table:
    specs = (("id", Integer), ("document_id", Integer), *_PROVENANCE, *extra)
    return Table(name, _V5_METADATA, *(Column(column, typ) for column, typ in specs))
CONCEPTS = _table("cfdi_concepts", (("source_ordinal", Integer), ("description", String), ("amount", Numeric(18, 6))))
TAXES = _table(
    "cfdi_taxes",
    (
        ("tax_type", String(16)),
        ("concept_id", Integer),
        ("amount", Numeric(18, 6)),
        ("source_ordinal", Integer),
        ("scope", String(16)),
        ("concept_ordinal", Integer),
    ),
)
PAYMENTS = _table(
    "cfdi_payments",
    (
        ("amount", Numeric(18, 6)),
        ("currency", String(8)),
        ("payment_ordinal", Integer),
        ("exchange_rate", Numeric(18, 8)),
    ),
)
PAYROLL = _table(
    "cfdi_payroll",
    (
        ("payroll_ordinal", Integer),
        ("total_perceptions", Numeric(18, 6)),
        ("total_deductions", Numeric(18, 6)),
        ("total_other_payments", Numeric(18, 6)),
        ("source_net_amount", Numeric(18, 6)),
        ("currency", String(8)),
        ("source_period_type", String(32)),
    ),
)
RELATED = _table(
    "cfdi_related_documents",
    (
        ("related_ordinal", Integer),
        ("payment_ordinal", Integer),
        ("applied_amount", Numeric(18, 6)),
        ("installment_number", Integer),
        ("currency", String(8)),
        ("related_uuid", String(64)),
        ("relation_type", String(16)),
    ),
)
_DOCUMENTS = Table("cfdi_documents", _V5_METADATA, Column("id", Integer), Column("tenant_id", String(64)))
_EVIDENCE = Table(
    "xml_evidence",
    _V5_METADATA,
    Column("id", Integer),
    Column("tenant_id", String(64)),
    Column("xml_sha256", String(64)),
    Column("parser_version", String(32)),
)
def _text(value: str, error: str, limit: int = 192) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(error)
def _decimal(value: Decimal | None, error: str = "ledger-v5-decimal-invalid") -> None:
    if value is not None and (not isinstance(value, Decimal) or not value.is_finite()):
        raise ValueError(error)
def _ordinal(value: int, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise ValueError(f"ledger-v5-{name}-required")
class _Redacted:
    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"
@dataclass(frozen=True, slots=True, repr=False)
class EvidenceRef(_Redacted):
    tenant_id: str
    document_id: int
    source_evidence_id: int
    source_sha256: str
    parser_version: str
    parser_status: str
    normalization_generation: str
    idempotency_key: str
    def __post_init__(self) -> None:
        _text(self.tenant_id, "ledger-v5-tenant-required", 64)
        if type(self.document_id) is not int or self.document_id <= 0:
            raise ValueError("ledger-v5-document-required")
        if type(self.source_evidence_id) is not int or self.source_evidence_id <= 0:
            raise ValueError("ledger-v5-evidence-required")
        if _HEX.fullmatch(self.source_sha256) is None:
            raise ValueError("ledger-v5-source-hash-invalid")
        _text(self.parser_version, "ledger-v5-parser-version-required", 32)
        _text(self.parser_status, "ledger-v5-parser-status-required", 32)
        if _GENERATION.fullmatch(self.normalization_generation) is None:
            raise ValueError("ledger-v5-generation-invalid")
        _text(self.idempotency_key, "ledger-v5-idempotency-required")
def _validate_evidence(evidence: EvidenceRef, ordinal: int, name: str) -> None:
    if not isinstance(evidence, EvidenceRef):
        raise TypeError("ledger-v5-evidence-type-invalid")
    _ordinal(ordinal, name)
@dataclass(frozen=True, slots=True, repr=False)
class ConceptWrite(_Redacted):
    evidence: EvidenceRef
    source_ordinal: int
    description: str
    amount: Decimal | None = None
    raw_payload: object | None = field(default=None, repr=False)
    def __post_init__(self) -> None:
        _validate_evidence(self.evidence, self.source_ordinal, "ordinal")
        _text(self.description, "ledger-v5-description-required", 4096)
        _decimal(self.amount)
        if self.raw_payload is not None:
            raise ValueError("ledger-v5-raw-payload-forbidden")
    def values(self) -> dict[str, Any]:
        return _values(
            self.evidence, source_ordinal=self.source_ordinal, description=self.description, amount=self.amount
        )
@dataclass(frozen=True, slots=True, repr=False)
class TaxWrite(_Redacted):
    evidence: EvidenceRef
    source_ordinal: int
    tax_type: str
    scope: str
    concept_id: int | None = None
    concept_ordinal: int | None = None
    amount: Decimal | None = None
    def __post_init__(self) -> None:
        _validate_evidence(self.evidence, self.source_ordinal, "ordinal")
        _text(self.tax_type, "ledger-v5-tax-type-required", 16)
        _decimal(self.amount)
        valid = self.scope == "document" and self.concept_id is None and self.concept_ordinal is None
        valid |= (
            self.scope == "concept"
            and self.concept_id is not None
            and isinstance(self.concept_ordinal, int)
            and self.concept_ordinal > 0
        )
        if not valid:
            raise ValueError("ledger-v5-tax-scope-invalid")
    def values(self) -> dict[str, Any]:
        return _values(
            self.evidence,
            source_ordinal=self.source_ordinal,
            tax_type=self.tax_type,
            scope=self.scope,
            concept_id=self.concept_id,
            concept_ordinal=self.concept_ordinal,
            amount=self.amount,
        )
@dataclass(frozen=True, slots=True, repr=False)
class PaymentWrite(_Redacted):
    evidence: EvidenceRef
    payment_ordinal: int
    currency: str | None = None
    exchange_rate: Decimal | None = None
    amount: Decimal | None = None
    def __post_init__(self) -> None:
        _validate_evidence(self.evidence, self.payment_ordinal, "payment-ordinal")
        _decimal(self.amount)
        _decimal(self.exchange_rate)
        if self.currency == "MXN" and self.exchange_rate is not None:
            raise ValueError("ledger-v5-exchange-rate-forbidden")
        if self.currency not in (None, "MXN") and (self.exchange_rate is None or self.exchange_rate <= 0):
            raise ValueError("ledger-v5-exchange-rate-required")
    def values(self) -> dict[str, Any]:
        return _values(
            self.evidence,
            payment_ordinal=self.payment_ordinal,
            currency=self.currency,
            exchange_rate=self.exchange_rate,
            amount=self.amount,
        )
def _values(evidence: EvidenceRef, **extra: Any) -> dict[str, Any]:
    return {
        "tenant_id": evidence.tenant_id,
        "document_id": evidence.document_id,
        "source_evidence_id": evidence.source_evidence_id,
        "source_sha256": evidence.source_sha256,
        "parser_version": evidence.parser_version,
        "parser_status": evidence.parser_status,
        "normalization_generation": evidence.normalization_generation,
        "idempotency_key": evidence.idempotency_key,
        **extra,
    }
def aggregate_statement(tenant_id: str) -> Select[Any]:
    _text(tenant_id, "ledger-v5-tenant-required", 64)
    def metric(table: Table, column: str, total: bool = False) -> Any:
        return (
            select(func.coalesce(func.sum(table.c[column]), 0) if total else func.count(table.c.id))
            .where(table.c.tenant_id == tenant_id)
            .scalar_subquery()
        )
    return select(
        *(
            metric(table, "id").label(f"{name}_count")
            for name, table in (
                ("concept", CONCEPTS),
                ("tax", TAXES),
                ("payment", PAYMENTS),
                ("payroll", PAYROLL),
                ("related", RELATED),
            )
        ),
        metric(TAXES, "amount", True).label("tax_amount"),
        metric(PAYMENTS, "amount", True).label("payment_amount"),
        metric(PAYROLL, "source_net_amount", True).label("source_net_amount"),
    )
@dataclass(frozen=True, slots=True, repr=False)
class LedgerAggregate(_Redacted):
    concept_count: int = 0
    tax_count: int = 0
    payment_count: int = 0
    payroll_count: int = 0
    related_count: int = 0
    tax_amount: Decimal = Decimal(0)
    payment_amount: Decimal = Decimal(0)
    source_net_amount: Decimal = Decimal(0)


@dataclass(frozen=True, slots=True, repr=False)
class LedgerWriteCounts(_Redacted):
    """Sanitized row-write counters returned by one V5 transaction."""

    concepts: int = 0
    taxes: int = 0
    payments: int = 0
    payroll: int = 0
    related: int = 0
    duplicates: int = 0
class AccountingLedgerRepository:
    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory
    def _insert(self, table: Table, values: dict[str, Any], identity: list[str], index_where: Any = None) -> bool:
        statement = (
            pg_insert(table)
            .values(values)
            .on_conflict_do_nothing(index_elements=[table.c[name] for name in identity], index_where=index_where)
        )
        with self._session_factory() as session:
            try:
                result = session.execute(statement)
                session.commit()
                return getattr(result, "rowcount", 1) != 0
            except Exception:
                session.rollback()
                raise

    @staticmethod
    def _insert_in_session(
        session: Session,
        table: Table,
        values: dict[str, Any],
        identity: list[str],
        index_where: Any = None,
    ) -> bool:
        """Insert one row without opening or committing a nested transaction."""

        statement = (
            pg_insert(table)
            .values(values)
            .on_conflict_do_nothing(index_elements=[table.c[name] for name in identity], index_where=index_where)
        )
        result = session.execute(statement)
        return getattr(result, "rowcount", 1) != 0

    def write_batch(
        self,
        concepts: Sequence[ConceptWrite],
        taxes: Sequence[Mapping[str, Any]],
        payments: Sequence[PaymentWrite],
        payroll: Sequence[Mapping[str, Any]],
        related: Sequence[Mapping[str, Any]] = (),
        *,
        binding: EvidenceRef | None = None,
    ) -> LedgerWriteCounts:
        """Write one document's child rows in exactly one short transaction.

        The caller supplies already redacted, provenance-bound values. Concept
        ids for concept-scoped tax rows are resolved inside this transaction;
        no parser or artifact I/O may occur while the session is open.
        """

        concept_rows = tuple(concepts)
        tax_rows = tuple(taxes)
        payment_rows = tuple(payments)
        payroll_rows = tuple(payroll)
        related_rows = tuple(related)
        if any(not isinstance(row, ConceptWrite) for row in concept_rows):
            raise TypeError("ledger-v5-concepts-required")
        if any(not isinstance(row, PaymentWrite) for row in payment_rows):
            raise TypeError("ledger-v5-payments-required")
        if binding is not None and not isinstance(binding, EvidenceRef):
            raise TypeError("ledger-v5-evidence-type-invalid")

        written = {name: 0 for name in ("concepts", "taxes", "payments", "payroll", "related")}
        duplicates = 0
        with self._session_factory() as session:
            try:
                binding = binding or _first_evidence(concept_rows, payment_rows, tax_rows, payroll_rows)
                if binding is None:
                    raise ValueError("ledger-v5-provenance-binding-invalid")
                _validate_batch_provenance(binding, concept_rows, payment_rows, tax_rows, payroll_rows)
                _verify_provenance_binding(session, binding)
                for row in concept_rows:
                    inserted = self._insert_in_session(
                        session,
                        CONCEPTS,
                        row.values(),
                        ["tenant_id", "document_id", "source_sha256", "normalization_generation", "source_ordinal"],
                    )
                    written["concepts"] += int(inserted)
                    duplicates += int(not inserted)

                concept_ids: dict[int, int] = {}
                concept_ordinals = {
                    value.get("concept_ordinal")
                    for value in tax_rows
                    if value.get("scope") == "concept" and value.get("concept_ordinal") is not None
                }
                if concept_ordinals:
                    first = concept_rows[0] if concept_rows else None
                    if first is None:
                        raise ValueError("ledger-v5-concept-not-found")
                    evidence = first.evidence
                    result = session.execute(
                        select(CONCEPTS.c.id, CONCEPTS.c.source_ordinal).where(
                            CONCEPTS.c.tenant_id == evidence.tenant_id,
                            CONCEPTS.c.document_id == evidence.document_id,
                            CONCEPTS.c.source_sha256 == evidence.source_sha256,
                            CONCEPTS.c.source_evidence_id == evidence.source_evidence_id,
                            CONCEPTS.c.normalization_generation == evidence.normalization_generation,
                            CONCEPTS.c.source_ordinal.in_(concept_ordinals),
                        )
                    )
                    rows = result.all() if hasattr(result, "all") else ()
                    for row in rows:
                        mapping = getattr(row, "_mapping", row)
                        concept_ids[mapping["source_ordinal"]] = mapping["id"]

                for value in tax_rows:
                    clean = dict(value)
                    if clean.get("scope") == "concept":
                        concept_id = concept_ids.get(clean.get("concept_ordinal"))
                        if concept_id is None:
                            raise ValueError("ledger-v5-concept-not-found")
                        clean["concept_id"] = concept_id
                    clean = _mapping_values(clean, TAXES, "source_ordinal")
                    identity = [
                        "tenant_id",
                        "document_id",
                        "source_sha256",
                        "normalization_generation",
                        "source_ordinal",
                    ]
                    if clean.get("scope") == "concept":
                        identity.insert(-1, "concept_ordinal")
                    inserted = self._insert_in_session(session, TAXES, clean, identity, _scope_predicate(clean["scope"]))
                    written["taxes"] += int(inserted)
                    duplicates += int(not inserted)

                for row in payment_rows:
                    inserted = self._insert_in_session(
                        session,
                        PAYMENTS,
                        row.values(),
                        ["tenant_id", "document_id", "source_sha256", "normalization_generation", "payment_ordinal"],
                    )
                    written["payments"] += int(inserted)
                    duplicates += int(not inserted)

                for value in payroll_rows:
                    clean = _mapping_values(value, PAYROLL, "payroll_ordinal")
                    inserted = self._insert_in_session(
                        session,
                        PAYROLL,
                        clean,
                        ["tenant_id", "document_id", "source_sha256", "normalization_generation", "payroll_ordinal"],
                    )
                    written["payroll"] += int(inserted)
                    duplicates += int(not inserted)

                for value in related_rows:
                    clean = _mapping_values(value, RELATED, "related_ordinal")
                    identity = [
                        "tenant_id",
                        "document_id",
                        "source_sha256",
                        "normalization_generation",
                        "related_ordinal",
                    ]
                    scoped = clean.get("payment_ordinal") is not None
                    if scoped:
                        identity.insert(-1, "payment_ordinal")
                    inserted = self._insert_in_session(
                        session,
                        RELATED,
                        clean,
                        identity,
                        RELATED.c.payment_ordinal.is_not(None) if scoped else RELATED.c.payment_ordinal.is_(None),
                    )
                    written["related"] += int(inserted)
                    duplicates += int(not inserted)
                session.commit()
            except Exception:
                session.rollback()
                raise
        return LedgerWriteCounts(**written, duplicates=duplicates)

    def write_intent(
        self,
        concepts: Sequence[ConceptWrite],
        taxes: Sequence[Mapping[str, Any]],
        payments: Sequence[PaymentWrite],
        payroll: Sequence[Mapping[str, Any]],
        related: Sequence[Mapping[str, Any]] = (),
        *,
        binding: EvidenceRef | None = None,
    ) -> LedgerWriteCounts:
        """Compatibility name for the transaction-scoped batch surface."""

        return self.write_batch(concepts, taxes, payments, payroll, related, binding=binding)

    def insert_concept(self, row: ConceptWrite) -> bool:
        return self._insert(
            CONCEPTS,
            row.values(),
            ["tenant_id", "document_id", "source_sha256", "normalization_generation", "source_ordinal"],
        )
    def insert_tax(self, row: TaxWrite) -> bool:
        identity = ["tenant_id", "document_id", "source_sha256", "normalization_generation", "source_ordinal"]
        if row.scope == "concept":
            identity.insert(-1, "concept_ordinal")
        return self._insert(TAXES, row.values(), identity, _scope_predicate(row.scope))
    def insert_payment(self, row: PaymentWrite) -> bool:
        return self._insert(
            PAYMENTS,
            row.values(),
            ["tenant_id", "document_id", "source_sha256", "normalization_generation", "payment_ordinal"],
        )
    def insert_payroll(self, values: Mapping[str, Any]) -> bool:
        return self._insert(
            PAYROLL,
            _mapping_values(values, PAYROLL, "payroll_ordinal"),
            ["tenant_id", "document_id", "source_sha256", "normalization_generation", "payroll_ordinal"],
        )
    def insert_related(self, values: Mapping[str, Any]) -> bool:
        clean = _mapping_values(values, RELATED, "related_ordinal")
        identity = ["tenant_id", "document_id", "source_sha256", "normalization_generation", "related_ordinal"]
        scoped = clean.get("payment_ordinal") is not None
        if scoped:
            identity.insert(-1, "payment_ordinal")
        return self._insert(
            RELATED,
            clean,
            identity,
            RELATED.c.payment_ordinal.is_not(None) if scoped else RELATED.c.payment_ordinal.is_(None),
        )
    def aggregate(self, tenant_id: str) -> LedgerAggregate:
        with self._session_factory() as session:
            row = session.execute(aggregate_statement(tenant_id)).one()
        mapping = getattr(row, "_mapping", row)
        return LedgerAggregate(**{name: mapping[name] or 0 for name in LedgerAggregate.__dataclass_fields__})


def _scope_predicate(scope: str) -> Any:
    if scope == "concept":
        return TAXES.c.scope == "concept"
    if scope == "document":
        return TAXES.c.scope == "document"
    raise ValueError("ledger-v5-tax-scope-invalid")


def _first_evidence(
    concepts: Sequence[ConceptWrite],
    payments: Sequence[PaymentWrite],
    taxes: Sequence[Mapping[str, Any]],
    payroll: Sequence[Mapping[str, Any]],
) -> EvidenceRef | None:
    if concepts:
        return concepts[0].evidence
    if payments:
        return payments[0].evidence
    for values in (*taxes, *payroll):
        try:
            return EvidenceRef(
                **({name: values[name] for name, _ in _PROVENANCE} | {"document_id": values["document_id"]})
            )
        except (KeyError, TypeError, ValueError):
            continue
    return None


def _validate_batch_provenance(
    binding: EvidenceRef,
    concepts: Sequence[ConceptWrite],
    payments: Sequence[PaymentWrite],
    taxes: Sequence[Mapping[str, Any]],
    payroll: Sequence[Mapping[str, Any]],
) -> None:
    expected = tuple(getattr(binding, name) for name in _BINDING_FIELDS)
    values: list[tuple[Any, ...]] = [
        tuple(getattr(row.evidence, name) for name in _BINDING_FIELDS) for row in (*concepts, *payments)
    ]
    values.extend(tuple(row.get(name) for name in _BINDING_FIELDS) for row in (*taxes, *payroll))
    if any(value != expected for value in values):
        raise ValueError("ledger-v5-provenance-binding-invalid")


def _verify_provenance_binding(session: Session, binding: EvidenceRef) -> None:
    statement = (
        select(_DOCUMENTS.c.id)
        .select_from(_DOCUMENTS.join(_EVIDENCE, _EVIDENCE.c.tenant_id == _DOCUMENTS.c.tenant_id))
        .where(
            _DOCUMENTS.c.id == binding.document_id,
            _DOCUMENTS.c.tenant_id == binding.tenant_id,
            _EVIDENCE.c.id == binding.source_evidence_id,
            _EVIDENCE.c.tenant_id == binding.tenant_id,
            _EVIDENCE.c.xml_sha256 == binding.source_sha256,
            _EVIDENCE.c.parser_version == binding.parser_version,
        )
    )
    result = session.execute(statement)
    if not hasattr(result, "first") or result.first() is None:
        raise ValueError("ledger-v5-provenance-binding-invalid")


def _mapping_values(values: Mapping[str, Any], table: Table, ordinal: str) -> dict[str, Any]:
    if not isinstance(values, Mapping):
        raise TypeError("ledger-v5-values-required")
    if "raw_payload" in values:
        raise ValueError("ledger-v5-raw-payload-forbidden")
    if "id" in values or any(key not in table.c for key in values):
        raise ValueError("ledger-v5-field-forbidden")
    required = {name for name, _ in _PROVENANCE} | {"document_id", ordinal}
    if any(name not in values for name in required):
        raise ValueError("ledger-v5-field-required")
    for name in (ordinal, "payment_ordinal", "installment_number"):
        if values.get(name) is not None:
            _ordinal(values[name], name.replace("_", "-"))
    EvidenceRef(
        **{name: values[name] for name, _ in _PROVENANCE if name != "parser_status"}
        | {
            "parser_status": values["parser_status"],
            "document_id": values["document_id"],
            "source_evidence_id": values["source_evidence_id"],
        }
    )
    for name in (
        "amount",
        "exchange_rate",
        "total_perceptions",
        "total_deductions",
        "total_other_payments",
        "source_net_amount",
        "applied_amount",
    ):
        _decimal(values.get(name))
    if table is TAXES:
        scope = values.get("scope")
        if scope not in {"concept", "document"}:
            raise ValueError("ledger-v5-tax-scope-invalid")
        concept_id = values.get("concept_id")
        concept_ordinal = values.get("concept_ordinal")
        if scope == "concept":
            if type(concept_id) is not int or concept_id <= 0 or type(concept_ordinal) is not int or concept_ordinal <= 0:
                raise ValueError("ledger-v5-tax-scope-invalid")
        elif concept_id is not None or concept_ordinal is not None:
            raise ValueError("ledger-v5-tax-scope-invalid")
    if table is RELATED:
        _text(values.get("related_uuid"), "ledger-v5-related-identity-required", 64)
    return dict(values)
