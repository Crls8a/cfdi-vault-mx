"""Internal mapper from redacted accounting intents to V5 child ledgers.

The mapper owns only deterministic DTO conversion and delegates one bounded
transaction to :class:`AccountingLedgerRepository`.  Parsing and artifact
storage must finish before this function is called.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cfdi_vault.accounting_ledger_v5 import (
    AccountingLedgerRepository,
    ConceptWrite,
    EvidenceRef,
    LedgerWriteCounts,
    PaymentWrite,
)
from cfdi_vault.accounting_ledger_worker import LedgerParseAggregate
from cfdi_vault.analysis.ledger_intent import LedgerWriteIntent


@dataclass(frozen=True, slots=True, repr=False)
class LedgerIntentMapping:
    """Sanitized mapper outcome suitable for a worker completion call."""

    aggregate: LedgerParseAggregate
    reason_code: str | None = None

    def as_dict(self) -> dict[str, object]:
        """Return fixed counters and an optional fixed omission reason."""

        result: dict[str, object] = {"aggregates": self.aggregate.as_dict()}
        if self.reason_code is not None:
            result["reason_code"] = self.reason_code
        return result

    def __repr__(self) -> str:
        return f"LedgerIntentMapping({self.as_dict()!r})"


class LedgerWriteIntentMapper:
    """Map one immutable intent using one transaction-scoped repository call."""

    def __init__(self, repository: AccountingLedgerRepository) -> None:
        if not callable(getattr(repository, "write_batch", None)):
            raise TypeError("ledger-v5-repository-required")
        self._repository = repository

    def map(
        self,
        intent: LedgerWriteIntent,
        *,
        tenant_id: str,
        document_id: int,
        source_evidence_id: int,
        parser_version: str,
    ) -> LedgerIntentMapping:
        """Persist one intent after parser/storage I/O has completed.

        ``tenant_id`` must be the same opaque tenant reference carried by the
        intent.  Related payment rows are omitted when source identity is not
        represented by the pure intent; no related UUID or parent id is
        synthesized.
        """

        if not isinstance(intent, LedgerWriteIntent):
            raise TypeError("ledger-v5-intent-required")
        if tenant_id != intent.context.tenant_ref:
            raise ValueError("ledger-v5-tenant-context-mismatch")

        concepts = tuple(ConceptWrite(EvidenceRef(**_provenance(intent, tenant_id, document_id, source_evidence_id, parser_version, "concept", row.idempotency_key)), row.ordinal, row.record.description, row.record.amount) for row in intent.concepts)
        taxes = tuple(
            _tax_values(intent, tenant_id, document_id, source_evidence_id, parser_version, row)
            for row in intent.taxes
        )
        payments = tuple(PaymentWrite(EvidenceRef(**_provenance(intent, tenant_id, document_id, source_evidence_id, parser_version, "payment", row.idempotency_key)), row.ordinal, row.record.currency, row.record.exchange_rate, row.record.amount) for row in intent.payments)
        payroll = tuple(
            _payroll_values(intent, tenant_id, document_id, source_evidence_id, parser_version, row)
            for row in intent.payroll
        )
        binding = EvidenceRef(
            **_provenance(intent, tenant_id, document_id, source_evidence_id, parser_version, "concept", intent.source.idempotency_key)
        )
        counts = self._repository.write_batch(concepts, taxes, payments, payroll, binding=binding)
        related_missing = sum(
            row.record.related_document_count
            for row in intent.payments
            if row.record.related_document_count is not None and row.record.related_document_count > 0
        )
        return LedgerIntentMapping(
            aggregate=_aggregate(intent, counts, related_missing),
            reason_code="related_identity_missing" if related_missing else None,
        )

    map_intent = map

    def map_aggregate(self, intent: LedgerWriteIntent, **kwargs: Any) -> LedgerParseAggregate:
        """Return only the aggregate accepted by ``LedgerWorker`` parsers."""

        return self.map(intent, **kwargs).aggregate


def map_ledger_write_intent(
    intent: LedgerWriteIntent,
    repository: AccountingLedgerRepository,
    *,
    tenant_id: str,
    document_id: int,
    source_evidence_id: int,
    parser_version: str,
) -> LedgerIntentMapping:
    """Functional adapter for worker parser callbacks and tests."""

    return LedgerWriteIntentMapper(repository).map(
        intent,
        tenant_id=tenant_id,
        document_id=document_id,
        source_evidence_id=source_evidence_id,
        parser_version=parser_version,
    )


def map_ledger_write_intent_aggregate(
    intent: LedgerWriteIntent, repository: AccountingLedgerRepository, **kwargs: Any
) -> LedgerParseAggregate:
    """Worker-facing adapter that strips the optional omission reason."""

    return LedgerWriteIntentMapper(repository).map_aggregate(intent, **kwargs)


def _provenance(
    intent: LedgerWriteIntent,
    tenant_id: str,
    document_id: int,
    source_evidence_id: int,
    parser_version: str,
    family: str,
    idempotency_key: str,
) -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "document_id": document_id,
        "source_evidence_id": source_evidence_id,
        "source_sha256": intent.source.source_sha256,
        "parser_version": parser_version,
        "parser_status": intent.source.parser_statuses[{"concept": "concepts", "tax": "taxes", "payment": "payments", "payroll": "payroll"}[family]],
        "normalization_generation": intent.normalization_generation,
        "idempotency_key": idempotency_key,
    }


def _tax_values(
    intent: LedgerWriteIntent,
    tenant_id: str,
    document_id: int,
    source_evidence_id: int,
    parser_version: str,
    row: Any,
) -> dict[str, Any]:
    return {
        **_provenance(intent, tenant_id, document_id, source_evidence_id, parser_version, "tax", row.idempotency_key),
        "source_ordinal": row.ordinal,
        "tax_type": row.record.tax_type,
        "scope": row.record.document_scope,
        "concept_ordinal": row.record.concept_ordinal,
        "amount": row.record.amount,
    }


def _payroll_values(
    intent: LedgerWriteIntent,
    tenant_id: str,
    document_id: int,
    source_evidence_id: int,
    parser_version: str,
    row: Any,
) -> dict[str, Any]:
    record = row.record
    return {
        **_provenance(intent, tenant_id, document_id, source_evidence_id, parser_version, "payroll", row.idempotency_key),
        "payroll_ordinal": row.ordinal,
        "total_perceptions": record.total_perceptions,
        "total_deductions": record.total_deductions,
        "total_other_payments": record.total_other_payments,
        # The source DTO does not expose a source net amount or currency.
        "source_net_amount": None,
        "currency": None,
        "source_period_type": None,
    }


def _aggregate(intent: LedgerWriteIntent, counts: LedgerWriteCounts, related_missing: int) -> LedgerParseAggregate:
    records_seen = sum(intent.source.record_counts.values())
    records_written = counts.concepts + counts.taxes + counts.payments + counts.payroll + counts.related
    return LedgerParseAggregate(
        records_seen=records_seen,
        records_written=records_written,
        duplicates=counts.duplicates,
        unknown=related_missing,
        concepts=counts.concepts,
        taxes=counts.taxes,
        payments=counts.payments,
        payroll=counts.payroll,
        related=counts.related,
    )


__all__ = [
    "LedgerIntentMapping",
    "LedgerWriteIntentMapper",
    "map_ledger_write_intent",
    "map_ledger_write_intent_aggregate",
]
