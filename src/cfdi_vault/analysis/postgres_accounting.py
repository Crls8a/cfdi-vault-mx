"""Read-only PostgreSQL inputs for private accounting analysis.

This adapter reads tenant/evidence-bound V5 child tables without writing state,
reading artifact bytes, contacting SAT, or exposing source identifiers.  The
current write model does not retain every analytical dimension, so those gaps
are returned as explicit ``partial`` evidence rather than inferred values.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Generic, TypeVar

from sqlalchemy import Select, Table, and_, literal, select
from sqlalchemy.orm import Session

from cfdi_vault.accounting_ledger_v5 import PAYMENTS, PAYROLL, TAXES
from cfdi_vault.analysis.payments import PaymentRecord
from cfdi_vault.analysis.postgres_payroll import PayrollReadRow
from cfdi_vault.analysis.postgres_quality import quality_observations_statement
from cfdi_vault.analysis.quality import QualityObservation
from cfdi_vault.analysis.quality_context import QualityAnalysisRecord
from cfdi_vault.analysis.taxes import TaxRecord
from cfdi_vault.recovery_db import CfdiDocument, XmlEvidence

SessionFactory = Callable[[], Session]
_PROVENANCE = "postgres-row"
_T = TypeVar("_T")
_PARSER_STATUSES = frozenset({"complete", "partial", "empty", "unsupported"})
_UTC = timezone.utc
_TAX_UNAVAILABLE = ("tax", "factor_type", "base", "rate_or_quota")
_PAYMENT_UNAVAILABLE = ("payment_date", "payment_form", "related_document_identity")
_PAYROLL_UNAVAILABLE = (
    "payroll_type",
    "payment_date",
    "period_start",
    "period_end",
    "paid_days",
    "perception_count",
    "deduction_count",
    "other_payment_count",
    "source_net_amount",
    "currency",
    "source_period_type",
)


@dataclass(frozen=True, slots=True)
class AccountingReadResult(Sequence[_T], Generic[_T]):
    """Aggregate-safe rows plus parser completeness evidence.

    The sequence contains only normalized DTOs, never identifiers or source
    payloads.  ``unavailable_fields`` documents analytical columns missing
    from the current schema; ``money_available`` is false for payroll because
    its source net amount and currency are not durable in the V5 write model.
    """

    rows: tuple[_T, ...]
    parser_status: str
    unavailable_fields: tuple[str, ...] = ()
    money_available: bool = True

    def __post_init__(self) -> None:
        if self.parser_status not in _PARSER_STATUSES:
            raise ValueError("analysis-source-status-invalid")
        if type(self.rows) is not tuple:
            raise TypeError("analysis-rows-required")
        if type(self.unavailable_fields) is not tuple or any(
            not isinstance(value, str) or not value for value in self.unavailable_fields
        ):
            raise TypeError("analysis-unavailable-fields-invalid")
        if type(self.money_available) is not bool:
            raise TypeError("analysis-money-availability-invalid")

    @property
    def source_status(self) -> str:
        """Return the parser status under the accounting-report name."""

        return self.parser_status

    def __iter__(self) -> Iterator[_T]:
        return iter(self.rows)

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int | slice) -> _T | tuple[_T, ...]:
        return self.rows[index]

    def __repr__(self) -> str:
        """Avoid exposing rows or schema field values in diagnostics."""

        return (
            "AccountingReadResult(<redacted>, "
            f"parser_status={self.parser_status!r}, money_available={self.money_available!r})"
        )


def tax_records_statement(
    tenant_id: str,
    *,
    start: date | None = None,
    end: date | None = None,
) -> Select[tuple[Any, ...]]:
    """Build a tenant/evidence-bound V5 tax read using parent issue date."""

    return _child_statement(
        TAXES,
        tenant_id,
        start=start,
        end=end,
        extra=(TAXES.c.scope.is_not(None),),
        columns=(
            TAXES.c.tax_type.label("tax_type"),
            literal("UNKNOWN").label("tax"),
            literal(None).label("factor_type"),
            literal(None).label("rate_or_quota"),
            literal(None).label("base"),
            TAXES.c.amount.label("amount"),
            TAXES.c.scope.label("document_scope"),
            TAXES.c.concept_ordinal.label("concept_ordinal"),
            TAXES.c.parser_status.label("parser_status"),
        ),
        order=(TAXES.c.source_ordinal, TAXES.c.id),
    )


def payment_records_statement(
    tenant_id: str,
    *,
    start: date | None = None,
    end: date | None = None,
) -> Select[tuple[Any, ...]]:
    """Build a tenant/evidence-bound V5 payment read with explicit gaps."""

    return _child_statement(
        PAYMENTS,
        tenant_id,
        start=start,
        end=end,
        extra=(PAYMENTS.c.payment_ordinal.is_not(None),),
        columns=(
            literal(None).label("payment_date"),
            literal(None).label("payment_form"),
            PAYMENTS.c.currency.label("currency"),
            PAYMENTS.c.amount.label("amount"),
            PAYMENTS.c.exchange_rate.label("exchange_rate"),
            literal(None).label("related_document_count"),
            PAYMENTS.c.parser_status.label("parser_status"),
        ),
        order=(PAYMENTS.c.payment_ordinal, PAYMENTS.c.id),
    )


def payroll_records_statement(
    tenant_id: str,
    *,
    start: date | None = None,
    end: date | None = None,
) -> Select[tuple[Any, ...]]:
    """Build a tenant/evidence-bound V5 payroll read with partial dimensions."""

    return _child_statement(
        PAYROLL,
        tenant_id,
        start=start,
        end=end,
        extra=(PAYROLL.c.payroll_ordinal.is_not(None),),
        columns=(
            literal("UNKNOWN").label("payroll_type"),
            literal(None).label("payment_date"),
            literal(None).label("period_start"),
            literal(None).label("period_end"),
            literal(None).label("paid_days"),
            PAYROLL.c.total_perceptions.label("total_perceptions"),
            PAYROLL.c.total_deductions.label("total_deductions"),
            PAYROLL.c.total_other_payments.label("total_other_payments"),
            literal(None).label("perception_count"),
            literal(None).label("deduction_count"),
            literal(None).label("other_payment_count"),
            literal(1).label("incomplete_count"),
            PAYROLL.c.parser_status.label("parser_status"),
        ),
        order=(PAYROLL.c.payroll_ordinal, PAYROLL.c.id),
    )


class AccountingPostgresAdapter:
    """Read accounting normalizers' inputs through short DB transactions."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def tax_records(
        self, tenant_id: str, *, start: date | None = None, end: date | None = None
    ) -> AccountingReadResult[TaxRecord]:
        """Return V5 tax rows with unavailable dimensions marked explicitly."""

        _validate_period(tenant_id, start, end)
        rows = self._execute(tax_records_statement(tenant_id, start=start, end=end))
        return AccountingReadResult(
            tuple(_tax_record_from_row(row) for row in rows),
            _partial_source_status(rows),
            _TAX_UNAVAILABLE,
            money_available=True,
        )

    def payment_records(
        self, tenant_id: str, *, start: date | None = None, end: date | None = None
    ) -> AccountingReadResult[PaymentRecord]:
        """Return V5 payment money with date/form gaps left unavailable."""

        _validate_period(tenant_id, start, end)
        rows = self._execute(payment_records_statement(tenant_id, start=start, end=end))
        return AccountingReadResult(
            tuple(_payment_record_from_row(row) for row in rows),
            _partial_source_status(rows),
            _PAYMENT_UNAVAILABLE,
            money_available=True,
        )

    def payroll_records(
        self, tenant_id: str, *, start: date | None = None, end: date | None = None
    ) -> AccountingReadResult[PayrollReadRow]:
        """Return V5 payroll totals without substituting dates or dimensions."""

        _validate_period(tenant_id, start, end)
        rows = self._execute(payroll_records_statement(tenant_id, start=start, end=end))
        return AccountingReadResult(
            tuple(_payroll_record_from_row(row) for row in rows),
            _partial_source_status(rows),
            _PAYROLL_UNAVAILABLE,
            money_available=False,
        )

    def quality_observations(
        self, tenant_id: str, *, start: date | None = None, end: date | None = None
    ) -> tuple[QualityObservation, ...]:
        """Read redacted metadata/XML quality observations only."""

        rows = self._execute(quality_observations_statement(tenant_id, start=start, end=end))
        return tuple(_quality_observation_from_row(row) for row in rows)

    def quality_context_records(
        self, tenant_id: str, *, start: date | None = None, end: date | None = None
    ) -> tuple[QualityAnalysisRecord, ...]:
        """Read dated quality records with only explicit context dimensions.

        Metadata rows provide their stored direction and may use the joined
        document currency. XML-only rows deliberately have no direction; a
        document currency is retained when present. Missing optional fields in
        legacy row doubles become ``None``. This is read-only and does not
        infer dimensions from status, reconciliation text, or party fields.
        """

        rows = self._execute(quality_observations_statement(tenant_id, start=start, end=end))
        records: list[QualityAnalysisRecord] = []
        for row in rows:
            observed_at = _optional_value(row, "observed_at")
            if observed_at is None:
                # SQL predicates exclude undated rows; keep compatibility with
                # old row doubles that do not expose the new optional field.
                continue
            records.append(
                QualityAnalysisRecord(
                    observed_at=observed_at,
                    observation=_quality_observation_from_row(row),
                    direction=_optional_value(row, "direction"),
                    currency=_optional_value(row, "currency"),
                )
            )
        return tuple(records)

    def _execute(self, statement: Any) -> list[Any]:
        with self._session_factory() as session:
            return list(session.execute(statement).all())


def _child_statement(
    table: Table,
    tenant_id: str,
    *,
    start: date | None,
    end: date | None,
    extra: tuple[Any, ...],
    columns: tuple[Any, ...],
    order: tuple[Any, ...],
) -> Select[tuple[Any, ...]]:
    _validate_period(tenant_id, start, end)
    parent_join = and_(
        table.c.tenant_id == CfdiDocument.tenant_id,
        table.c.document_id == CfdiDocument.id,
        table.c.tenant_id == tenant_id,
        CfdiDocument.tenant_id == tenant_id,
    )
    evidence_join = and_(
        table.c.tenant_id == XmlEvidence.tenant_id,
        table.c.source_evidence_id == XmlEvidence.id,
        XmlEvidence.uuid == CfdiDocument.uuid,
        table.c.source_sha256 == XmlEvidence.xml_sha256,
        table.c.parser_version == XmlEvidence.parser_version,
        XmlEvidence.tenant_id == tenant_id,
    )
    conditions = [
        table.c.tenant_id == tenant_id,
        table.c.document_id.is_not(None),
        table.c.source_evidence_id.is_not(None),
        table.c.source_sha256.is_not(None),
        table.c.parser_version.is_not(None),
        table.c.parser_status.is_not(None),
        table.c.normalization_generation.is_not(None),
        table.c.idempotency_key.is_not(None),
        CfdiDocument.issue_date.is_not(None),
        *extra,
    ]
    if start is not None:
        conditions.append(CfdiDocument.issue_date >= _utc_start(start))
    if end is not None:
        conditions.append(CfdiDocument.issue_date < _utc_start(end + timedelta(days=1)))
    return (
        select(*columns)
        .select_from(table.join(CfdiDocument, parent_join).join(XmlEvidence, evidence_join))
        .where(*conditions)
        .order_by(CfdiDocument.issue_date, *order)
    )


def _partial_source_status(rows: Sequence[object]) -> str:
    """Return parser status without claiming completeness for partial fields."""

    statuses = {_normalize_parser_status(_optional_value(row, "parser_status")) for row in rows}
    if "unsupported" in statuses:
        return "unsupported"
    return "partial"


def _normalize_parser_status(value: object) -> str:
    normalized = str(value or "partial").strip().lower().replace("_", "-")
    if normalized in {"unsupported", "unsupported-error"}:
        return "unsupported"
    if normalized in {"complete", "partial", "empty"}:
        return normalized
    return "partial"


def _tax_record_from_row(row: object) -> TaxRecord:
    return TaxRecord(
        tax_type=_optional_text(row, "tax_type") or "UNKNOWN",
        tax=_optional_text(row, "tax") or "UNKNOWN",
        factor_type=_optional_text(row, "factor_type"),
        rate_or_quota=_optional_value(row, "rate_or_quota"),
        base=_optional_value(row, "base"),
        amount=_optional_value(row, "amount"),
        concept_ordinal=_optional_value(row, "concept_ordinal"),
        document_scope=_optional_text(row, "document_scope") or "document",
        provenance=_PROVENANCE,
    )


def _payment_record_from_row(row: object) -> PaymentRecord:
    return PaymentRecord(
        payment_date=_optional_value(row, "payment_date"),
        payment_form=_optional_text(row, "payment_form"),
        currency=_optional_text(row, "currency"),
        amount=_optional_value(row, "amount"),
        exchange_rate=_optional_value(row, "exchange_rate"),
        related_document_count=_optional_value(row, "related_document_count"),
        provenance=_PROVENANCE,
    )


def _payroll_record_from_row(row: object) -> PayrollReadRow:
    return PayrollReadRow(
        payroll_type=_optional_text(row, "payroll_type") or "UNKNOWN",
        payment_date=_optional_value(row, "payment_date"),
        period_start=_optional_value(row, "period_start"),
        period_end=_optional_value(row, "period_end"),
        paid_days=_optional_value(row, "paid_days"),
        total_perceptions=_optional_value(row, "total_perceptions"),
        total_deductions=_optional_value(row, "total_deductions"),
        total_other_payments=_optional_value(row, "total_other_payments"),
        perception_count=_optional_value(row, "perception_count"),
        deduction_count=_optional_value(row, "deduction_count"),
        other_payment_count=_optional_value(row, "other_payment_count"),
        incomplete_count=_optional_value(row, "incomplete_count") or 1,
    )


def _validate_period(tenant_id: str, start: date | None, end: date | None) -> None:
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("analysis-tenant-required")
    if start is not None and type(start) is not date:
        raise TypeError("analysis-date-invalid")
    if end is not None and type(end) is not date:
        raise TypeError("analysis-date-invalid")
    if start is not None and end is not None and start > end:
        raise ValueError("analysis-period-invalid")


def _value(row: object, name: str) -> Any:
    mapping = getattr(row, "_mapping", None)
    if mapping is not None:
        return mapping[name]
    return getattr(row, name)


def _optional_value(row: object, name: str) -> Any:
    """Read a newly added query field without breaking legacy row doubles."""

    mapping = getattr(row, "_mapping", None)
    if mapping is not None:
        return mapping.get(name)
    return getattr(row, name, None)


def _optional_text(row: object, name: str) -> str | None:
    value = _optional_value(row, name)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _quality_observation_from_row(row: object) -> QualityObservation:
    return QualityObservation(
        metadata_present=bool(_value(row, "metadata_present")),
        xml_present=bool(_value(row, "xml_present")),
        cancelled_metadata=bool(_value(row, "cancelled_metadata")),
        xml_conflict=bool(_value(row, "xml_conflict")),
        payment_expected=bool(_value(row, "payment_expected")),
        payment_present=bool(_value(row, "payment_present")),
        payment_evidence_available=False,
        parser_status=_optional_text(row, "parser_status") or "partial",
        reconciliation_state=_optional_text(row, "reconciliation_state") or "unknown",
    )


def _utc_start(value: date) -> datetime:
    return datetime.combine(value, time.min, tzinfo=_UTC)
