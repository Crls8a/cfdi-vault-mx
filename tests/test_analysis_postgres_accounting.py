from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import date, datetime, timezone
from decimal import Decimal
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from cfdi_vault.analysis.accounting import summarize_payments
from cfdi_vault.analysis.payroll_accounting import summarize_payroll
from cfdi_vault.analysis.postgres_accounting import (
    AccountingPostgresAdapter,
    payment_records_statement,
    payroll_records_statement,
    quality_observations_statement,
    tax_records_statement,
)
from cfdi_vault.analysis.postgres_payroll import PayrollReadRow
from cfdi_vault.analysis.quality import QualityObservation


class _Result:
    def __init__(self, rows: list[object]) -> None:
        self.rows = rows

    def all(self) -> list[object]:
        return self.rows


class _Session:
    def __init__(self, rows: list[object]) -> None:
        self.rows = rows
        self.statement: object | None = None

    def execute(self, statement: object) -> _Result:
        self.statement = statement
        return _Result(self.rows)


def _factory(rows: list[object]) -> tuple[object, _Session]:
    session = _Session(rows)

    @contextmanager
    def open_session():
        yield session

    return open_session, session


def _row(**values: object) -> SimpleNamespace:
    return SimpleNamespace(**values)


def test_tax_read_uses_v5_rows_and_keeps_unavailable_dimensions_explicit() -> None:
    factory, session = _factory(
        [
            _row(
                tax_type="transferred",
                amount=Decimal("1.60"),
                parser_status="complete",
            )
        ]
    )
    result = AccountingPostgresAdapter(factory).tax_records("tenant")
    assert len(result.rows) == 1
    assert result.rows[0].tax_type == "transferred"
    assert result.rows[0].tax == "UNKNOWN"
    assert result.rows[0].amount == Decimal("1.60")
    assert result.rows[0].factor_type is None
    assert result.source_status == "partial"
    assert {"tax", "factor_type", "base", "rate_or_quota"}.issubset(result.unavailable_fields)
    assert session.statement is not None


def test_payment_read_maps_v5_money_without_inventing_payment_dimensions() -> None:
    factory, session = _factory(
        [
            _row(
                currency="MXN",
                amount=Decimal("25.00"),
                exchange_rate=None,
                related_document_count=None,
                parser_status="complete",
            )
        ]
    )
    result = AccountingPostgresAdapter(factory).payment_records(
        "tenant", start=date(2026, 1, 14), end=date(2026, 1, 14)
    )
    assert len(result.rows) == 1
    assert result.rows[0].payment_date is None
    assert result.rows[0].payment_form is None
    assert result.rows[0].currency == "MXN"
    assert result.rows[0].amount == Decimal("25.00")
    assert result.rows[0].related_document_count is None
    assert result.money_available is True
    assert "related_document_identity" in result.unavailable_fields
    summary = summarize_payments(result.rows, source_status=result.source_status)
    assert summary.rows == ()
    assert summary.incomplete_count == 1
    assert session.statement is not None


def test_payroll_read_maps_v5_totals_without_inventing_dates_or_dimensions() -> None:
    factory, session = _factory(
        [
            _row(
                payroll_type="UNKNOWN",
                total_perceptions=Decimal("10.00"),
                total_deductions=Decimal("1.00"),
                total_other_payments=Decimal("0.00"),
                parser_status="complete",
            )
        ]
    )
    result = AccountingPostgresAdapter(factory).payroll_records("tenant", start=date(2026, 1, 1), end=date(2026, 1, 31))
    assert len(result.rows) == 1
    assert result.rows[0].payroll_type == "UNKNOWN"
    assert result.rows[0].payment_date is None
    assert result.rows[0].total_perceptions == Decimal("10.00")
    assert result.rows[0].perception_count is None
    assert result.money_available is False
    assert "payment_date" in result.unavailable_fields
    summary = summarize_payroll(result.rows, source_status=result.source_status)
    assert summary.rows == ()
    assert summary.incomplete_count > 0
    assert result.source_status == "partial"
    assert session.statement is not None


def test_quality_adapter_returns_only_redacted_observations() -> None:
    factory, _ = _factory(
        [
            _row(
                metadata_present=True,
                xml_present=False,
                cancelled_metadata=False,
                xml_conflict=False,
                payment_expected=False,
                payment_present=False,
                parser_status="partial",
                reconciliation_state="xml_pending",
            )
        ]
    )
    observations = AccountingPostgresAdapter(factory).quality_observations("tenant")
    assert observations[0].metadata_present
    assert not observations[0].xml_present
    assert observations[0].parser_status == "partial"
    assert observations[0].payment_evidence_available is False
    assert "tenant" not in repr(observations[0])


def test_quality_context_records_use_metadata_direction_and_document_currency() -> None:
    factory, session = _factory(
        [
            _row(
                metadata_present=True,
                xml_present=True,
                cancelled_metadata=False,
                xml_conflict=False,
                payment_expected=False,
                payment_present=False,
                parser_status="complete",
                reconciliation_state="state_checked",
                observed_at=datetime(2026, 1, 14, 23, 30, tzinfo=timezone.utc),
                direction="received",
                currency="MXN",
            )
        ]
    )
    records = AccountingPostgresAdapter(factory).quality_context_records(
        "tenant", start=date(2026, 1, 1), end=date(2026, 1, 31)
    )
    assert len(records) == 1
    assert records[0].observed_at == date(2026, 1, 14)
    assert records[0].direction == "received"
    assert records[0].currency == "MXN"
    assert records[0].observation.xml_present
    sql = str(session.statement.compile(dialect=postgresql.dialect()))
    assert "AS observed_at" in sql and "AS direction" in sql and "AS currency" in sql
    assert "issue_date" in sql and "tenant_id" in sql


def test_quality_context_xml_only_rows_keep_currency_and_unknown_direction() -> None:
    factory, _ = _factory(
        [
            _row(
                metadata_present=False,
                xml_present=True,
                cancelled_metadata=False,
                xml_conflict=False,
                payment_expected=False,
                payment_present=False,
                parser_status="complete",
                reconciliation_state="unknown",
                observed_at=date(2026, 2, 1),
                direction=None,
                currency="USD",
            )
        ]
    )
    records = AccountingPostgresAdapter(factory).quality_context_records("tenant")
    assert [(record.direction, record.currency) for record in records] == [(None, "USD")]


def test_quality_context_missing_optional_dimensions_map_to_none() -> None:
    factory, _ = _factory(
        [
            _row(
                metadata_present=True,
                xml_present=False,
                cancelled_metadata=False,
                xml_conflict=False,
                payment_expected=False,
                payment_present=False,
                parser_status="partial",
                reconciliation_state="unknown",
                observed_at=date(2026, 3, 1),
            )
        ]
    )
    records = AccountingPostgresAdapter(factory).quality_context_records("tenant")
    assert len(records) == 1
    assert records[0].direction is None and records[0].currency is None


def test_quality_observations_remains_compatible_with_rows_without_context_fields() -> None:
    factory, _ = _factory(
        [
            _row(
                metadata_present=True,
                xml_present=False,
                cancelled_metadata=False,
                xml_conflict=False,
                payment_expected=False,
                payment_present=False,
                parser_status="partial",
                reconciliation_state="unknown",
            )
        ]
    )
    observations = AccountingPostgresAdapter(factory).quality_observations("tenant")
    assert observations == (
        QualityObservation(
            metadata_present=True,
            parser_status="partial",
            reconciliation_state="unknown",
            payment_evidence_available=False,
        ),
    )


def test_quality_statement_is_union_and_does_not_select_identifiers() -> None:
    statement = quality_observations_statement("tenant", start=date(2026, 1, 1), end=date(2026, 1, 14))
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "UNION ALL" in sql
    assert "AS metadata_present" in sql
    assert "AS xml_present" in sql
    assert "AS parser_status" in sql
    assert "AS reconciliation_state" in sql
    assert "issuer_rfc" not in sql
    assert "receiver_rfc" not in sql
    assert "raw_payload" not in sql


def test_v5_accounting_statements_scope_parent_and_evidence_without_legacy_columns() -> None:
    for builder in (tax_records_statement, payment_records_statement, payroll_records_statement):
        statement = builder("tenant", start=date(2026, 1, 1), end=date(2026, 1, 14))
        sql = str(statement.compile(dialect=postgresql.dialect()))
        assert "tenant_id" in sql
        assert "source_evidence_id" in sql
        assert "issue_date" in sql
        assert "raw_payload" not in sql
        assert "issuer_rfc" not in sql and "receiver_rfc" not in sql


def test_adapter_rejects_blank_tenant_and_inverted_period() -> None:
    factory, _ = _factory([])
    adapter = AccountingPostgresAdapter(factory)
    with pytest.raises(ValueError, match="analysis-tenant-required"):
        adapter.payment_records(" ")
    with pytest.raises(ValueError, match="analysis-period-invalid"):
        adapter.payroll_records("tenant", start=date(2026, 2, 1), end=date(2026, 1, 1))
    with pytest.raises(TypeError, match="analysis-date-invalid"):
        adapter.tax_records("tenant", start=datetime(2026, 1, 1, tzinfo=timezone.utc))  # type: ignore[arg-type]


def test_payroll_read_row_validates_type_utc_order_money_and_counts() -> None:
    valid = PayrollReadRow(
        payroll_type="O",
        payment_date=None,
        period_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        period_end=datetime(2026, 1, 15, tzinfo=timezone.utc),
        paid_days=Decimal("5"),
        total_perceptions=None,
        total_deductions=None,
        total_other_payments=None,
        perception_count=0,
        deduction_count=0,
        other_payment_count=0,
        incomplete_count=1,
    )
    assert "PayrollReadRow(<redacted>)" == repr(valid)
    with pytest.raises(ValueError, match="payroll-read-type-invalid"):
        replace(valid, payroll_type="X")
    with pytest.raises(ValueError, match="payroll-read-period_start-utc-required"):
        replace(valid, period_start=datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="payroll-read-period-invalid"):
        replace(valid, period_start=datetime(2026, 1, 16, tzinfo=timezone.utc))
    with pytest.raises(TypeError, match="payroll-read-decimal-invalid"):
        replace(valid, paid_days=Decimal("-1"))
    with pytest.raises(TypeError, match="payroll-read-count-invalid"):
        replace(valid, perception_count=-1)
    assert replace(valid, perception_count=None).perception_count is None
