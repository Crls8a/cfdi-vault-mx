from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from cfdi_vault.analysis.contextual_report import ContextualReportBundle
from cfdi_vault.analysis.monthly import MonthlyAnalysisRecord
from cfdi_vault.analysis.postgres_accounting import AccountingReadResult
from cfdi_vault.analysis.postgres_payroll import PayrollReadRow
from cfdi_vault.analysis.postgres_report import PostgresFinancialAnalysisService
from cfdi_vault.analysis.quality import QualityObservation
from cfdi_vault.analysis.quality_context import QualityAnalysisRecord


class _MonthlyReader:
    def __init__(self, records: tuple[MonthlyAnalysisRecord, ...] = ()) -> None:
        self.records = records
        self.calls: list[tuple[str, date, date]] = []

    def records_for_period(self, tenant_id: str, *, start: date, end: date):
        self.calls.append((tenant_id, start, end))
        return self.records


class _AccountingReader:
    def __init__(
        self,
        *,
        tax_status: str = "partial",
        payment_status: str = "partial",
        payroll_status: str = "partial",
        payroll_rows: tuple[PayrollReadRow, ...] = (),
        observations: tuple[QualityObservation, ...] = (),
    ) -> None:
        self.tax_result = AccountingReadResult((), tax_status)
        self.payment_result = AccountingReadResult((), payment_status)
        self.payroll_result = AccountingReadResult(payroll_rows, payroll_status)
        self.observations = observations
        self.calls: list[tuple[str, str, date, date]] = []

    def tax_records(self, tenant_id: str, *, start: date, end: date):
        self.calls.append(("tax", tenant_id, start, end))
        return self.tax_result

    def payment_records(self, tenant_id: str, *, start: date, end: date):
        self.calls.append(("payment", tenant_id, start, end))
        return self.payment_result

    def payroll_records(self, tenant_id: str, *, start: date, end: date):
        self.calls.append(("payroll", tenant_id, start, end))
        return self.payroll_result

    def quality_observations(self, tenant_id: str, *, start: date, end: date):
        self.calls.append(("quality", tenant_id, start, end))
        return self.observations


class _ContextualAccountingReader(_AccountingReader):
    def __init__(
        self,
        *,
        context_records: tuple[QualityAnalysisRecord, ...] = (),
    ) -> None:
        super().__init__()
        self.context_records = context_records
        self.context_calls: list[tuple[str, date, date]] = []

    def quality_context_records(self, tenant_id: str, *, start: date, end: date):
        self.context_calls.append((tenant_id, start, end))
        return self.context_records


def _contextual_service(
    records: tuple[QualityAnalysisRecord, ...] = (),
) -> tuple[PostgresFinancialAnalysisService, _MonthlyReader, _ContextualAccountingReader]:
    monthly = _MonthlyReader()
    accounting = _ContextualAccountingReader(context_records=records)
    service = PostgresFinancialAnalysisService(
        monthly,  # type: ignore[arg-type]
        accounting,  # type: ignore[arg-type]
    )
    return service, monthly, accounting


def _service(
    *,
    records: tuple[MonthlyAnalysisRecord, ...] = (),
    tax_status: str = "partial",
    payment_status: str = "partial",
    payroll_status: str = "partial",
    payroll_rows: tuple[PayrollReadRow, ...] = (),
    observations: tuple[QualityObservation, ...] = (),
) -> tuple[PostgresFinancialAnalysisService, _MonthlyReader, _AccountingReader]:
    monthly = _MonthlyReader(records)
    accounting = _AccountingReader(
        tax_status=tax_status,
        payment_status=payment_status,
        payroll_status=payroll_status,
        payroll_rows=payroll_rows,
        observations=observations,
    )
    service = PostgresFinancialAnalysisService(
        monthly,  # type: ignore[arg-type]
        accounting,  # type: ignore[arg-type]
        clock=lambda: datetime(2026, 2, 1, 12, 0, tzinfo=UTC),
    )
    return service, monthly, accounting


def test_report_validates_tenant_and_inclusive_period() -> None:
    service, monthly, accounting = _service()
    with pytest.raises(ValueError, match="analysis-tenant-required"):
        service.build_report(" ", date(2026, 1, 1), date(2026, 1, 31))
    with pytest.raises(TypeError, match="analysis-date-invalid"):
        service.build_report("tenant", datetime(2026, 1, 1, tzinfo=UTC), date(2026, 1, 31))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="analysis-period-invalid"):
        service.build_report("tenant", date(2026, 2, 1), date(2026, 1, 31))
    assert monthly.calls == []
    assert accounting.calls == []


def test_report_requires_payroll_reader_for_the_five_section_contract() -> None:
    class _MissingPayroll:
        def tax_records(self, tenant_id: str, *, start: date, end: date):
            return AccountingReadResult((), "partial")

        def payment_records(self, tenant_id: str, *, start: date, end: date):
            return AccountingReadResult((), "partial")

        def quality_observations(self, tenant_id: str, *, start: date, end: date):
            return ()

    with pytest.raises(TypeError, match="analysis-accounting-adapter-required"):
        PostgresFinancialAnalysisService(_MonthlyReader(), _MissingPayroll())  # type: ignore[arg-type]


def test_metadata_only_monthly_aggregation_uses_requested_tenant_period() -> None:
    service, monthly, accounting = _service(
        records=(
            MonthlyAnalysisRecord(
                issue_date=date(2026, 1, 31),
                direction="received",
                currency="MXN",
                subtotal=Decimal("100.00"),
                total=Decimal("116.00"),
                status="vigente",
                source_kind="metadata",
            ),
        )
    )
    report = service.build_report("tenant", date(2026, 1, 1), date(2026, 1, 31))
    row = report.monthly.rows[0]
    assert (row.month, row.direction, row.currency, row.count) == ("2026-01", "received", "MXN", 1)
    assert row.subtotal == Decimal("100.00")
    assert row.total == Decimal("116.00")
    assert row.metadata_count == 1
    assert row.xml_count == 0
    assert dict(report.section_statuses) == {
        "monthly": "partial",
        "taxes": "partial",
        "payments": "partial",
        "payroll": "partial",
        "quality": "empty",
    }
    assert monthly.calls == [("tenant", date(2026, 1, 1), date(2026, 1, 31))]
    assert accounting.calls == [
        ("tax", "tenant", date(2026, 1, 1), date(2026, 1, 31)),
        ("payment", "tenant", date(2026, 1, 1), date(2026, 1, 31)),
        ("payroll", "tenant", date(2026, 1, 1), date(2026, 1, 31)),
        ("quality", "tenant", date(2026, 1, 1), date(2026, 1, 31)),
    ]


def test_quality_rows_are_tenant_safe_and_aggregate_only() -> None:
    service, _, _ = _service(
        observations=(
            QualityObservation(metadata_present=True, xml_present=False, parser_status="partial"),
            QualityObservation(metadata_present=False, xml_present=True, reconciliation_state="unknown"),
        )
    )
    report = service.build_report("tenant", date(2026, 1, 1), date(2026, 1, 31))
    payload = report.to_public_dict()
    assert payload["sections"]["quality"]["counts"]["metadata_without_xml"] == 1
    assert payload["sections"]["quality"]["counts"]["xml_without_metadata"] == 1
    assert "tenant" not in repr(report)
    assert "QualityObservation" not in repr(report)


def test_v5_accounting_sources_remain_explicitly_partial_without_inference() -> None:
    service, _, _ = _service(tax_status="partial", payment_status="partial")
    report = service.build_report("tenant", date(2026, 1, 1), date(2026, 1, 31))
    payload = report.to_public_dict()
    assert payload["section_statuses"]["taxes"] == "partial"
    assert payload["section_statuses"]["payments"] == "partial"
    assert payload["sections"]["taxes"]["rows"] == []
    assert payload["sections"]["payments"]["rows"] == []
    assert payload["section_statuses"]["payroll"] == "partial"
    assert payload["sections"]["payroll"]["rows"] == []


def test_payroll_section_keeps_partial_status_and_redacted_aggregate_shape() -> None:
    payroll_row = PayrollReadRow(
        payroll_type="UNKNOWN",
        payment_date=datetime(2026, 1, 31, tzinfo=UTC),
        period_start=None,
        period_end=None,
        paid_days=None,
        total_perceptions=Decimal("100.00"),
        total_deductions=None,
        total_other_payments=None,
        perception_count=None,
        deduction_count=None,
        other_payment_count=None,
        incomplete_count=3,
    )
    service, _, _ = _service(payroll_rows=(payroll_row,))
    payload = service.build_report("tenant", date(2026, 1, 1), date(2026, 1, 31)).to_public_dict()
    assert payload["section_statuses"]["payroll"] == "partial"
    assert payload["sections"]["payroll"]["record_count"] == 1
    assert payload["sections"]["payroll"]["rows"] == [
        {
            "month": "2026-01",
            "payroll_type": "UNKNOWN",
            "count": 1,
            "incomplete_count": 3,
            "paid_days": None,
            "total_perceptions": "100.00",
            "total_deductions": None,
            "total_other_payments": None,
        }
    ]
    assert "tenant" not in repr(payload)


def test_empty_period_is_explicit_and_does_not_invent_zero_accounting_data() -> None:
    service, _, _ = _service()
    report = service.build_report("tenant", date(2026, 3, 1), date(2026, 3, 31))
    payload = report.to_public_dict()
    assert payload["section_statuses"] == {
        "monthly": "empty",
        "taxes": "partial",
        "payments": "partial",
        "payroll": "partial",
        "quality": "empty",
    }
    assert payload["sections"]["monthly"]["rows"] == []
    assert payload["sections"]["taxes"]["incomplete_count"] == 0
    assert payload["sections"]["payments"]["incomplete_count"] == 0


def test_generated_at_uses_injected_clock_or_explicit_utc_timestamp() -> None:
    service, _, _ = _service()
    default_report = service.build_report("tenant", date(2026, 1, 1), date(2026, 1, 31))
    assert default_report.generated_at == datetime(2026, 2, 1, 12, 0, tzinfo=UTC)
    explicit = datetime(2026, 2, 2, 9, 0, tzinfo=UTC)
    explicit_report = service.build_report("tenant", date(2026, 1, 1), date(2026, 1, 31), generated_at=explicit)
    assert explicit_report.generated_at == explicit
    with pytest.raises(ValueError, match="analysis-generated-at-utc-required"):
        service.build_report(
            "tenant",
            date(2026, 1, 1),
            date(2026, 1, 31),
            generated_at=datetime(2026, 2, 2, 9, 0, tzinfo=timezone(timedelta(hours=-6))),
        )


def test_contextual_report_uses_quality_context_and_keeps_legacy_children_partial() -> None:
    service, monthly, accounting = _contextual_service(
        (
            QualityAnalysisRecord(
                observed_at=date(2026, 1, 31),
                direction="received",
                currency="MXN",
                observation=QualityObservation(
                    metadata_present=True,
                    xml_present=False,
                    parser_status="partial",
                ),
            ),
        )
    )

    bundle = service.build_contextual_report("tenant", date(2026, 1, 1), date(2026, 1, 31))

    assert isinstance(bundle, ContextualReportBundle)
    assert bundle.source_status == "partial"
    assert bundle.month_bounds == ("2026-01", "2026-01")
    assert bundle.quality.contexts[0].direction == "received"
    assert bundle.quality.contexts[0].currency == "MXN"
    assert bundle.taxes.contexts == () and bundle.taxes.source_status == "partial"
    assert bundle.payments.contexts == () and bundle.payments.source_status == "partial"
    assert monthly.calls == []
    assert accounting.calls == []
    assert accounting.context_calls == [("tenant", date(2026, 1, 1), date(2026, 1, 31))]


def test_contextual_report_with_no_quality_rows_does_not_invent_period_or_zeroes() -> None:
    service, _, accounting = _contextual_service()

    bundle = service.build_contextual_report("tenant", date(2026, 3, 1), date(2026, 3, 31))

    assert bundle.source_status == "partial"
    assert bundle.month_bounds is None
    assert bundle.quality.contexts == ()
    assert bundle.taxes.contexts == () and bundle.payments.contexts == ()
    assert accounting.context_calls == [("tenant", date(2026, 3, 1), date(2026, 3, 31))]


def test_contextual_report_validates_before_database_reads() -> None:
    service, monthly, accounting = _contextual_service()

    with pytest.raises(ValueError, match="analysis-tenant-required"):
        service.build_contextual_report(" ", date(2026, 1, 1), date(2026, 1, 31))
    with pytest.raises(TypeError, match="analysis-date-invalid"):
        service.build_contextual_report("tenant", datetime(2026, 1, 1, tzinfo=UTC), date(2026, 1, 31))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="analysis-period-invalid"):
        service.build_contextual_report("tenant", date(2026, 2, 1), date(2026, 1, 31))

    assert monthly.calls == []
    assert accounting.context_calls == []


def test_contextual_report_requires_only_new_quality_adapter_method() -> None:
    service, _, accounting = _service()

    with pytest.raises(TypeError, match="analysis-quality-context-adapter-required"):
        service.build_contextual_report("tenant", date(2026, 1, 1), date(2026, 1, 31))

    assert accounting.calls == []
