"""Compose aggregate financial reports from the read-only PostgreSQL adapters.

This module owns orchestration of already-sanitized database read models.  It
does not issue SQL, write PostgreSQL, access artifacts, contact SAT, enqueue
jobs, or infer accounting or tax treatment.  Legacy tax/payment/payroll child
tables remain explicitly partial until the approved tenant-safe V5 ledger is
available; payroll is therefore not included in this four-section report.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, date, datetime

from cfdi_vault.analysis.accounting import summarize_payments, summarize_taxes
from cfdi_vault.analysis.monthly import analyze_monthly
from cfdi_vault.analysis.postgres import MonthlyAnalysisPostgresAdapter
from cfdi_vault.analysis.postgres_accounting import AccountingPostgresAdapter
from cfdi_vault.analysis.quality import snapshot_quality
from cfdi_vault.analysis.reporting import AnalysisPeriod, FinancialAnalysisReport

__all__ = ["PostgresFinancialAnalysisService"]

Clock = Callable[[], datetime]


class PostgresFinancialAnalysisService:
    """Build one redacted report from tenant-scoped PostgreSQL read adapters.

    The adapters each use short-lived read transactions.  This service does
    not hold a transaction while pure analysis runs and never mutates the
    database.  The resulting report contains monthly, tax, payment, and
    quality sections; payroll is intentionally omitted while the legacy
    payroll table lacks tenant-safe normalized amount fields.

    Args:
        monthly_adapter: Existing tenant-scoped monthly read adapter.
        accounting_adapter: Existing read-only accounting/quality adapter.
        clock: UTC-aware clock used when ``generated_at`` is not supplied.

    Raises:
        ValueError: for a blank tenant, inverted period, or invalid report
            timestamp.
        TypeError: for non-``date`` period bounds or a non-callable clock.

    No filesystem, network, SAT, queue, or storage side effects occur.
    """

    def __init__(
        self,
        monthly_adapter: MonthlyAnalysisPostgresAdapter,
        accounting_adapter: AccountingPostgresAdapter,
        *,
        clock: Clock | None = None,
    ) -> None:
        if not callable(monthly_adapter.records_for_period):
            raise TypeError("analysis-monthly-adapter-required")
        if not callable(accounting_adapter.tax_records) or not callable(accounting_adapter.payment_records):
            raise TypeError("analysis-accounting-adapter-required")
        if not callable(accounting_adapter.quality_observations):
            raise TypeError("analysis-quality-adapter-required")
        if clock is not None and not callable(clock):
            raise TypeError("analysis-clock-required")
        self._monthly_adapter = monthly_adapter
        self._accounting_adapter = accounting_adapter
        self._clock = clock or (lambda: datetime.now(UTC))

    def build_report(
        self,
        tenant_id: str,
        start: date,
        end: date,
        *,
        generated_at: datetime | None = None,
    ) -> FinancialAnalysisReport:
        """Return an aggregate-only report for one inclusive tenant period.

        Monthly records and quality observations are read through their
        existing adapters.  Tax and payment sources carry their explicit
        parser status into the summary, so unavailable legacy child tables
        remain ``partial`` rather than looking like measured zeroes.
        ``generated_at`` is normalized and validated by the report DTO; when
        omitted, the injected UTC clock supplies it.
        """

        _validate_request(tenant_id, start, end)
        monthly_records = self._monthly_adapter.records_for_period(tenant_id, start=start, end=end)
        tax_result = self._accounting_adapter.tax_records(tenant_id, start=start, end=end)
        payment_result = self._accounting_adapter.payment_records(tenant_id, start=start, end=end)
        quality_observations = self._accounting_adapter.quality_observations(tenant_id, start=start, end=end)

        monthly = analyze_monthly(monthly_records, start=start, end=end)
        taxes = summarize_taxes(tax_result.rows, source_status=tax_result.source_status)
        payments = summarize_payments(
            payment_result.rows,
            start=start,
            end=end,
            source_status=payment_result.source_status,
        )
        quality = snapshot_quality(quality_observations)
        timestamp = generated_at if generated_at is not None else self._clock()
        return FinancialAnalysisReport(
            monthly=monthly,
            taxes=taxes,
            payments=payments,
            quality=quality,
            period=AnalysisPeriod(start, end),
            generated_at=timestamp,
        )

    def __repr__(self) -> str:
        """Return a representation without adapters, tenants, or report data."""

        return "PostgresFinancialAnalysisService(<redacted>)"


def _validate_request(tenant_id: str, start: date, end: date) -> None:
    if type(tenant_id) is not str or not tenant_id.strip():
        raise ValueError("analysis-tenant-required")
    if type(start) is not date or type(end) is not date:
        raise TypeError("analysis-date-invalid")
    if start > end:
        raise ValueError("analysis-period-invalid")
