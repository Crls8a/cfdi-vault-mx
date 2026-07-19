from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from cfdi_vault.analysis.accounting import (
    PaymentSummaryReport,
    PaymentSummaryRow,
    TaxSummaryReport,
    TaxSummaryRow,
)
from cfdi_vault.analysis.monthly import MonthlyAggregate, MonthlyAnalysisReport
from cfdi_vault.analysis.quality import QualityObservation, snapshot_quality
from cfdi_vault.analysis.reporting import AnalysisPeriod, FinancialAnalysisReport


def _monthly(*, month: str = "2026-01", metadata_count: int = 0) -> MonthlyAnalysisReport:
    return MonthlyAnalysisReport(
        rows=(
            MonthlyAggregate(
                month=month,
                direction="received",
                currency="MXN",
                count=2,
                subtotal=Decimal("100.00"),
                total=Decimal("116.00"),
                cancelled_count=1,
                metadata_count=metadata_count,
                xml_count=2 - metadata_count,
            ),
        )
    )


def _taxes(status: str = "complete") -> TaxSummaryReport:
    return TaxSummaryReport(
        rows=(
            TaxSummaryRow(
                tax_type="transferred",
                tax="002",
                factor_type="Tasa",
                count=1,
                base=Decimal("100.00"),
                amount=Decimal("16.00"),
                rate_or_quota=Decimal("0.160000"),
            ),
        )
        if status != "empty"
        else (),
        source_status=status,
        incomplete_count=1 if status == "partial" else 0,
    )


def _payments(status: str = "complete") -> PaymentSummaryReport:
    return PaymentSummaryReport(
        rows=(
            PaymentSummaryRow(
                month="2026-01",
                currency="MXN",
                payment_form="03",
                count=1,
                amount=Decimal("116.00"),
                related_document_count=1,
            ),
        )
        if status != "empty"
        else (),
        source_status=status,
        incomplete_count=1 if status == "partial" else 0,
    )


def _report(**overrides: object) -> FinancialAnalysisReport:
    values: dict[str, object] = {
        "monthly": _monthly(),
        "taxes": _taxes(),
        "payments": _payments(),
        "quality": snapshot_quality([QualityObservation(metadata_present=True, xml_present=True)]),
        "period": (date(2026, 1, 1), date(2026, 1, 31)),
        "generated_at": datetime(2026, 2, 1, 12, 0, tzinfo=UTC),
    }
    values.update(overrides)
    return FinancialAnalysisReport(**values)  # type: ignore[arg-type]


def test_report_composes_sections_and_serializes_decimal_values() -> None:
    report = _report()
    payload = report.to_public_dict()

    assert isinstance(report.period, AnalysisPeriod)
    assert payload["period"] == {"start": "2026-01-01", "end": "2026-01-31"}
    assert payload["generated_at"] == "2026-02-01T12:00:00Z"
    assert payload["section_statuses"] == {
        "monthly": "complete",
        "taxes": "complete",
        "payments": "complete",
        "quality": "complete",
    }
    assert payload["sections"]["monthly"]["rows"][0]["total"] == "116.00"
    assert payload["sections"]["taxes"]["rows"][0]["amount"] == "16.00"
    assert payload["sections"]["payments"]["rows"][0]["amount"] == "116.00"
    json.dumps(payload)


def test_report_preserves_empty_partial_and_unsupported_section_statuses() -> None:
    report = _report(
        monthly=_monthly(metadata_count=1),
        taxes=_taxes("unsupported"),
        payments=_payments("partial"),
        quality=snapshot_quality([]),
    )

    assert dict(report.section_statuses) == {
        "monthly": "partial",
        "taxes": "unsupported",
        "payments": "partial",
        "quality": "empty",
    }
    assert dict(report.section_completeness) == dict(report.section_statuses)
    assert report.as_dict() == report.to_public_dict()


def test_report_projection_is_redacted_stable_and_contains_no_float() -> None:
    first = _report()
    second = _report()
    assert first.as_dict() == second.as_dict()
    assert "TaxSummaryRow" not in repr(first)
    assert "PaymentSummaryRow" not in repr(first)
    assert "QualityObservation" not in repr(first)

    def walk(value: object) -> None:
        assert not isinstance(value, float)
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(first.as_dict())


def test_report_orders_rows_independently_of_input_order() -> None:
    report = _report(
        monthly=MonthlyAnalysisReport(
            rows=(
                MonthlyAggregate("2026-02", "issued", "USD", 1, Decimal("1"), Decimal("2"), 0, 0, 1),
                MonthlyAggregate("2026-01", "received", "MXN", 1, Decimal("3"), Decimal("4"), 0, 0, 1),
            )
        ),
        taxes=TaxSummaryReport(
            rows=(_taxes().rows[0], TaxSummaryRow("transferred", "001", "Tasa", 1, Decimal("1"), Decimal("1"), None)),
            source_status="complete",
        ),
    )
    rows = report.as_dict()["sections"]
    assert [row["month"] for row in rows["monthly"]["rows"]] == ["2026-01", "2026-02"]
    assert [row["tax"] for row in rows["taxes"]["rows"]] == ["001", "002"]


def test_report_rejects_reversed_period_non_utc_and_missing_sections() -> None:
    with pytest.raises(ValueError, match="analysis-period-invalid"):
        _report(period=(date(2026, 2, 1), date(2026, 1, 1)))
    with pytest.raises(ValueError, match="analysis-generated-at-utc-required"):
        _report(generated_at=datetime(2026, 2, 1, tzinfo=timezone(timedelta(hours=-6))))
    with pytest.raises(TypeError, match="analysis-quality-section-required"):
        _report(quality=None)


def test_report_rejects_free_form_dimensions_and_invalid_section_counts() -> None:
    bad_month = MonthlyAggregate("2026-13", "received", "MXN", 1, Decimal("1"), Decimal("1"), 0, 0, 1)
    with pytest.raises(ValueError, match="analysis-month-invalid"):
        _report(monthly=MonthlyAnalysisReport(rows=(bad_month,)))

    bad_tax = TaxSummaryRow("transferred", "999", "Tasa", 1, Decimal("1"), Decimal("1"), None)
    with pytest.raises(ValueError, match="analysis-tax-invalid"):
        _report(taxes=TaxSummaryReport(rows=(bad_tax,), source_status="complete"))

    bad_payment = PaymentSummaryRow("2026-01", "MXN", "path", 1, Decimal("1"), 0)
    with pytest.raises(ValueError, match="analysis-payment-form-invalid"):
        _report(payments=PaymentSummaryReport(rows=(bad_payment,), source_status="complete"))

    with pytest.raises(TypeError, match="analysis-count-invalid"):
        _report(taxes=TaxSummaryReport(rows=(), source_status="empty", incomplete_count=-1))
    with pytest.raises(ValueError, match="analysis-section-status-invalid"):
        _report(payments=PaymentSummaryReport(rows=(), source_status="raw"))
