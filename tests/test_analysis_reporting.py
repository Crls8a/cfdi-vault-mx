from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from cfdi_vault.analysis.accounting import (
    PaymentSummaryReport,
    PaymentSummaryRow,
    TaxSummaryReport,
    TaxSummaryRow,
)
from cfdi_vault.analysis.monthly import MonthlyAggregate, MonthlyAnalysisReport, MonthlyTrend
from cfdi_vault.analysis.payroll_accounting import PayrollSummaryReport, PayrollSummaryRow
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


def _payroll(status: str = "complete") -> PayrollSummaryReport:
    return PayrollSummaryReport(
        rows=(
            PayrollSummaryRow(
                month="2026-01",
                payroll_type="O",
                count=2,
                incomplete_count=1 if status == "partial" else 0,
                paid_days=Decimal("30"),
                total_perceptions=Decimal("2000"),
                total_deductions=Decimal("400"),
                total_other_payments=Decimal("100"),
            ),
        )
        if status not in {"empty", "unsupported"}
        else (),
        source_status=status,
        incomplete_count=1 if status == "partial" else 0,
        record_count=2 if status not in {"empty", "unsupported"} else 0,
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
    assert payload["sections"]["monthly"]["rows"][0]["active_count"] == 0
    assert payload["sections"]["monthly"]["rows"][0]["unknown_status_count"] == 0
    assert payload["sections"]["monthly"]["trends"] == []
    assert payload["sections"]["taxes"]["rows"][0]["amount"] == "16.00"
    assert payload["sections"]["payments"]["rows"][0]["amount"] == "116.00"
    json.dumps(payload)


def test_report_accepts_unknown_related_count_without_turning_it_into_zero() -> None:
    payments = _payments()
    unknown = replace(payments.rows[0], related_document_count=None)
    report = _report(payments=replace(payments, rows=(unknown,), source_status="partial", incomplete_count=1))
    assert report.to_public_dict()["sections"]["payments"]["rows"][0]["related_document_count"] is None


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


def test_report_serializes_monthly_trends_as_aggregate_only_values() -> None:
    trend = MonthlyTrend(
        month="2026-02",
        direction="received",
        currency="MXN",
        prior_month="2026-01",
        prior_available=True,
        count_delta=1,
        subtotal_delta=Decimal("10.00"),
        total_delta=Decimal("11.60"),
        cancelled_count_delta=-1,
        active_count_delta=1,
        unknown_status_count_delta=0,
        metadata_count_delta=1,
        xml_count_delta=0,
    )
    row = MonthlyAggregate(
        "2026-02",
        "received",
        "MXN",
        3,
        Decimal("110.00"),
        Decimal("127.60"),
        0,
        1,
        2,
        2,
        1,
    )
    report = _report(monthly=MonthlyAnalysisReport(rows=(row,), trends=(trend,)))

    payload = report.as_dict()["sections"]["monthly"]
    assert payload["rows"][0]["active_count"] == 2
    assert payload["rows"][0]["unknown_status_count"] == 1
    assert payload["trends"] == [
        {
            "month": "2026-02",
            "direction": "received",
            "currency": "MXN",
            "prior_month": "2026-01",
            "prior_available": True,
            "count_delta": 1,
            "subtotal_delta": "10.00",
            "total_delta": "11.60",
            "cancelled_count_delta": -1,
            "active_count_delta": 1,
            "unknown_status_count_delta": 0,
            "metadata_count_delta": 1,
            "xml_count_delta": 0,
        }
    ]


def test_report_rejects_invalid_monthly_status_counts_and_trend_dimensions() -> None:
    with pytest.raises(TypeError, match="analysis-count-invalid"):
        _report(
            monthly=MonthlyAnalysisReport(
                rows=(
                    MonthlyAggregate(
                        "2026-01",
                        "received",
                        "MXN",
                        1,
                        Decimal("1"),
                        Decimal("1"),
                        0,
                        0,
                        1,
                        -1,
                        0,
                    ),
                )
            )
        )

    bad_trend = MonthlyTrend(
        month="2026-02",
        direction="RFCABC010101AAA",
        currency="MXN",
        prior_month="2026-01",
        prior_available=True,
        count_delta=0,
        subtotal_delta=Decimal("0"),
        total_delta=Decimal("0"),
        cancelled_count_delta=0,
        active_count_delta=0,
        unknown_status_count_delta=0,
        metadata_count_delta=0,
        xml_count_delta=0,
    )
    with pytest.raises(ValueError, match="analysis-direction-invalid"):
        _report(monthly=MonthlyAnalysisReport(rows=_monthly().rows, trends=(bad_trend,)))
    with pytest.raises(TypeError, match="analysis-trend-delta-invalid"):
        _report(
            monthly=MonthlyAnalysisReport(
                rows=_monthly().rows,
                trends=(replace(bad_trend, direction="received", count_delta="1"),),
            )
        )
    with pytest.raises(ValueError, match="analysis-trend-baseline-invalid"):
        _report(
            monthly=MonthlyAnalysisReport(
                rows=_monthly().rows,
                trends=(replace(bad_trend, direction="received", prior_available=False),),
            )
        )


def test_report_includes_payroll_as_an_aggregate_only_section() -> None:
    report = _report(payroll=_payroll())
    payload = report.as_dict()

    assert payload["section_statuses"]["payroll"] == "complete"
    assert payload["section_completeness"]["payroll"] == "complete"
    assert payload["sections"]["payroll"] == {
        "status": "complete",
        "completeness": "complete",
        "record_count": 2,
        "incomplete_count": 0,
        "rows": [
            {
                "month": "2026-01",
                "payroll_type": "O",
                "count": 2,
                "incomplete_count": 0,
                "paid_days": "30",
                "total_perceptions": "2000",
                "total_deductions": "400",
                "total_other_payments": "100",
            }
        ],
    }
    json.dumps(payload)


@pytest.mark.parametrize("status", ["partial", "empty", "unsupported"])
def test_report_preserves_payroll_status_and_incomplete_count(status: str) -> None:
    report = _report(payroll=_payroll(status))

    assert report.section_statuses["payroll"] == status
    section = report.as_dict()["sections"]["payroll"]
    assert section["status"] == status
    assert section["completeness"] == status
    assert section["incomplete_count"] == (1 if status == "partial" else 0)


def test_report_orders_payroll_rows_and_redacts_source_details() -> None:
    first = PayrollSummaryRow("2026-02", "E", 1, 0, Decimal("1"), Decimal("2"), None, None)
    second = PayrollSummaryRow("2026-01", "O", 1, 0, Decimal("3"), Decimal("4"), None, None)
    report = _report(
        payroll=PayrollSummaryReport(
            rows=(first, second),
            source_status="complete",
            incomplete_count=0,
            record_count=2,
        )
    )

    rows = report.as_dict()["sections"]["payroll"]["rows"]
    assert [(row["month"], row["payroll_type"]) for row in rows] == [("2026-01", "O"), ("2026-02", "E")]
    rendered = repr(report) + json.dumps(report.as_dict())
    assert "PayrollSummaryRow" not in rendered
    assert "PayrollRecord" not in rendered
    assert "RFC" not in rendered


def test_report_rejects_malformed_payroll_dimensions_and_counts() -> None:
    base = _payroll().rows[0]
    with pytest.raises(ValueError, match="analysis-month-invalid"):
        _report(payroll=PayrollSummaryReport((replace(base, month="2026-13"),), "complete", 0, 1))
    with pytest.raises(ValueError, match="analysis-payroll-type-invalid"):
        _report(payroll=PayrollSummaryReport((replace(base, payroll_type="RFCABC010101AAA"),), "complete", 0, 1))
    with pytest.raises(TypeError, match="analysis-count-invalid"):
        _report(payroll=PayrollSummaryReport((replace(base, count=-1),), "complete", 0, 1))
    with pytest.raises(TypeError, match="analysis-count-invalid"):
        _report(payroll=PayrollSummaryReport((base,), "complete", -1, 1))
    with pytest.raises(TypeError, match="analysis-count-invalid"):
        _report(payroll=PayrollSummaryReport((base,), "complete", 0, -1))
    with pytest.raises(ValueError, match="analysis-section-status-invalid"):
        _report(payroll=PayrollSummaryReport((), "raw", 0, 0))


def test_report_without_payroll_keeps_legacy_four_section_shape() -> None:
    legacy = FinancialAnalysisReport(
        _monthly(),
        _taxes(),
        _payments(),
        snapshot_quality([]),
        (date(2026, 1, 1), date(2026, 1, 31)),
        datetime(2026, 2, 1, 12, 0, tzinfo=UTC),
    )
    payload = legacy.as_dict()

    assert "payroll" not in payload["section_statuses"]
    assert "payroll" not in payload["sections"]
