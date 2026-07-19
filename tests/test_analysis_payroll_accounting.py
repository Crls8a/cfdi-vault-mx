from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from cfdi_vault.analysis import PayrollSummaryReport, PayrollSummaryRow, summarize_payroll
from cfdi_vault.analysis.accounting import summarize_payroll as accounting_summarize_payroll
from cfdi_vault.analysis.payroll import PayrollNormalizationResult, PayrollRecord


def _record(**overrides: object) -> PayrollRecord:
    values: dict[str, object] = {
        "payroll_type": "O",
        "payment_date": datetime(2026, 1, 15, 23, 30, tzinfo=UTC),
        "period_start": datetime(2026, 1, 1, tzinfo=UTC),
        "period_end": datetime(2026, 1, 15, tzinfo=UTC),
        "paid_days": Decimal("15"),
        "total_perceptions": Decimal("1000"),
        "total_deductions": Decimal("200"),
        "total_other_payments": Decimal("50"),
        "perception_count": 1,
        "deduction_count": 1,
        "other_payment_count": 1,
        "incomplete_count": 0,
        "provenance": "document",
    }
    values.update(overrides)
    return PayrollRecord(**values)  # type: ignore[arg-type]


def test_payroll_summary_groups_utc_month_and_sums_finite_decimals() -> None:
    report = summarize_payroll(
        [
            _record(),
            _record(
                payment_date=datetime(2026, 1, 31, 23, 45, tzinfo=UTC),
                paid_days=Decimal("10"),
                total_perceptions=Decimal("500"),
                total_deductions=Decimal("100"),
                total_other_payments=Decimal("25"),
            ),
        ]
    )

    assert isinstance(report, PayrollSummaryReport)
    assert report.source_status == "complete"
    assert report.record_count == 2
    assert report.rows == (
        PayrollSummaryRow(
            month="2026-01",
            payroll_type="O",
            count=2,
            incomplete_count=0,
            paid_days=Decimal("25"),
            total_perceptions=Decimal("1500"),
            total_deductions=Decimal("300"),
            total_other_payments=Decimal("75"),
        ),
    )
    assert report.rows[0].record_count == 2


def test_payroll_summary_uses_utc_boundary_and_separates_types_and_months() -> None:
    report = summarize_payroll(
        [
            _record(payment_date=datetime(2026, 2, 1, 0, 15, tzinfo=UTC), payroll_type="E"),
            _record(
                payment_date=datetime(2026, 1, 31, 23, 59, tzinfo=UTC),
                payroll_type="O",
                total_perceptions=Decimal("20"),
            ),
            _record(
                payment_date=datetime(2026, 2, 1, 0, 0, tzinfo=UTC),
                payroll_type="E",
                total_perceptions=Decimal("30"),
            ),
        ]
    )

    assert [(row.month, row.payroll_type, row.count) for row in report.rows] == [
        ("2026-01", "O", 1),
        ("2026-02", "E", 2),
    ]
    assert report.rows[1].total_perceptions == Decimal("1030")


def test_payroll_summary_keeps_missing_and_nonfinite_values_none() -> None:
    report = summarize_payroll(
        [
            _record(
                paid_days=None,
                total_deductions=Decimal("NaN"),
                incomplete_count=2,
            )
        ]
    )

    row = report.rows[0]
    assert report.source_status == "partial"
    assert report.incomplete_count == 2
    assert row.incomplete_count == 2
    assert row.paid_days is None
    assert row.total_deductions is None
    assert row.total_perceptions == Decimal("1000")
    assert row.total_other_payments == Decimal("50")
    assert row.as_dict()["paid_days"] is None


def test_payroll_summary_preserves_upstream_statuses_and_empty_input() -> None:
    empty = PayrollNormalizationResult((), "4.0", "1.2", None, "empty", False)
    unsupported = PayrollNormalizationResult((), "unknown", None, None, "unsupported-error", True)
    partial = PayrollNormalizationResult((), "4.0", "1.2", None, "partial", True)

    assert summarize_payroll(empty).source_status == "empty"
    assert summarize_payroll(unsupported).source_status == "unsupported"
    assert summarize_payroll(partial).source_status == "partial"
    assert summarize_payroll([]).source_status == "empty"


def test_payroll_summary_marks_unsupported_type_without_echoing_input() -> None:
    report = summarize_payroll([_record(payroll_type="unexpected-secret")])

    assert report.source_status == "unsupported"
    assert report.rows[0].payroll_type == "UNKNOWN"
    assert "unexpected-secret" not in repr(report)
    assert "unexpected-secret" not in repr(report.as_dict())


def test_payroll_summary_serialization_and_repr_are_redacted() -> None:
    report = summarize_payroll([_record()])
    payload = report.to_public_dict()

    assert payload["record_count"] == 1
    assert payload["rows"][0]["total_perceptions"] == "1000"  # type: ignore[index]
    rendered = repr(report) + repr(report.rows[0]) + repr(payload)
    assert "document" not in rendered
    assert "PayrollRecord" not in rendered
    assert "RFC" not in rendered


def test_payroll_summary_is_exported_from_accounting_and_analysis_package() -> None:
    assert accounting_summarize_payroll is summarize_payroll


def test_payroll_summary_rejects_invalid_source_status_and_counts() -> None:
    with pytest.raises(ValueError, match="analysis-source-status-invalid"):
        summarize_payroll([], source_status="mystery")
    with pytest.raises(TypeError, match="payroll-summary-count-invalid"):
        summarize_payroll([_record(incomplete_count=-1)])
