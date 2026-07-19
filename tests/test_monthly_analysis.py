from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal

import pytest

from cfdi_vault.analysis.monthly import MonthlyAnalysisRecord, analyze_monthly


def _record(**overrides: object) -> MonthlyAnalysisRecord:
    values: dict[str, object] = {
        "issue_date": date(2026, 1, 10),
        "direction": "received",
        "currency": "MXN",
        "subtotal": Decimal("100.00"),
        "total": Decimal("116.00"),
        "status": "Vigente",
        "source_kind": "xml",
    }
    values.update(overrides)
    return MonthlyAnalysisRecord(**values)  # type: ignore[arg-type]


def test_monthly_analysis_separates_direction_currency_and_source() -> None:
    report = analyze_monthly(
        [
            _record(),
            _record(status="Cancelado", source_kind="metadata"),
            _record(direction="issued", currency="USD", total=Decimal("10.00")),
        ]
    )

    assert len(report.rows) == 2
    received = next(row for row in report.rows if row.direction == "received")
    issued = next(row for row in report.rows if row.direction == "issued")
    assert received.count == 2
    assert received.total == Decimal("232.00")
    assert received.cancelled_count == 1
    assert (received.metadata_count, received.xml_count) == (1, 1)
    assert issued.currency == "USD"
    assert issued.total == Decimal("10.00")


def test_monthly_analysis_uses_inclusive_bounds_and_preserves_months() -> None:
    report = analyze_monthly(
        [
            _record(issue_date=datetime(2026, 1, 31, 23, tzinfo=timezone.utc)),
            _record(issue_date=date(2026, 2, 1)),
            _record(issue_date=date(2026, 3, 1)),
        ],
        start=date(2026, 1, 31),
        end=date(2026, 2, 1),
    )

    assert [(row.month, row.count) for row in report.rows] == [("2026-01", 1), ("2026-02", 1)]


def test_monthly_analysis_rejects_invalid_period_and_mixed_amount_types() -> None:
    with pytest.raises(ValueError, match="analysis-period-invalid"):
        analyze_monthly([], start=date(2026, 2, 1), end=date(2026, 1, 1))
    with pytest.raises(TypeError, match="analysis-amount-invalid"):
        analyze_monthly([_record(total=116.0)])


def test_monthly_analysis_rejects_unknown_source_kind() -> None:
    with pytest.raises(ValueError, match="analysis-source-invalid"):
        analyze_monthly([_record(source_kind="csv")])


def test_monthly_analysis_reports_bounded_status_counts() -> None:
    report = analyze_monthly(
        [
            _record(status="Vigente"),
            _record(status="Cancelado"),
            _record(status="estado-no-reconocido"),
            _record(status=None),
        ]
    )

    row = report.rows[0]
    assert row.count == 4
    assert row.active_count == 1
    assert row.cancelled_count == 1
    assert row.unknown_status_count == 2


def test_monthly_analysis_builds_deltas_only_with_prior_evidence() -> None:
    report = analyze_monthly(
        [
            _record(issue_date=date(2026, 1, 10), total=Decimal("10.00")),
            _record(issue_date=date(2026, 2, 10), total=Decimal("25.00")),
            _record(issue_date=date(2026, 4, 10), total=Decimal("40.00")),
        ]
    )

    assert [trend.month for trend in report.trends] == ["2026-01", "2026-02", "2026-04"]
    january, february, april = report.trends
    assert january.prior_month == "2025-12"
    assert not january.prior_available
    assert january.total_delta is None
    assert february.prior_month == "2026-01"
    assert february.prior_available
    assert february.count_delta == 0
    assert february.total_delta == Decimal("15.00")
    assert april.prior_month == "2026-03"
    assert not april.prior_available
    assert april.total_delta is None


def test_monthly_analysis_rejects_free_form_dimensions() -> None:
    with pytest.raises(ValueError, match="analysis-direction-invalid"):
        analyze_monthly([_record(direction="RFCABC010101AAA")])
    with pytest.raises(ValueError, match="analysis-currency-invalid"):
        analyze_monthly([_record(currency="C:/private")])
    with pytest.raises(ValueError, match="analysis-currency-invalid"):
        analyze_monthly([_record(currency="USDX")])


def test_monthly_analysis_separates_explicit_effect_and_document_type() -> None:
    report = analyze_monthly(
        [
            _record(effect="i", document_type="i"),
            _record(effect="E", document_type="E", total=Decimal("20.00")),
            _record(total=Decimal("30.00")),
        ]
    )

    assert [(row.effect, row.document_type, row.count, row.total) for row in report.rows] == [
        (None, None, 1, Decimal("30.00")),
        ("E", "E", 1, Decimal("20.00")),
        ("I", "I", 1, Decimal("116.00")),
    ]


def test_monthly_analysis_rejects_unsupported_effect_or_document_type() -> None:
    with pytest.raises(ValueError, match="analysis-effect-invalid"):
        analyze_monthly([_record(effect="received")])
    with pytest.raises(ValueError, match="analysis-document-type-invalid"):
        analyze_monthly([_record(document_type="invoice")])


def test_monthly_analysis_trends_keep_explicit_dimensions_separate() -> None:
    report = analyze_monthly(
        [
            _record(issue_date=date(2026, 1, 10), effect="I", document_type="I"),
            _record(issue_date=date(2026, 2, 10), effect="I", document_type="I", total=Decimal("25.00")),
            _record(issue_date=date(2026, 2, 10), effect="E", document_type="E", total=Decimal("8.00")),
        ]
    )

    february_issued = next(trend for trend in report.trends if trend.month == "2026-02" and trend.effect == "I")
    february_credit = next(trend for trend in report.trends if trend.month == "2026-02" and trend.effect == "E")
    assert february_issued.prior_available
    assert february_issued.total_delta == Decimal("-91.00")
    assert not february_credit.prior_available
