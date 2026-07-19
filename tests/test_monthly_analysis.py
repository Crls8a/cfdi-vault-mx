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
