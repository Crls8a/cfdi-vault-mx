from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

from cfdi_vault.analysis.tax_context import (
    TaxAnalysisRecord,
    TaxContextReport,
    summarize_taxes_by_context,
)
from cfdi_vault.analysis.taxes import TaxRecord


def _tax(*, amount: Decimal | None = Decimal("16.00"), provenance: str = "xml-a") -> TaxRecord:
    return TaxRecord(
        tax_type="transferred",
        tax="002",
        factor_type="Tasa",
        rate_or_quota=Decimal("0.16"),
        base=Decimal("100.00"),
        amount=amount,
        concept_ordinal=1,
        document_scope="concept",
        provenance=provenance,
    )


def _record(
    issue_date: date | datetime,
    *,
    direction: str = "received",
    currency: str = "MXN",
    amount: Decimal | None = Decimal("16.00"),
    provenance: str = "xml-a",
) -> TaxAnalysisRecord:
    return TaxAnalysisRecord(issue_date, direction, currency, _tax(amount=amount, provenance=provenance))


def test_groups_by_month_direction_and_currency_without_mixing() -> None:
    report = summarize_taxes_by_context(
        (
            _record(date(2026, 1, 31), amount=Decimal("16.00")),
            _record(date(2026, 1, 31), direction="issued", amount=Decimal("8.00")),
            _record(date(2026, 2, 1), currency="USD", amount=Decimal("2.00")),
        )
    )

    assert [(row.month, row.direction, row.currency) for row in report.rows] == [
        ("2026-01", "issued", "MXN"),
        ("2026-01", "received", "MXN"),
        ("2026-02", "received", "USD"),
    ]
    assert report.rows[0].summary.rows[0].amount == Decimal("8.00")
    assert report.rows[1].summary.rows[0].amount == Decimal("16.00")
    assert report.rows[2].summary.rows[0].amount == Decimal("2.00")


def test_utc_dates_and_inclusive_bounds_are_applied() -> None:
    report = summarize_taxes_by_context(
        (
            _record(datetime(2026, 1, 1, 1, tzinfo=UTC)),
            _record(datetime(2026, 1, 31, 23, 59, tzinfo=UTC)),
            _record(date(2026, 2, 1)),
        ),
        start=date(2026, 1, 1),
        end=date(2026, 1, 31),
    )

    assert [row.month for row in report.rows] == ["2026-01"]
    assert report.rows[0].summary.rows[0].count == 2


def test_partial_and_missing_numeric_values_remain_explicit() -> None:
    report = summarize_taxes_by_context((_record(date(2026, 1, 1), amount=None),))

    assert report.source_status == "partial"
    assert report.rows[0].summary.rows[0].amount is None
    assert report.rows[0].summary.rows[0].incomplete_count == 1


def test_explicit_source_status_and_empty_input_are_preserved() -> None:
    assert summarize_taxes_by_context((), source_status="partial").source_status == "partial"
    assert summarize_taxes_by_context((), source_status="unsupported-error").source_status == "unsupported"
    assert summarize_taxes_by_context(()).source_status == "empty"


def test_redacted_aggregate_output_never_contains_provenance() -> None:
    report = summarize_taxes_by_context((_record(date(2026, 1, 1), provenance="xml-private"),))

    payload = report.as_dict()
    rendered = repr(report)
    assert payload["contexts"][0]["rows"][0]["amount"] == "16.00"
    assert "xml-private" not in repr(payload)
    assert "xml-private" not in rendered


def test_context_validation_rejects_inference_prone_dimensions() -> None:
    with pytest.raises(ValueError, match="tax-context-direction-invalid"):
        _record(date(2026, 1, 1), direction="sales")
    with pytest.raises(ValueError, match="tax-context-currency-invalid"):
        _record(date(2026, 1, 1), currency="pesos")
    with pytest.raises(TypeError, match="tax-context-currency-required"):
        _record(date(2026, 1, 1), currency=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="analysis-period-invalid"):
        summarize_taxes_by_context((), start=date(2026, 2, 1), end=date(2026, 1, 1))


def test_non_records_and_invalid_status_are_rejected() -> None:
    with pytest.raises(TypeError, match="tax-context-record-required"):
        summarize_taxes_by_context((object(),))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="analysis-source-status-invalid"):
        summarize_taxes_by_context((), source_status="guess")


def test_context_report_rejects_non_deterministic_order() -> None:
    report = summarize_taxes_by_context((_record(date(2026, 1, 1)), _record(date(2026, 2, 1))))
    first, second = report.rows
    with pytest.raises(ValueError, match="tax-context-order-invalid"):
        TaxContextReport((second, first), report.source_status)
