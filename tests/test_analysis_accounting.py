from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

from cfdi_vault.analysis.accounting import (
    PaymentSummaryReport,
    TaxSummaryReport,
    summarize_payments,
    summarize_taxes,
)
from cfdi_vault.analysis.payments import PaymentNormalizationResult, PaymentRecord
from cfdi_vault.analysis.taxes import TaxNormalizationResult, TaxRecord


def _tax(**overrides: object) -> TaxRecord:
    values: dict[str, object] = {
        "tax_type": "transferred",
        "tax": "002",
        "factor_type": "Tasa",
        "rate_or_quota": Decimal("0.160000"),
        "base": Decimal("100.00"),
        "amount": Decimal("16.00"),
        "concept_ordinal": 1,
        "document_scope": "concept",
        "provenance": "document",
    }
    values.update(overrides)
    return TaxRecord(**values)  # type: ignore[arg-type]


def _payment(**overrides: object) -> PaymentRecord:
    values: dict[str, object] = {
        "payment_date": datetime(2026, 1, 31, 23, 30, tzinfo=UTC),
        "payment_form": "03",
        "currency": "MXN",
        "amount": Decimal("116.00"),
        "exchange_rate": None,
        "related_document_count": 2,
        "provenance": "document",
    }
    values.update(overrides)
    return PaymentRecord(**values)  # type: ignore[arg-type]


def test_tax_summary_separates_dimensions_and_sums_decimal_values() -> None:
    report = summarize_taxes([_tax(), _tax(amount=Decimal("8.00"), factor_type="Cuota")])

    assert isinstance(report, TaxSummaryReport)
    assert report.source_status == "complete"
    assert [(row.tax, row.factor_type, row.count) for row in report.rows] == [
        ("002", "Cuota", 1),
        ("002", "Tasa", 1),
    ]
    tasa = report.rows[1]
    assert tasa.amount == Decimal("16.00")
    assert tasa.amount_total == tasa.amount


def test_tax_summary_marks_missing_and_non_decimal_values_partial() -> None:
    report = summarize_taxes(
        [
            _tax(base=None, rate_or_quota=0.16),
            _tax(amount=None),
        ]
    )

    assert report.source_status == "partial"
    assert report.incomplete_count == 3
    assert report.rows[0].base == Decimal("100.00")
    assert report.rows[0].amount == Decimal("16.00")
    assert report.rows[0].rate_or_quota == Decimal("0.160000")


def test_tax_summary_empty_and_unsupported_statuses() -> None:
    assert summarize_taxes([]).source_status == "empty"
    report = summarize_taxes([_tax(tax="999")])
    assert report.source_status == "unsupported"


def test_tax_summary_preserves_upstream_empty_partial_and_unsupported_statuses() -> None:
    assert summarize_taxes(TaxNormalizationResult((), "4.0", "empty")).source_status == "empty"
    assert summarize_taxes(TaxNormalizationResult((), "4.0", "partial")).source_status == "partial"
    assert summarize_taxes(TaxNormalizationResult((), "unknown", "unsupported-error")).source_status == "unsupported"


def test_payment_summary_uses_utc_month_currency_and_form_with_inclusive_bounds() -> None:
    report = summarize_payments(
        [
            _payment(),
            _payment(
                payment_date=datetime(2026, 2, 1, 0, 15, tzinfo=UTC),
                currency="USD",
                payment_form="01",
                amount=Decimal("10.00"),
                related_document_count=1,
            ),
        ],
        start=date(2026, 1, 31),
        end=date(2026, 2, 1),
    )

    assert isinstance(report, PaymentSummaryReport)
    assert [(row.month, row.currency, row.payment_form) for row in report.rows] == [
        ("2026-01", "MXN", "03"),
        ("2026-02", "USD", "01"),
    ]
    assert report.rows[0].amount == Decimal("116.00")
    assert report.rows[0].related_document_count == 2


def test_payment_summary_marks_missing_amount_and_keeps_count() -> None:
    report = summarize_payments([_payment(amount=None)])

    assert report.source_status == "partial"
    assert report.incomplete_count == 1
    assert report.rows[0].count == 1
    assert report.rows[0].amount is None


def test_payment_summary_keeps_unknown_related_count_as_none() -> None:
    report = summarize_payments([_payment(related_document_count=None)])
    assert report.source_status == "partial"
    assert report.rows[0].related_document_count is None
    assert report.rows[0].incomplete_count == 1


def test_payment_summary_preserves_upstream_empty_partial_and_unsupported_statuses() -> None:
    empty = PaymentNormalizationResult((), "4.0", "2.0", "empty", False)
    partial = PaymentNormalizationResult((), "4.0", "2.0", "partial", True)
    unsupported = PaymentNormalizationResult((), "unknown", None, "unsupported-error", False)
    assert summarize_payments(empty).source_status == "empty"
    assert summarize_payments(partial).source_status == "partial"
    assert summarize_payments(unsupported).source_status == "unsupported"


def test_payment_summary_is_deterministic_and_redacted() -> None:
    records = [_payment(), _payment(currency="USD", amount=Decimal("4.00"))]
    first = summarize_payments(records)
    second = summarize_payments(reversed(records))

    assert first == second
    rendered = repr(first) + repr(first.rows[0])
    assert "document" not in rendered
    assert "PaymentRecord" not in rendered


def test_accounting_summaries_reject_reversed_period() -> None:
    with pytest.raises(ValueError, match="analysis-period-invalid"):
        summarize_payments([], start=date(2026, 2, 1), end=date(2026, 1, 1))
