from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

from cfdi_vault.analysis.payment_context import (
    PaymentAnalysisRecord,
    PaymentContextReport,
    summarize_payments_by_context,
)
from cfdi_vault.analysis.payments import PaymentRecord


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


def _record(
    payment: PaymentRecord | None = None,
    *,
    direction: str = "received",
) -> PaymentAnalysisRecord:
    return PaymentAnalysisRecord(payment or _payment(), direction)


def test_groups_by_month_direction_currency_and_form_without_mixing() -> None:
    report = summarize_payments_by_context(
        (
            _record(),
            _record(direction="issued"),
            _record(_payment(currency="USD", payment_form="01"), direction="received"),
        )
    )

    assert [(row.month, row.direction, row.currency, row.payment_form) for row in report.rows] == [
        ("2026-01", "issued", "MXN", "03"),
        ("2026-01", "received", "MXN", "03"),
        ("2026-01", "received", "USD", "01"),
    ]
    assert report.rows[0].summary.rows[0].amount == Decimal("116.00")


def test_utc_dates_and_inclusive_bounds_are_applied() -> None:
    report = summarize_payments_by_context(
        (
            _record(_payment(payment_date=datetime(2026, 1, 1, 0, 1, tzinfo=UTC))),
            _record(_payment(payment_date=datetime(2026, 1, 31, 23, 59, tzinfo=UTC))),
            _record(_payment(payment_date=datetime(2026, 2, 1, tzinfo=UTC))),
        ),
        start=date(2026, 1, 1),
        end=date(2026, 1, 31),
    )

    assert len(report.rows) == 1
    assert report.rows[0].summary.rows[0].count == 2


def test_partial_payment_values_remain_explicit() -> None:
    report = summarize_payments_by_context((_record(_payment(amount=None)),))

    assert report.source_status == "partial"
    assert report.rows[0].summary.rows[0].amount is None
    assert report.rows[0].summary.rows[0].incomplete_count == 1


def test_unknown_dimensions_are_visible_but_not_inferred() -> None:
    report = summarize_payments_by_context((_record(_payment(currency=None, payment_form=None), direction="unknown"),))

    row = report.rows[0]
    assert (row.direction, row.currency, row.payment_form) == ("unknown", "UNKNOWN", "UNKNOWN")
    assert report.source_status == "partial"


def test_explicit_source_status_and_empty_input_are_preserved() -> None:
    assert summarize_payments_by_context((), source_status="partial").source_status == "partial"
    assert summarize_payments_by_context((), source_status="unsupported-error").source_status == "unsupported"
    assert summarize_payments_by_context(()).source_status == "empty"


def test_redacted_aggregate_output_never_contains_provenance() -> None:
    report = summarize_payments_by_context((_record(_payment(provenance="payment-private")),))

    payload = report.as_dict()
    rendered = repr(report)
    assert payload["contexts"][0]["rows"][0]["amount"] == "116.00"
    assert "payment-private" not in repr(payload)
    assert "payment-private" not in rendered


def test_context_validation_rejects_malformed_dimensions_and_period() -> None:
    with pytest.raises(ValueError, match="payment-context-direction-invalid"):
        _record(direction="sales")
    with pytest.raises(ValueError, match="payment-context-currency-invalid"):
        _record(_payment(currency="pesos"))
    with pytest.raises(ValueError, match="payment-context-form-invalid"):
        _record(_payment(payment_form="cash"))
    with pytest.raises(ValueError, match="analysis-period-invalid"):
        summarize_payments_by_context((), start=date(2026, 2, 1), end=date(2026, 1, 1))


def test_non_records_and_invalid_dates_are_rejected() -> None:
    with pytest.raises(TypeError, match="payment-context-record-required"):
        summarize_payments_by_context((object(),))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="payment-context-date-required"):
        _record(_payment(payment_date=None))
    with pytest.raises(ValueError, match="analysis-source-status-invalid"):
        summarize_payments_by_context((), source_status="guess")


def test_context_report_rejects_non_deterministic_order() -> None:
    report = summarize_payments_by_context(
        (_record(), _record(_payment(payment_date=datetime(2026, 2, 1, tzinfo=UTC))))
    )
    first, second = report.rows
    with pytest.raises(ValueError, match="payment-context-order-invalid"):
        PaymentContextReport((second, first), report.source_status)
