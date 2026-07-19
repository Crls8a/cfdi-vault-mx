from __future__ import annotations

from decimal import Decimal

import pytest

from cfdi_vault.analysis.payment_reconciliation import (
    InvoiceApplicationCandidate,
    PaymentApplicationCandidate,
    reconcile_payment_applications,
)


def _invoice(ref: str = "invoice-a", amount: str = "100", currency: str = "MXN", **kwargs: object):
    return InvoiceApplicationCandidate(ref, currency, Decimal(amount), **kwargs)


def _application(
    payment: str | None = "payment-a",
    invoice: str | None = "invoice-a",
    amount: str | None = "100",
    currency: str | None = "MXN",
    **kwargs: object,
):
    return PaymentApplicationCandidate(
        payment, invoice, currency, None if amount is None else Decimal(amount), **kwargs
    )


def test_exact_allocation_is_applied_and_currency_is_preserved() -> None:
    report = reconcile_payment_applications(
        [_invoice()],
        [_application(amount="40"), _application(payment="payment-b", amount="60")],
    )

    assert report.status == "complete"
    assert report.complete is True
    assert report.counts["applied"] == 2
    assert report.rows[0].amount == Decimal("100")
    assert report.rows[0].currency == "MXN"


def test_over_allocation_is_conflict_and_is_not_clipped_to_balance() -> None:
    report = reconcile_payment_applications([_invoice(amount="100")], [_application(amount="101")])

    assert report.status == "partial"
    assert report.counts["duplicate_conflict"] == 1
    assert report.counts["applied"] == 0
    assert report.rows[0].amount == Decimal("101")


def test_duplicate_link_is_counted_once_as_applied_then_as_conflict() -> None:
    application = _application(amount="50")
    report = reconcile_payment_applications([_invoice()], [application, application])

    assert report.counts["applied"] == 1
    assert report.counts["duplicate_conflict"] == 1
    assert report.rows[0].amount == Decimal("50")


def test_canonical_order_handles_reversed_overallocation() -> None:
    low = _application(payment="payment-a", amount="60")
    high = _application(payment="payment-a", amount="70")
    forward = reconcile_payment_applications([_invoice(amount="100")], [low, high])
    reverse = reconcile_payment_applications([_invoice(amount="100")], [high, low])

    assert forward == reverse
    assert forward.counts["applied"] == 1
    assert forward.counts["duplicate_conflict"] == 1


@pytest.mark.parametrize(
    ("payment", "invoice", "expected"),
    [
        (None, "invoice-a", "missing_identity"),
        ("payment-a", None, "unapplied"),
        ("payment-a", "missing-invoice", "missing_identity"),
    ],
)
def test_identity_gaps_are_not_interpreted_as_paid(payment: str | None, invoice: str | None, expected: str) -> None:
    report = reconcile_payment_applications([_invoice()], [_application(payment, invoice)])

    assert report.counts[expected] == 1
    assert report.counts["applied"] == 0


def test_mixed_currency_is_invalid_and_never_netted() -> None:
    report = reconcile_payment_applications(
        [_invoice(currency="USD", amount="20")],
        [_application(currency="MXN", amount="400")],
    )

    assert report.status == "partial"
    assert report.counts["invalid_partial"] == 1
    assert report.rows[0].currency == "MXN"
    assert report.rows[0].amount == Decimal("400")


@pytest.mark.parametrize("status,expected", [("partial", "partial"), ("unsupported-error", "unsupported")])
def test_partial_and_unsupported_evidence_are_explicit(status: str, expected: str) -> None:
    report = reconcile_payment_applications([_invoice()], [_application(evidence_status=status)])

    assert report.status == expected
    assert report.counts["invalid_partial"] == 1
    assert report.incomplete_count == 1


def test_recomputation_is_idempotent_and_order_independent() -> None:
    invoices = [_invoice(amount="20"), _invoice("invoice-b", "50", "USD")]
    applications = [_application(amount="20"), _application("payment-b", "invoice-b", "50", "USD")]

    first = reconcile_payment_applications(invoices, applications)
    second = reconcile_payment_applications(reversed(invoices), reversed(applications))

    assert first == second
    assert first.as_dict() == second.as_dict()


def test_opaque_references_never_leave_candidate_or_report() -> None:
    candidate = _application(payment="private-payment", invoice="invoice-a", amount="1")
    report = reconcile_payment_applications([_invoice()], [candidate])

    assert "private-payment" not in repr(candidate)
    assert "private-payment" not in repr(report)
    assert "private-payment" not in repr(report.as_dict())


@pytest.mark.parametrize("value", ["123e4567-e89b-" + "12d3-a456-" + "426614174000", "AAA010101AAA", "C:\\secret"])
def test_sensitive_or_path_like_references_are_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        _application(payment=value)


def test_empty_report_is_explicitly_empty() -> None:
    report = reconcile_payment_applications([], [])

    assert report.status == "empty"
    assert report.complete is False
    assert report.counts["applied"] == 0
    assert report.as_dict()["rows"] == []


def test_unapplied_only_is_source_complete_but_not_allocation_complete() -> None:
    report = reconcile_payment_applications([], [_application(invoice=None)])

    assert report.status == "complete"
    assert report.complete is True
    assert report.allocation_complete is False
    assert report.counts["unapplied"] == 1


def test_explicit_partial_source_status_is_preserved() -> None:
    report = reconcile_payment_applications([_invoice()], [_application()], source_status="partial")

    assert report.status == "partial"
