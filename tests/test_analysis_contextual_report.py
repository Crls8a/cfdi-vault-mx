from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from cfdi_vault.analysis.contextual_report import (
    ContextualReportBundle,
    compose_contextual_report_bundle,
)
from cfdi_vault.analysis.payment_context import PaymentAnalysisRecord, summarize_payments_by_context
from cfdi_vault.analysis.payments import PaymentRecord
from cfdi_vault.analysis.quality import QualityObservation
from cfdi_vault.analysis.quality_context import QualityAnalysisRecord, summarize_quality_by_context
from cfdi_vault.analysis.tax_context import TaxAnalysisRecord, summarize_taxes_by_context
from cfdi_vault.analysis.taxes import TaxRecord
from cfdi_vault.domain import ReconciliationState


def _tax(month: int, *, status: str | None = None):
    record = TaxAnalysisRecord(
        datetime(2026, month, 1, tzinfo=UTC),
        "received",
        "MXN",
        TaxRecord(
            tax_type="transferred",
            tax="002",
            factor_type="Tasa",
            rate_or_quota=Decimal("0.16"),
            base=Decimal("100"),
            amount=Decimal("16"),
            concept_ordinal=1,
            document_scope="concept",
            provenance="private-tax",
        ),
    )
    return record, status


def _payment(month: int, *, status: str | None = None):
    record = PaymentAnalysisRecord(
        PaymentRecord(
            payment_date=datetime(2026, month, 1, tzinfo=UTC),
            payment_form="03",
            currency="MXN",
            amount=Decimal("116"),
            exchange_rate=None,
            related_document_count=1,
            provenance="private-payment",
        ),
        "received",
    )
    return record, status


def _quality(month: int, *, status: str | None = None):
    record = QualityAnalysisRecord(
        datetime(2026, month, 1, tzinfo=UTC),
        QualityObservation(reconciliation_state=ReconciliationState.STATE_CHECKED),
        "received",
        "MXN",
    )
    return record, status


def _bundle(*, months: tuple[int, ...] = (1, 2), status: str | None = None):
    tax_rows = tuple(_tax(month)[0] for month in months)
    payment_rows = tuple(_payment(month)[0] for month in months)
    quality_rows = tuple(_quality(month)[0] for month in months)
    return compose_contextual_report_bundle(
        summarize_taxes_by_context(tax_rows, source_status=status),
        summarize_payments_by_context(payment_rows, source_status=status),
        summarize_quality_by_context(quality_rows, source_status=status),
    )


def test_composes_three_context_reports_with_same_month_bounds() -> None:
    bundle = _bundle()

    assert isinstance(bundle, ContextualReportBundle)
    assert bundle.source_status == "complete"
    assert bundle.month_bounds == ("2026-01", "2026-02")
    assert bundle.as_dict()["period"] == {"start_month": "2026-01", "end_month": "2026-02"}
    assert bundle.as_dict()["taxes"]["status"] == "complete"
    assert bundle.as_dict()["payments"]["status"] == "complete"
    assert bundle.as_dict()["quality"]["source_status"] == "complete"


def test_child_statuses_are_preserved_and_bundle_status_is_conservative() -> None:
    bundle = _bundle(status="partial")

    payload = bundle.as_dict()
    assert bundle.source_status == "partial"
    assert payload["taxes"]["status"] == "partial"
    assert payload["payments"]["status"] == "partial"
    assert payload["quality"]["source_status"] == "partial"


def test_all_empty_sources_have_empty_bundle_without_inventing_period() -> None:
    empty = compose_contextual_report_bundle(
        summarize_taxes_by_context(()),
        summarize_payments_by_context(()),
        summarize_quality_by_context(()),
    )

    assert empty.source_status == "empty"
    assert empty.month_bounds is None
    assert empty.as_dict()["period"] == {"start_month": None, "end_month": None}


def test_empty_child_is_partial_without_inventing_its_months() -> None:
    bundle = compose_contextual_report_bundle(
        summarize_taxes_by_context(tuple(_tax(month)[0] for month in (1, 2))),
        summarize_payments_by_context(tuple(_payment(month)[0] for month in (1, 2))),
        summarize_quality_by_context(()),
    )

    assert bundle.source_status == "partial"
    assert bundle.month_bounds == ("2026-01", "2026-02")
    assert bundle.as_dict()["period"] == {"start_month": "2026-01", "end_month": "2026-02"}
    assert bundle.as_dict()["quality"]["source_status"] == "empty"


def test_mismatched_month_bounds_are_rejected() -> None:
    taxes = summarize_taxes_by_context(tuple(_tax(month)[0] for month in (1, 2)))
    payments = summarize_payments_by_context(tuple(_payment(month)[0] for month in (1,)))
    quality = summarize_quality_by_context(tuple(_quality(month)[0] for month in (1, 2)))

    with pytest.raises(ValueError, match="contextual-report-period-mismatch"):
        compose_contextual_report_bundle(taxes, payments, quality)


def test_report_types_and_repr_are_fail_closed_and_redacted() -> None:
    bundle = _bundle()

    with pytest.raises(TypeError, match="tax-context-report-required"):
        compose_contextual_report_bundle(object(), bundle.payments, bundle.quality)  # type: ignore[arg-type]
    assert repr(bundle) == "ContextualReportBundle(<redacted>)"
    assert "private-tax" not in repr(bundle.as_dict())
    assert "private-payment" not in repr(bundle.as_dict())
