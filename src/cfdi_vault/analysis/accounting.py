"""Pure, redacted aggregates for tax and payment evidence.

The functions in this module consume already-normalized records only.  They
do not read PostgreSQL or artifacts, contact SAT, infer tax liability, or
decide accounting treatment.  Missing or unsupported source fields remain
visible through a status on the returned report instead of being guessed.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal

from cfdi_vault.analysis.payments import PaymentRecord
from cfdi_vault.analysis.payroll_accounting import PayrollSummaryReport, PayrollSummaryRow, summarize_payroll
from cfdi_vault.analysis.taxes import TaxRecord

_ZERO = Decimal("0")
_KNOWN_TAX_TYPES = frozenset({"transferred", "withheld"})
_KNOWN_TAXES = frozenset({"001", "002", "003"})
_KNOWN_FACTORS = {"tasa": "Tasa", "cuota": "Cuota", "exento": "Exento"}

__all__ = [
    "TaxSummaryRow",
    "TaxSummaryReport",
    "summarize_taxes",
    "PaymentSummaryRow",
    "PaymentSummaryReport",
    "summarize_payments",
    "PayrollSummaryRow",
    "PayrollSummaryReport",
    "summarize_payroll",
]


@dataclass(frozen=True)
class TaxSummaryRow:
    """One aggregate tax bucket, without row-level provenance."""

    tax_type: str
    tax: str
    factor_type: str
    count: int
    base: Decimal | None
    amount: Decimal | None
    rate_or_quota: Decimal | None
    incomplete_count: int = 0

    @property
    def base_total(self) -> Decimal | None:
        """Alias for the aggregated taxable base."""

        return self.base

    @property
    def amount_total(self) -> Decimal | None:
        """Alias for the aggregated tax amount."""

        return self.amount

    @property
    def rate_or_quota_total(self) -> Decimal | None:
        """Alias for the decimal rate/quota sum."""

        return self.rate_or_quota

    def __repr__(self) -> str:
        """Avoid exposing source details through a diagnostic representation."""

        return "TaxSummaryRow(<redacted>)"


@dataclass(frozen=True)
class TaxSummaryReport:
    """Deterministic tax aggregates and source-completeness status."""

    rows: tuple[TaxSummaryRow, ...]
    source_status: str
    incomplete_count: int = 0

    @property
    def status(self) -> str:
        """Return the source status using a concise compatibility name."""

        return self.source_status

    def __repr__(self) -> str:
        """Return a redacted representation with no fiscal row details."""

        return f"TaxSummaryReport(rows=<redacted>, source_status={self.source_status!r})"


@dataclass(frozen=True)
class PaymentSummaryRow:
    """One UTC month/currency/payment-form aggregate."""

    month: str
    currency: str
    payment_form: str
    count: int
    amount: Decimal | None
    related_document_count: int
    incomplete_count: int = 0

    @property
    def amount_total(self) -> Decimal | None:
        """Alias for the aggregated payment amount."""

        return self.amount

    def __repr__(self) -> str:
        """Avoid exposing source details through a diagnostic representation."""

        return "PaymentSummaryRow(<redacted>)"


@dataclass(frozen=True)
class PaymentSummaryReport:
    """Deterministic payment aggregates and source-completeness status."""

    rows: tuple[PaymentSummaryRow, ...]
    source_status: str
    incomplete_count: int = 0

    @property
    def status(self) -> str:
        """Return the source status using a concise compatibility name."""

        return self.source_status

    def __repr__(self) -> str:
        """Return a redacted representation with no fiscal row details."""

        return f"PaymentSummaryReport(rows=<redacted>, source_status={self.source_status!r})"


def summarize_taxes(
    records: Iterable[TaxRecord],
    *,
    source_status: str | None = None,
) -> TaxSummaryReport:
    """Group taxes by type, tax code, and factor without inferring liability.

    Only ``Decimal`` values contribute to sums.  Missing or non-Decimal
    numeric values increment ``incomplete_count`` and never become zero.  An
    empty input is ``empty``; unknown tax dimensions are ``unsupported``;
    otherwise incomplete source fields produce ``partial``.
    """

    upstream_status = _source_status(records, source_status)
    buckets: defaultdict[tuple[str, str, str], dict[str, object]] = defaultdict(_new_tax_bucket)
    total_incomplete = 0
    unsupported = False
    seen = False
    for record in records:
        seen = True
        tax_type = str(record.tax_type).strip().lower() or "UNKNOWN"
        tax = str(record.tax).strip().upper() or "UNKNOWN"
        factor_key = str(record.factor_type or "").strip().lower()
        factor = _KNOWN_FACTORS.get(factor_key, "UNKNOWN")
        unsupported = unsupported or tax_type not in _KNOWN_TAX_TYPES or tax not in _KNOWN_TAXES
        if record.factor_type is not None and factor == "UNKNOWN":
            unsupported = True
        key = (tax_type, tax, factor)
        bucket = buckets[key]
        bucket["count"] = int(bucket["count"]) + 1
        missing = 0
        for field_name in ("base", "amount", "rate_or_quota"):
            value = getattr(record, field_name)
            if isinstance(value, Decimal) and value.is_finite():
                bucket[field_name] = bucket[field_name] + value
                bucket[f"{field_name}_count"] = int(bucket[f"{field_name}_count"]) + 1
            else:
                missing += 1
        if record.factor_type is None:
            missing += 1
        bucket["incomplete_count"] = int(bucket["incomplete_count"]) + missing
        total_incomplete += missing

    if upstream_status == "unsupported":
        status = "unsupported"
    elif upstream_status == "partial":
        status = "partial"
    elif not seen:
        status = "empty"
    elif unsupported:
        status = "unsupported"
    elif total_incomplete:
        status = "partial"
    else:
        status = "complete"

    rows = tuple(
        TaxSummaryRow(
            tax_type=tax_type,
            tax=tax,
            factor_type=factor,
            count=int(values["count"]),
            base=_sum_or_none(values["base"], values["base_count"]),
            amount=_sum_or_none(values["amount"], values["amount_count"]),
            rate_or_quota=_sum_or_none(values["rate_or_quota"], values["rate_or_quota_count"]),
            incomplete_count=int(values["incomplete_count"]),
        )
        for (tax_type, tax, factor), values in sorted(buckets.items())
    )
    return TaxSummaryReport(rows=rows, source_status=status, incomplete_count=total_incomplete)


def summarize_payments(
    records: Iterable[PaymentRecord],
    *,
    start: date | datetime | None = None,
    end: date | datetime | None = None,
    source_status: str | None = None,
) -> PaymentSummaryReport:
    """Group payments by UTC month, currency, and payment form.

    Bounds are inclusive after conversion to a UTC calendar date.  Missing or
    non-Decimal amounts contribute to the payment count but not the sum and
    are reported as incomplete; they are never silently converted to zero.
    Records without a usable UTC date are reported as incomplete and omitted
    from month buckets.
    """

    upstream_status = _source_status(records, source_status)
    start_date = _bound_date(start)
    end_date = _bound_date(end)
    if start_date is not None and end_date is not None and start_date > end_date:
        raise ValueError("analysis-period-invalid")

    buckets: defaultdict[tuple[str, str, str], dict[str, object]] = defaultdict(_new_payment_bucket)
    total_incomplete = 0
    unsupported = False
    seen = False
    for record in records:
        seen = True
        payment_date = _payment_date(record.payment_date)
        if payment_date is None:
            total_incomplete += 1
            continue
        if start_date is not None and payment_date < start_date:
            continue
        if end_date is not None and payment_date > end_date:
            continue
        currency = str(record.currency or "").strip().upper() or "UNKNOWN"
        payment_form = str(record.payment_form or "").strip() or "UNKNOWN"
        if currency == "XXX":
            unsupported = True
        key = (payment_date.strftime("%Y-%m"), currency, payment_form)
        bucket = buckets[key]
        bucket["count"] = int(bucket["count"]) + 1
        related = record.related_document_count
        if isinstance(related, int) and related >= 0:
            bucket["related_document_count"] = int(bucket["related_document_count"]) + related
        else:
            bucket["incomplete_count"] = int(bucket["incomplete_count"]) + 1
            total_incomplete += 1
        amount = record.amount
        if isinstance(amount, Decimal) and amount.is_finite():
            bucket["amount"] = bucket["amount"] + amount
            bucket["amount_count"] = int(bucket["amount_count"]) + 1
        else:
            bucket["incomplete_count"] = int(bucket["incomplete_count"]) + 1
            total_incomplete += 1
        if currency == "UNKNOWN" or payment_form == "UNKNOWN":
            bucket["incomplete_count"] = int(bucket["incomplete_count"]) + 1
            total_incomplete += 1

    if upstream_status == "unsupported":
        status = "unsupported"
    elif upstream_status == "partial":
        status = "partial"
    elif not seen or not buckets and not total_incomplete:
        status = "empty"
    elif unsupported:
        status = "unsupported"
    elif total_incomplete:
        status = "partial"
    else:
        status = "complete"

    rows = tuple(
        PaymentSummaryRow(
            month=month,
            currency=currency,
            payment_form=payment_form,
            count=int(values["count"]),
            amount=_sum_or_none(values["amount"], values["amount_count"]),
            related_document_count=int(values["related_document_count"]),
            incomplete_count=int(values["incomplete_count"]),
        )
        for (month, currency, payment_form), values in sorted(buckets.items())
    )
    return PaymentSummaryReport(rows=rows, source_status=status, incomplete_count=total_incomplete)


def _new_tax_bucket() -> dict[str, object]:
    return {
        "count": 0,
        "base": _ZERO,
        "base_count": 0,
        "amount": _ZERO,
        "amount_count": 0,
        "rate_or_quota": _ZERO,
        "rate_or_quota_count": 0,
        "incomplete_count": 0,
    }


def _new_payment_bucket() -> dict[str, object]:
    return {"count": 0, "amount": _ZERO, "amount_count": 0, "related_document_count": 0, "incomplete_count": 0}


def _sum_or_none(value: object, count: object) -> Decimal | None:
    return value if int(count) else None


def _bound_date(value: date | datetime | None) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _payment_date(value)
    if isinstance(value, date):
        return value
    raise TypeError("analysis-date-invalid")


def _payment_date(value: datetime | None) -> date | None:
    if value is None or not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).date()


def _source_status(records: Iterable[object], explicit: str | None) -> str | None:
    """Map parser status evidence without exposing parser payloads."""

    value = explicit if explicit is not None else getattr(records, "parser_status", None)
    if value is None:
        return None
    normalized = str(value).strip().lower().replace("_", "-")
    if normalized in {"unsupported", "unsupported-error"}:
        return "unsupported"
    if normalized == "partial":
        return "partial"
    if normalized == "empty":
        return "empty"
    if normalized == "complete":
        return "complete"
    raise ValueError("analysis-source-status-invalid")
