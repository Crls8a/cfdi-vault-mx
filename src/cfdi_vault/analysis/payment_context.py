"""Pure payment aggregates partitioned by UTC period and document context.

This module adds an explicit document direction to the existing payment
summary contract.  It consumes normalized :class:`PaymentRecord` values only;
it does not infer direction, read PostgreSQL, persist rows, contact SAT, or
decide whether a payment settles an invoice.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from cfdi_vault.analysis.accounting import PaymentSummaryReport, summarize_payments
from cfdi_vault.analysis.payments import PaymentRecord

_DIRECTIONS = frozenset({"received", "issued", "unknown"})
_CURRENCY = re.compile(r"^(?:[A-Z]{3}|UNKNOWN)$")
_PAYMENT_FORM = re.compile(r"^(?:\d{2}|UNKNOWN)$")
_STATUSES = frozenset({"complete", "partial", "empty", "unsupported"})

__all__ = [
    "PaymentAnalysisRecord",
    "PaymentContextSummary",
    "PaymentContextReport",
    "summarize_payments_by_context",
]


@dataclass(frozen=True, slots=True)
class PaymentAnalysisRecord:
    """One payment with an explicit, identifier-free document direction."""

    payment: PaymentRecord
    direction: str

    def __post_init__(self) -> None:
        if not isinstance(self.payment, PaymentRecord):
            raise TypeError("payment-context-record-required")
        object.__setattr__(self, "direction", _direction(self.direction))
        if _payment_date(self.payment.payment_date) is None:
            raise TypeError("payment-context-date-required")
        _currency(self.payment.currency)
        _payment_form(self.payment.payment_form)

    def __repr__(self) -> str:
        return "PaymentAnalysisRecord(<redacted>)"


@dataclass(frozen=True, slots=True)
class PaymentContextSummary:
    """One month/direction/currency/form payment summary."""

    month: str
    direction: str
    currency: str
    payment_form: str
    summary: PaymentSummaryReport

    def __post_init__(self) -> None:
        if re.fullmatch(r"\d{4}-(?:0[1-9]|1[0-2])", self.month) is None:
            raise ValueError("payment-context-month-invalid")
        object.__setattr__(self, "direction", _direction(self.direction))
        object.__setattr__(self, "currency", _currency(self.currency))
        object.__setattr__(self, "payment_form", _payment_form(self.payment_form))
        if not isinstance(self.summary, PaymentSummaryReport):
            raise TypeError("payment-context-summary-required")

    def as_dict(self) -> dict[str, Any]:
        """Return aggregate fields only, excluding provenance and source rows."""

        return {
            "month": self.month,
            "direction": self.direction,
            "currency": self.currency,
            "payment_form": self.payment_form,
            "status": self.summary.source_status,
            "incomplete_count": self.summary.incomplete_count,
            "rows": [_summary_row(row) for row in self.summary.rows],
        }

    def __repr__(self) -> str:
        return "PaymentContextSummary(<redacted>)"


@dataclass(frozen=True, slots=True)
class PaymentContextReport:
    """Deterministic contextual payment summaries and source status."""

    contexts: tuple[PaymentContextSummary, ...]
    source_status: str

    def __post_init__(self) -> None:
        if type(self.contexts) is not tuple or any(
            not isinstance(item, PaymentContextSummary) for item in self.contexts
        ):
            raise TypeError("payment-context-summaries-required")
        if self.source_status not in _STATUSES:
            raise ValueError("payment-context-source-status-invalid")
        keys = tuple((item.month, item.direction, item.currency, item.payment_form) for item in self.contexts)
        if keys != tuple(sorted(keys)):
            raise ValueError("payment-context-order-invalid")

    @property
    def rows(self) -> tuple[PaymentContextSummary, ...]:
        """Return contextual summaries under the common report terminology."""

        return self.contexts

    def as_dict(self) -> dict[str, Any]:
        """Return sanitized aggregate output."""

        return {"status": self.source_status, "contexts": [item.as_dict() for item in self.contexts]}

    def __repr__(self) -> str:
        return "PaymentContextReport(<redacted>)"


def summarize_payments_by_context(
    records: Iterable[PaymentAnalysisRecord],
    *,
    start: date | datetime | None = None,
    end: date | datetime | None = None,
    source_status: str | None = None,
) -> PaymentContextReport:
    """Group payment arithmetic by UTC month, direction, currency, and form.

    Direction is required from the caller and is never inferred.  Bounds are
    inclusive after conversion to a UTC calendar date.  Numeric incompleteness
    and parser status remain explicit through :func:`summarize_payments`.

    Raises:
        TypeError: for non-iterables, wrong record types, or missing dates.
        ValueError: for invalid dimensions, source status, or reversed bounds.
    """

    start_date = _optional_date(start)
    end_date = _optional_date(end)
    if start_date is not None and end_date is not None and start_date > end_date:
        raise ValueError("analysis-period-invalid")
    if isinstance(records, (str, bytes)):
        raise TypeError("payment-context-records-required")
    _status(source_status) if source_status is not None else None
    try:
        iterator = iter(records)
    except TypeError as exc:
        raise TypeError("payment-context-records-required") from exc

    groups: defaultdict[tuple[str, str, str, str], list[PaymentRecord]] = defaultdict(list)
    for item in iterator:
        if not isinstance(item, PaymentAnalysisRecord):
            raise TypeError("payment-context-record-required")
        payment_date = _payment_date(item.payment.payment_date)
        if payment_date is None:  # defensive: dataclass validation already rejects it
            raise TypeError("payment-context-date-required")
        if start_date is not None and payment_date < start_date:
            continue
        if end_date is not None and payment_date > end_date:
            continue
        currency = _currency(item.payment.currency)
        payment_form = _payment_form(item.payment.payment_form)
        key = (payment_date.strftime("%Y-%m"), item.direction, currency, payment_form)
        groups[key].append(item.payment)

    contexts = tuple(
        PaymentContextSummary(
            month,
            direction,
            currency,
            payment_form,
            summarize_payments(values, source_status=source_status),
        )
        for (month, direction, currency, payment_form), values in sorted(groups.items())
    )
    return PaymentContextReport(contexts, _report_status(contexts, source_status))


def _report_status(contexts: tuple[PaymentContextSummary, ...], explicit: str | None) -> str:
    normalized = _status(explicit) if explicit is not None else None
    if normalized in {"unsupported", "partial"}:
        return normalized
    if not contexts:
        return "empty"
    statuses = {context.summary.source_status for context in contexts}
    if "unsupported" in statuses:
        return "unsupported"
    if "partial" in statuses:
        return "partial"
    return "complete"


def _status(value: str) -> str:
    normalized = str(value).strip().lower().replace("_", "-")
    if normalized == "unsupported-error":
        normalized = "unsupported"
    if normalized not in _STATUSES:
        raise ValueError("analysis-source-status-invalid")
    return normalized


def _optional_date(value: date | datetime | None) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return normalized.date()
    if type(value) is date:
        return value
    raise TypeError("analysis-date-invalid")


def _payment_date(value: datetime | None) -> date | None:
    if value is None or not isinstance(value, datetime):
        return None
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.date()


def _direction(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("payment-context-direction-required")
    normalized = value.strip().lower()
    if normalized not in _DIRECTIONS:
        raise ValueError("payment-context-direction-invalid")
    return normalized


def _currency(value: str | None) -> str:
    if value is None:
        return "UNKNOWN"
    if not isinstance(value, str):
        raise TypeError("payment-context-currency-required")
    normalized = value.strip().upper() or "UNKNOWN"
    if _CURRENCY.fullmatch(normalized) is None:
        raise ValueError("payment-context-currency-invalid")
    return normalized


def _payment_form(value: str | None) -> str:
    if value is None:
        return "UNKNOWN"
    if not isinstance(value, str):
        raise TypeError("payment-context-form-required")
    normalized = value.strip().upper() or "UNKNOWN"
    if _PAYMENT_FORM.fullmatch(normalized) is None:
        raise ValueError("payment-context-form-invalid")
    return normalized


def _summary_row(row: object) -> dict[str, Any]:
    return {
        "month": row.month,
        "currency": row.currency,
        "payment_form": row.payment_form,
        "count": row.count,
        "amount": _decimal_text(row.amount),
        "related_document_count": row.related_document_count,
        "incomplete_count": row.incomplete_count,
    }


def _decimal_text(value: Decimal | None) -> str | None:
    return None if value is None else format(value, "f")
