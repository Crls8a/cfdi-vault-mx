"""Pure tax aggregates partitioned by period, direction, and currency.

This module adds context around the existing :mod:`analysis.taxes` records
without reading PostgreSQL, persisting rows, contacting SAT, or inferring tax
treatment.  The context is supplied by a future tenant-safe ledger mapper.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from cfdi_vault.analysis.accounting import TaxSummaryReport, summarize_taxes
from cfdi_vault.analysis.taxes import TaxRecord

_DIRECTIONS = frozenset({"received", "issued", "unknown"})
_CURRENCY = re.compile(r"^(?:[A-Z]{3}|UNKNOWN)$")
_STATUSES = frozenset({"complete", "partial", "empty", "unsupported"})

__all__ = ["TaxAnalysisRecord", "TaxContextSummary", "TaxContextReport", "summarize_taxes_by_context"]


@dataclass(frozen=True, slots=True)
class TaxAnalysisRecord:
    """One tax record with explicit, identifier-free document context."""

    issue_date: date | datetime
    direction: str
    currency: str
    tax: TaxRecord

    def __post_init__(self) -> None:
        object.__setattr__(self, "issue_date", _as_date(self.issue_date))
        object.__setattr__(self, "direction", _direction(self.direction))
        object.__setattr__(self, "currency", _currency(self.currency))
        if not isinstance(self.tax, TaxRecord):
            raise TypeError("tax-context-record-required")

    def __repr__(self) -> str:
        return "TaxAnalysisRecord(<redacted>)"


@dataclass(frozen=True, slots=True)
class TaxContextSummary:
    """One month/direction/currency tax summary without source rows."""

    month: str
    direction: str
    currency: str
    summary: TaxSummaryReport

    def __post_init__(self) -> None:
        if not re.fullmatch(r"\d{4}-(?:0[1-9]|1[0-2])", self.month):
            raise ValueError("tax-context-month-invalid")
        object.__setattr__(self, "direction", _direction(self.direction))
        object.__setattr__(self, "currency", _currency(self.currency))
        if not isinstance(self.summary, TaxSummaryReport):
            raise TypeError("tax-context-summary-required")

    def as_dict(self) -> dict[str, Any]:
        return {
            "month": self.month,
            "direction": self.direction,
            "currency": self.currency,
            "status": self.summary.source_status,
            "incomplete_count": self.summary.incomplete_count,
            "rows": [_summary_row(row) for row in self.summary.rows],
        }

    def __repr__(self) -> str:
        return "TaxContextSummary(<redacted>)"


@dataclass(frozen=True, slots=True)
class TaxContextReport:
    """Deterministic tax summaries and one aggregate source status."""

    contexts: tuple[TaxContextSummary, ...]
    source_status: str

    def __post_init__(self) -> None:
        if type(self.contexts) is not tuple or any(not isinstance(item, TaxContextSummary) for item in self.contexts):
            raise TypeError("tax-context-summaries-required")
        if self.source_status not in _STATUSES:
            raise ValueError("tax-context-source-status-invalid")
        keys = tuple((item.month, item.direction, item.currency) for item in self.contexts)
        if keys != tuple(sorted(keys)):
            raise ValueError("tax-context-order-invalid")

    @property
    def rows(self) -> tuple[TaxContextSummary, ...]:
        return self.contexts

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.source_status, "contexts": [item.as_dict() for item in self.contexts]}

    def __repr__(self) -> str:
        return "TaxContextReport(<redacted>)"


def summarize_taxes_by_context(
    records: Iterable[TaxAnalysisRecord],
    *,
    start: date | datetime | None = None,
    end: date | datetime | None = None,
    source_status: str | None = None,
) -> TaxContextReport:
    """Group tax math by UTC month, direction, and currency.

    Currency and direction are never inferred.  Each group delegates numeric
    aggregation and incomplete-field handling to :func:`summarize_taxes`.
    """

    start_date = _optional_date(start)
    end_date = _optional_date(end)
    if start_date is not None and end_date is not None and start_date > end_date:
        raise ValueError("analysis-period-invalid")
    if isinstance(records, (str, bytes)):
        raise TypeError("tax-context-records-required")
    groups: defaultdict[tuple[str, str, str], list[TaxRecord]] = defaultdict(list)
    try:
        iterator = iter(records)
    except TypeError as exc:
        raise TypeError("tax-context-records-required") from exc
    for item in iterator:
        if not isinstance(item, TaxAnalysisRecord):
            raise TypeError("tax-context-record-required")
        if start_date is not None and item.issue_date < start_date:
            continue
        if end_date is not None and item.issue_date > end_date:
            continue
        key = (item.issue_date.strftime("%Y-%m"), item.direction, item.currency)
        groups[key].append(item.tax)
    contexts = tuple(
        TaxContextSummary(month, direction, currency, summarize_taxes(values, source_status=source_status))
        for (month, direction, currency), values in sorted(groups.items())
    )
    return TaxContextReport(contexts, _report_status(contexts, source_status))


def _report_status(contexts: tuple[TaxContextSummary, ...], explicit: str | None) -> str:
    normalized = _status(explicit) if explicit is not None else None
    if normalized == "unsupported":
        return normalized
    if normalized == "partial":
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


def _as_date(value: date | datetime) -> date:
    if isinstance(value, datetime):
        normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        return normalized.date()
    if type(value) is date:
        return value
    raise TypeError("tax-context-date-invalid")


def _optional_date(value: date | datetime | None) -> date | None:
    return None if value is None else _as_date(value)


def _direction(value: str) -> str:
    normalized = str(value).strip().lower()
    if normalized not in _DIRECTIONS:
        raise ValueError("tax-context-direction-invalid")
    return normalized


def _currency(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("tax-context-currency-required")
    normalized = value.strip().upper()
    if _CURRENCY.fullmatch(normalized) is None:
        raise ValueError("tax-context-currency-invalid")
    return normalized


def _summary_row(row: object) -> dict[str, Any]:
    return {
        "tax_type": row.tax_type,
        "tax": row.tax,
        "factor_type": row.factor_type,
        "count": row.count,
        "base": _decimal_text(row.base),
        "amount": _decimal_text(row.amount),
        "rate_or_quota": _decimal_text(row.rate_or_quota),
        "incomplete_count": row.incomplete_count,
    }


def _decimal_text(value: Decimal | None) -> str | None:
    return None if value is None else format(value, "f")
