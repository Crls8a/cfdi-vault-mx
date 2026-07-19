"""Deterministic monthly aggregates over normalized CFDI evidence.

This module is intentionally pure.  It does not open PostgreSQL, read files,
contact SAT, or decide tax liability.  A repository adapter can convert
normalized database rows into ``MonthlyAnalysisRecord`` values later.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Iterable

_ZERO = Decimal("0")
_CANCELLED = frozenset({"cancelado", "cancelled", "canceled"})


@dataclass(frozen=True)
class MonthlyAnalysisRecord:
    """Aggregate input copied from one normalized CFDI or metadata row."""

    issue_date: date | datetime
    direction: str
    currency: str | None
    subtotal: Decimal | None
    total: Decimal | None
    status: str | None = None
    source_kind: str = "metadata"


@dataclass(frozen=True)
class MonthlyAggregate:
    """One private aggregate bucket, separated by month/direction/currency."""

    month: str
    direction: str
    currency: str
    count: int
    subtotal: Decimal
    total: Decimal
    cancelled_count: int
    metadata_count: int
    xml_count: int


@dataclass(frozen=True)
class MonthlyAnalysisReport:
    """Sanitized monthly report with no row-level identifiers."""

    rows: tuple[MonthlyAggregate, ...]


def analyze_monthly(
    records: Iterable[MonthlyAnalysisRecord],
    *,
    start: date | None = None,
    end: date | None = None,
) -> MonthlyAnalysisReport:
    """Return deterministic month/direction/currency aggregates.

    Bounds are inclusive and use the CFDI issue date.  Currency buckets never
    mix, and missing amounts are treated as zero only for aggregation; source
    completeness must be reported separately by the caller.
    """

    if start is not None and end is not None and start > end:
        raise ValueError("analysis-period-invalid")

    buckets: defaultdict[tuple[str, str, str], dict[str, object]] = defaultdict(
        lambda: {
            "count": 0,
            "subtotal": _ZERO,
            "total": _ZERO,
            "cancelled_count": 0,
            "metadata_count": 0,
            "xml_count": 0,
        }
    )
    for record in records:
        issue_date = _as_date(record.issue_date)
        if start is not None and issue_date < start:
            continue
        if end is not None and issue_date > end:
            continue
        direction = str(record.direction).strip().lower() or "unknown"
        currency = str(record.currency or "unknown").strip().upper() or "UNKNOWN"
        source_kind = str(record.source_kind).strip().lower()
        if source_kind not in {"metadata", "xml"}:
            raise ValueError("analysis-source-invalid")
        key = (issue_date.strftime("%Y-%m"), direction, currency)
        bucket = buckets[key]
        bucket["count"] = int(bucket["count"]) + 1
        bucket["subtotal"] = bucket["subtotal"] + _decimal(record.subtotal)
        bucket["total"] = bucket["total"] + _decimal(record.total)
        if str(record.status or "").strip().lower() in _CANCELLED:
            bucket["cancelled_count"] = int(bucket["cancelled_count"]) + 1
        if source_kind == "xml":
            bucket["xml_count"] = int(bucket["xml_count"]) + 1
        else:
            bucket["metadata_count"] = int(bucket["metadata_count"]) + 1

    rows = tuple(
        MonthlyAggregate(
            month=month,
            direction=direction,
            currency=currency,
            count=int(values["count"]),
            subtotal=values["subtotal"],
            total=values["total"],
            cancelled_count=int(values["cancelled_count"]),
            metadata_count=int(values["metadata_count"]),
            xml_count=int(values["xml_count"]),
        )
        for (month, direction, currency), values in sorted(buckets.items())
    )
    return MonthlyAnalysisReport(rows=rows)


def _as_date(value: date | datetime) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    raise TypeError("analysis-date-invalid")


def _decimal(value: Decimal | None) -> Decimal:
    if value is None:
        return _ZERO
    if not isinstance(value, Decimal):
        raise TypeError("analysis-amount-invalid")
    return value
