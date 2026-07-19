"""Deterministic monthly aggregates over normalized CFDI evidence.

This module is intentionally pure.  It does not open PostgreSQL, read files,
contact SAT, or decide tax liability.  A repository adapter can convert
normalized database rows into ``MonthlyAnalysisRecord`` values later. CFDI
effect and document type are accepted only as explicit bounded dimensions;
missing values remain missing.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import Iterable

_ZERO = Decimal("0")
_CANCELLED = frozenset({"cancelado", "cancelled", "canceled"})
_ACTIVE = frozenset({"vigente", "active", "activo", "valid"})
_DIRECTIONS = frozenset({"received", "issued", "unknown"})
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_CFDI_DIMENSIONS = frozenset({"I", "E", "T", "P", "N"})


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
    effect: str | None = None
    document_type: str | None = None


@dataclass(frozen=True)
class MonthlyAggregate:
    """One private aggregate bucket separated by explicit CFDI dimensions.

    ``effect`` and ``document_type`` remain ``None`` when the source did not
    provide those fields. They are never derived from direction, status, or
    another payload field.
    """

    month: str
    direction: str
    currency: str
    count: int
    subtotal: Decimal
    total: Decimal
    cancelled_count: int
    metadata_count: int
    xml_count: int
    active_count: int = 0
    unknown_status_count: int = 0
    effect: str | None = None
    document_type: str | None = None


@dataclass(frozen=True)
class MonthlyTrend:
    """Month-over-month deltas for one bounded month/direction/currency key.

    Deltas are ``None`` when the immediately preceding calendar month has no
    aggregate for the same key.  This distinguishes missing evidence from a
    measured zero and avoids inventing a baseline outside the requested data.
    """

    month: str
    direction: str
    currency: str
    prior_month: str
    prior_available: bool
    count_delta: int | None
    subtotal_delta: Decimal | None
    total_delta: Decimal | None
    cancelled_count_delta: int | None
    active_count_delta: int | None
    unknown_status_count_delta: int | None
    metadata_count_delta: int | None
    xml_count_delta: int | None
    effect: str | None = None
    document_type: str | None = None


@dataclass(frozen=True)
class MonthlyAnalysisReport:
    """Sanitized monthly report with no row-level identifiers."""

    rows: tuple[MonthlyAggregate, ...]
    trends: tuple[MonthlyTrend, ...] = ()


def analyze_monthly(
    records: Iterable[MonthlyAnalysisRecord],
    *,
    start: date | None = None,
    end: date | None = None,
) -> MonthlyAnalysisReport:
    """Return deterministic monthly aggregates with explicit CFDI dimensions.

    Bounds are inclusive and use the CFDI issue date.  Currency buckets never
    mix, and effect/type fields are used only when explicitly supplied by the
    source. Missing amounts are treated as zero only for aggregation; source
    completeness must be reported separately by the caller.
    """

    if start is not None and end is not None and start > end:
        raise ValueError("analysis-period-invalid")

    buckets: defaultdict[tuple[str, str, str, str | None, str | None], dict[str, object]] = defaultdict(
        lambda: {
            "count": 0,
            "subtotal": _ZERO,
            "total": _ZERO,
            "cancelled_count": 0,
            "metadata_count": 0,
            "xml_count": 0,
            "active_count": 0,
            "unknown_status_count": 0,
        }
    )
    for record in records:
        issue_date = _as_date(record.issue_date)
        if start is not None and issue_date < start:
            continue
        if end is not None and issue_date > end:
            continue
        direction = _normalize_direction(record.direction)
        currency = _normalize_currency(record.currency)
        effect = _normalize_cfdi_dimension(record.effect, "analysis-effect-invalid")
        document_type = _normalize_cfdi_dimension(record.document_type, "analysis-document-type-invalid")
        source_kind = str(record.source_kind).strip().lower()
        if source_kind not in {"metadata", "xml"}:
            raise ValueError("analysis-source-invalid")
        key = (issue_date.strftime("%Y-%m"), direction, currency, effect, document_type)
        bucket = buckets[key]
        bucket["count"] = int(bucket["count"]) + 1
        bucket["subtotal"] = bucket["subtotal"] + _decimal(record.subtotal)
        bucket["total"] = bucket["total"] + _decimal(record.total)
        status_bucket = _status_bucket(record.status)
        if status_bucket == "cancelled":
            bucket["cancelled_count"] = int(bucket["cancelled_count"]) + 1
        elif status_bucket == "active":
            bucket["active_count"] = int(bucket["active_count"]) + 1
        else:
            bucket["unknown_status_count"] = int(bucket["unknown_status_count"]) + 1
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
            active_count=int(values["active_count"]),
            unknown_status_count=int(values["unknown_status_count"]),
            effect=effect,
            document_type=document_type,
        )
        for (month, direction, currency, effect, document_type), values in sorted(
            buckets.items(), key=lambda item: tuple(value or "" for value in item[0])
        )
    )
    return MonthlyAnalysisReport(rows=rows, trends=_build_trends(rows))


def _build_trends(rows: tuple[MonthlyAggregate, ...]) -> tuple[MonthlyTrend, ...]:
    by_key = {(row.month, row.direction, row.currency, row.effect, row.document_type): row for row in rows}
    trends: list[MonthlyTrend] = []
    for row in rows:
        prior_month = _previous_month(row.month)
        prior = by_key.get((prior_month, row.direction, row.currency, row.effect, row.document_type))
        if prior is None:
            trends.append(
                MonthlyTrend(
                    month=row.month,
                    direction=row.direction,
                    currency=row.currency,
                    prior_month=prior_month,
                    prior_available=False,
                    count_delta=None,
                    subtotal_delta=None,
                    total_delta=None,
                    cancelled_count_delta=None,
                    active_count_delta=None,
                    unknown_status_count_delta=None,
                    metadata_count_delta=None,
                    xml_count_delta=None,
                    effect=row.effect,
                    document_type=row.document_type,
                )
            )
            continue
        trends.append(
            MonthlyTrend(
                month=row.month,
                direction=row.direction,
                currency=row.currency,
                prior_month=prior_month,
                prior_available=True,
                count_delta=row.count - prior.count,
                subtotal_delta=row.subtotal - prior.subtotal,
                total_delta=row.total - prior.total,
                cancelled_count_delta=row.cancelled_count - prior.cancelled_count,
                active_count_delta=row.active_count - prior.active_count,
                unknown_status_count_delta=row.unknown_status_count - prior.unknown_status_count,
                metadata_count_delta=row.metadata_count - prior.metadata_count,
                xml_count_delta=row.xml_count - prior.xml_count,
                effect=row.effect,
                document_type=row.document_type,
            )
        )
    return tuple(trends)


def _previous_month(month: str) -> str:
    year, month_number = (int(value) for value in month.split("-"))
    if month_number == 1:
        return f"{year - 1:04d}-12"
    return f"{year:04d}-{month_number - 1:02d}"


def _normalize_direction(value: object) -> str:
    normalized = str(value).strip().lower() or "unknown"
    if normalized not in _DIRECTIONS:
        raise ValueError("analysis-direction-invalid")
    return normalized


def _normalize_currency(value: object) -> str:
    normalized = str(value or "unknown").strip().upper() or "UNKNOWN"
    if normalized != "UNKNOWN" and not _CURRENCY.fullmatch(normalized):
        raise ValueError("analysis-currency-invalid")
    return normalized


def _normalize_cfdi_dimension(value: object, error: str) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().upper()
    if not normalized:
        return None
    if normalized not in _CFDI_DIMENSIONS:
        raise ValueError(error)
    return normalized


def _status_bucket(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in _CANCELLED:
        return "cancelled"
    if normalized in _ACTIVE:
        return "active"
    return "unknown"


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
