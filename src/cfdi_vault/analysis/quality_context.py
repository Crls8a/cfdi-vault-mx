"""Pure quality aggregates by UTC month and explicitly supplied context.

No database, artifact, SAT, persistence, or dimension-inference side effects.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from cfdi_vault.analysis.quality import QUALITY_CATEGORIES, QualityObservation, QualitySnapshot, snapshot_quality

_DIRECTIONS = frozenset({"received", "issued", "unknown"})
_CURRENCY = re.compile(r"^(?:[A-Z]{3}|UNKNOWN)$")
_STATUSES = frozenset({"complete", "partial", "empty", "unsupported"})

__all__ = [
    "QualityAnalysisRecord",
    "QualityContextSummary",
    "QualityContextReport",
    "summarize_quality_by_context",
]


@dataclass(frozen=True, slots=True)
class QualityAnalysisRecord:
    """One dated quality observation with optional explicit context."""

    observed_at: date | datetime
    observation: QualityObservation
    direction: str | None = None
    currency: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_at", _as_date(self.observed_at))
        if not isinstance(self.observation, QualityObservation):
            raise TypeError("quality-context-observation-required")
        object.__setattr__(self, "direction", _optional_direction(self.direction))
        object.__setattr__(self, "currency", _optional_currency(self.currency))

    def __repr__(self) -> str:
        return "QualityAnalysisRecord(<redacted>)"


@dataclass(frozen=True, slots=True)
class QualityContextSummary:
    """One month/context snapshot with explicit source status."""

    month: str
    direction: str | None
    currency: str | None
    snapshot: QualitySnapshot
    source_status: str = "complete"

    def __post_init__(self) -> None:
        if re.fullmatch(r"\d{4}-(?:0[1-9]|1[0-2])", self.month) is None:
            raise ValueError("quality-context-month-invalid")
        object.__setattr__(self, "direction", _optional_direction(self.direction))
        object.__setattr__(self, "currency", _optional_currency(self.currency))
        if not isinstance(self.snapshot, QualitySnapshot):
            raise TypeError("quality-context-snapshot-required")
        object.__setattr__(self, "source_status", _status(self.source_status))

    @property
    def completeness(self) -> str:
        """Return source completeness for this context."""

        return self.source_status

    def as_dict(self) -> dict[str, Any]:
        """Return fixed categories and counts only."""

        result: dict[str, Any] = {
            "month": self.month,
            "source_status": self.source_status,
            "completeness": self.completeness,
            "total_observations": self.snapshot.total_observations,
            "counts": {category: self.snapshot.counts[category] for category in QUALITY_CATEGORIES},
        }
        if self.direction is not None:
            result["direction"] = self.direction
        if self.currency is not None:
            result["currency"] = self.currency
        return result

    def __repr__(self) -> str:
        return "QualityContextSummary(<redacted>)"


@dataclass(frozen=True, slots=True)
class QualityContextReport:
    """Deterministic quality contexts and aggregate source status."""

    contexts: tuple[QualityContextSummary, ...]
    source_status: str

    def __post_init__(self) -> None:
        if type(self.contexts) is not tuple or any(
            not isinstance(item, QualityContextSummary) for item in self.contexts
        ):
            raise TypeError("quality-context-summaries-required")
        object.__setattr__(self, "source_status", _status(self.source_status))
        keys = tuple(_context_key(item) for item in self.contexts)
        if keys != tuple(sorted(keys, key=_context_sort_key)):
            raise ValueError("quality-context-order-invalid")

    @property
    def rows(self) -> tuple[QualityContextSummary, ...]:
        """Return contexts under report terminology."""

        return self.contexts

    @property
    def completeness(self) -> str:
        """Return aggregate source completeness."""

        return self.source_status

    def as_dict(self) -> dict[str, Any]:
        """Return aggregate status and context counts only."""

        return {
            "source_status": self.source_status,
            "completeness": self.completeness,
            "contexts": [item.as_dict() for item in self.contexts],
        }

    def __repr__(self) -> str:
        return "QualityContextReport(<redacted>)"


def summarize_quality_by_context(
    records: Iterable[QualityAnalysisRecord],
    *,
    start: date | datetime | None = None,
    end: date | datetime | None = None,
    source_status: str | None = None,
) -> QualityContextReport:
    """Group fixed quality categories by UTC month and explicit dimensions."""

    start_date = _optional_date(start)
    end_date = _optional_date(end)
    if start_date is not None and end_date is not None and start_date > end_date:
        raise ValueError("analysis-period-invalid")
    if isinstance(records, (str, bytes)):
        raise TypeError("quality-context-records-required")
    explicit_status = _status(source_status) if source_status is not None else None
    try:
        iterator = iter(records)
    except TypeError as exc:
        raise TypeError("quality-context-records-required") from exc

    groups: defaultdict[tuple[str, str | None, str | None], list[QualityObservation]] = defaultdict(list)
    for item in iterator:
        if not isinstance(item, QualityAnalysisRecord):
            raise TypeError("quality-context-record-required")
        if start_date is not None and item.observed_at < start_date:
            continue
        if end_date is not None and item.observed_at > end_date:
            continue
        key = (item.observed_at.strftime("%Y-%m"), item.direction, item.currency)
        groups[key].append(item.observation)

    contexts = tuple(
        QualityContextSummary(
            month, direction, currency, snapshot_quality(observations), _context_status(explicit_status)
        )
        for (month, direction, currency), observations in sorted(
            groups.items(), key=lambda item: _context_sort_key(item[0])
        )
    )
    return QualityContextReport(contexts, _report_status(contexts, explicit_status))


def _context_status(explicit: str | None) -> str:
    if explicit in {"partial", "unsupported"}:
        return explicit
    return "complete"


def _report_status(contexts: tuple[QualityContextSummary, ...], explicit: str | None) -> str:
    if explicit in {"partial", "unsupported"}:
        return explicit
    if not contexts:
        return "empty"
    statuses = {context.source_status for context in contexts}
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
    raise TypeError("quality-context-date-invalid")


def _optional_date(value: date | datetime | None) -> date | None:
    return None if value is None else _as_date(value)


def _optional_direction(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("quality-context-direction-required")
    normalized = value.strip().lower()
    if normalized not in _DIRECTIONS:
        raise ValueError("quality-context-direction-invalid")
    return normalized


def _optional_currency(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("quality-context-currency-required")
    normalized = value.strip().upper()
    if _CURRENCY.fullmatch(normalized) is None:
        raise ValueError("quality-context-currency-invalid")
    return normalized


def _context_key(item: QualityContextSummary) -> tuple[str, str | None, str | None]:
    return (item.month, item.direction, item.currency)


def _context_sort_key(key: tuple[str, str | None, str | None]) -> tuple[str, str, str]:
    return (key[0], key[1] or "", key[2] or "")
