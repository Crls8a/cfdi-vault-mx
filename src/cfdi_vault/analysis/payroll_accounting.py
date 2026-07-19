"""Pure, redacted aggregates for normalized payroll evidence.

This module consumes :class:`~cfdi_vault.analysis.payroll.PayrollRecord`
values only.  It does not read PostgreSQL, persist ledger rows, contact SAT,
calculate net pay, or infer payroll liabilities.  Missing numeric evidence is
kept as ``None`` and is reflected by an explicit completeness status.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from cfdi_vault.analysis.payroll import PayrollRecord

_ZERO = Decimal("0")
_PAYROLL_TYPES = frozenset({"O", "E"})
_STATUSES = frozenset({"complete", "partial", "empty", "unsupported"})


@dataclass(frozen=True, slots=True)
class PayrollSummaryRow:
    """One UTC month/payroll-type aggregate without source provenance."""

    month: str
    payroll_type: str
    count: int
    incomplete_count: int
    paid_days: Decimal | None
    total_perceptions: Decimal | None
    total_deductions: Decimal | None
    total_other_payments: Decimal | None

    @property
    def record_count(self) -> int:
        """Return the number of normalized payroll records in the bucket."""

        return self.count

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe aggregate projection without source details."""

        return {
            "month": self.month,
            "payroll_type": self.payroll_type,
            "record_count": self.count,
            "count": self.count,
            "incomplete_count": self.incomplete_count,
            "paid_days": _decimal_text(self.paid_days),
            "total_perceptions": _decimal_text(self.total_perceptions),
            "total_deductions": _decimal_text(self.total_deductions),
            "total_other_payments": _decimal_text(self.total_other_payments),
        }

    def __repr__(self) -> str:
        """Return a representation that contains no payroll amounts."""

        return "PayrollSummaryRow(<redacted>)"


@dataclass(frozen=True, slots=True)
class PayrollSummaryReport:
    """Deterministic payroll aggregates and explicit source completeness."""

    rows: tuple[PayrollSummaryRow, ...]
    source_status: str
    incomplete_count: int
    record_count: int

    @property
    def status(self) -> str:
        """Return the source status using the accounting-report convention."""

        return self.source_status

    def as_dict(self) -> dict[str, object]:
        """Return only aggregate values suitable for a public status view."""

        return {
            "source_status": self.source_status,
            "status": self.source_status,
            "record_count": self.record_count,
            "incomplete_count": self.incomplete_count,
            "rows": [row.as_dict() for row in self.rows],
        }

    def to_public_dict(self) -> dict[str, object]:
        """Alias for :meth:`as_dict` used by report adapters."""

        return self.as_dict()

    def __repr__(self) -> str:
        """Return a redacted representation with no row contents."""

        return f"PayrollSummaryReport(rows=<redacted>, source_status={self.source_status!r})"


def summarize_payroll(
    records: Iterable[PayrollRecord],
    *,
    source_status: str | None = None,
) -> PayrollSummaryReport:
    """Group payroll records by UTC payment month and payroll type.

    Numeric fields are summed only when they are finite :class:`Decimal`
    values.  A missing or non-finite field remains ``None`` in its bucket and
    makes the result ``partial``; it is never treated as zero.  Unsupported
    payroll types or an upstream unsupported parser status produce
    ``unsupported``.  The aggregate intentionally does not calculate net pay,
    payroll liability, withholding, or any legal/accounting classification.
    """

    upstream_status = _source_status(records, source_status)
    buckets: defaultdict[tuple[str, str], dict[str, object]] = defaultdict(_new_bucket)
    total_incomplete = 0
    record_count = 0
    seen = False
    unsupported = False

    for record in records:
        seen = True
        record_count += 1
        payment_date = _utc_date(getattr(record, "payment_date", None))
        payroll_type, type_incomplete = _payroll_type(getattr(record, "payroll_type", None))
        unsupported = unsupported or payroll_type == "UNKNOWN"
        field_incomplete = type_incomplete
        values: dict[str, Decimal | None] = {}
        for field_name in (
            "paid_days",
            "total_perceptions",
            "total_deductions",
            "total_other_payments",
        ):
            value = getattr(record, field_name, None)
            if isinstance(value, Decimal) and value.is_finite():
                values[field_name] = value
            else:
                values[field_name] = None
                field_incomplete += 1
        source_incomplete = getattr(record, "incomplete_count", 0)
        if type(source_incomplete) is not int or source_incomplete < 0:
            raise TypeError("payroll-summary-count-invalid")
        field_incomplete += 0 if payment_date is not None else 1
        incomplete = max(source_incomplete, field_incomplete)
        total_incomplete += incomplete
        if payment_date is None:
            continue

        key = (payment_date.strftime("%Y-%m"), payroll_type)
        bucket = buckets[key]
        bucket["count"] = int(bucket["count"]) + 1
        bucket["incomplete_count"] = int(bucket["incomplete_count"]) + incomplete
        for field_name, value in values.items():
            if value is not None:
                bucket[field_name] = bucket[field_name] + value
                bucket[f"{field_name}_count"] = int(bucket[f"{field_name}_count"]) + 1

    status = _result_status(
        upstream_status,
        seen=seen,
        unsupported=unsupported,
        incomplete_count=total_incomplete,
    )
    rows = tuple(
        PayrollSummaryRow(
            month=month,
            payroll_type=payroll_type,
            count=int(values["count"]),
            incomplete_count=int(values["incomplete_count"]),
            paid_days=_sum_or_none(values["paid_days"], values["paid_days_count"]),
            total_perceptions=_sum_or_none(values["total_perceptions"], values["total_perceptions_count"]),
            total_deductions=_sum_or_none(values["total_deductions"], values["total_deductions_count"]),
            total_other_payments=_sum_or_none(values["total_other_payments"], values["total_other_payments_count"]),
        )
        for (month, payroll_type), values in sorted(buckets.items())
    )
    return PayrollSummaryReport(
        rows=rows,
        source_status=status,
        incomplete_count=total_incomplete,
        record_count=record_count,
    )


def _new_bucket() -> dict[str, object]:
    return {
        "count": 0,
        "incomplete_count": 0,
        "paid_days": _ZERO,
        "paid_days_count": 0,
        "total_perceptions": _ZERO,
        "total_perceptions_count": 0,
        "total_deductions": _ZERO,
        "total_deductions_count": 0,
        "total_other_payments": _ZERO,
        "total_other_payments_count": 0,
    }


def _sum_or_none(value: object, count: object) -> Decimal | None:
    return value if int(count) else None


def _utc_date(value: object) -> object:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).date()


def _payroll_type(value: object) -> tuple[str, int]:
    if not isinstance(value, str) or not value.strip():
        return "UNKNOWN", 1
    normalized = value.strip().upper()
    if normalized in _PAYROLL_TYPES:
        return normalized, 0
    return "UNKNOWN", 0


def _source_status(records: Iterable[object], explicit: str | None) -> str | None:
    value = explicit if explicit is not None else getattr(records, "parser_status", None)
    if value is None:
        return None
    normalized = str(value).strip().lower().replace("_", "-")
    if normalized in {"unsupported", "unsupported-error"}:
        return "unsupported"
    if normalized in _STATUSES:
        return normalized
    raise ValueError("analysis-source-status-invalid")


def _result_status(
    upstream_status: str | None,
    *,
    seen: bool,
    unsupported: bool,
    incomplete_count: int,
) -> str:
    if upstream_status == "unsupported":
        return "unsupported"
    if upstream_status == "partial":
        return "partial"
    if upstream_status == "empty":
        return "empty"
    if not seen:
        return "empty"
    if unsupported:
        return "unsupported"
    if incomplete_count:
        return "partial"
    return "complete"


def _decimal_text(value: Decimal | None) -> str | None:
    return None if value is None else format(value, "f")
