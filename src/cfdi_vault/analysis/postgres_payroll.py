"""Safe DTO for incomplete payroll rows read from the legacy schema."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal


@dataclass(frozen=True, slots=True)
class PayrollReadRow:
    """Payroll period shape with unavailable payment and money fields.

    This deliberately is not :class:`PayrollRecord`: the legacy table has no
    payment date or amount columns, so constructing a supposedly complete
    normalized record would invent evidence.
    """

    payroll_type: str
    payment_date: datetime | None = field(repr=False)
    period_start: datetime | None = field(repr=False)
    period_end: datetime | None = field(repr=False)
    paid_days: Decimal | None = field(repr=False)
    total_perceptions: Decimal | None = field(repr=False)
    total_deductions: Decimal | None = field(repr=False)
    total_other_payments: Decimal | None = field(repr=False)
    perception_count: int | None
    deduction_count: int | None
    other_payment_count: int | None
    incomplete_count: int

    def __post_init__(self) -> None:
        if self.payroll_type not in {"O", "E", "UNKNOWN"}:
            raise ValueError("payroll-read-type-invalid")
        for name in ("payment_date", "period_start", "period_end"):
            _validate_utc(getattr(self, name), name)
        if self.period_start is not None and self.period_end is not None and self.period_start > self.period_end:
            raise ValueError("payroll-read-period-invalid")
        for name in (
            "paid_days",
            "total_perceptions",
            "total_deductions",
            "total_other_payments",
        ):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, Decimal) or not value.is_finite() or value < 0):
                raise TypeError("payroll-read-decimal-invalid")
        for name in ("perception_count", "deduction_count", "other_payment_count"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise TypeError("payroll-read-count-invalid")
        if type(self.incomplete_count) is not int or self.incomplete_count < 0:
            raise TypeError("payroll-read-count-invalid")

    def __repr__(self) -> str:
        """Avoid exposing payroll values in diagnostics."""

        return "PayrollReadRow(<redacted>)"


def _validate_utc(value: datetime | None, name: str) -> None:
    if value is not None and (value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value)):
        raise ValueError(f"payroll-read-{name}-utc-required")
