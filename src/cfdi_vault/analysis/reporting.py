"""Compose deterministic, aggregate-only financial analysis reports.

This module owns report DTO composition and public serialization only.  It does
not read PostgreSQL, load artifacts, contact SAT, infer tax liability, or add
row-level provenance.  Inputs must already be sanitized reports from the
monthly, accounting, and quality analysis modules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Mapping

from cfdi_vault.analysis.accounting import PaymentSummaryReport, TaxSummaryReport
from cfdi_vault.analysis.monthly import MonthlyAnalysisReport, MonthlyTrend
from cfdi_vault.analysis.payroll_accounting import PayrollSummaryReport
from cfdi_vault.analysis.quality import QualitySnapshot

_SECTION_STATUSES = frozenset({"complete", "partial", "empty", "unsupported"})
_MONTH = re.compile(r"^\d{4}-(?:0[1-9]|1[0-2])$")
_CURRENCY = re.compile(r"^(?:[A-Z]{3}|UNKNOWN)$")
_PAYMENT_FORM = re.compile(r"^(?:\d{2}|UNKNOWN)$")
_DIRECTIONS = frozenset({"received", "issued", "unknown"})
_TAX_TYPES = frozenset({"transferred", "withheld", "UNKNOWN"})
_TAXES = frozenset({"001", "002", "003", "UNKNOWN"})
_FACTORS = frozenset({"Tasa", "Cuota", "Exento", "UNKNOWN"})
_PAYROLL_TYPES = frozenset({"O", "E", "UNKNOWN"})

__all__ = ["AnalysisPeriod", "FinancialAnalysisReport"]


@dataclass(frozen=True, slots=True)
class AnalysisPeriod:
    """Inclusive calendar period used by one report."""

    start: date
    end: date

    def __post_init__(self) -> None:
        if type(self.start) is not date or type(self.end) is not date:
            raise TypeError("analysis-period-date-required")
        if self.start > self.end:
            raise ValueError("analysis-period-invalid")

    def as_dict(self) -> dict[str, str]:
        """Return an ISO-8601 period without row-level data."""

        return {"start": self.start.isoformat(), "end": self.end.isoformat()}


@dataclass(frozen=True, slots=True)
class FinancialAnalysisReport:
    """Immutable composition of monthly, accounting, and quality aggregates.

    The monthly, tax, payment, and quality sections are mandatory.  The
    payroll section is optional so existing four-section callers retain their
    projection shape; when supplied it is validated and serialized as a fifth
    aggregate-only section.  ``period`` accepts an :class:`AnalysisPeriod`, a
    two-date tuple, or ``None``.  ``generated_at`` must be timezone-aware UTC
    when supplied and is normalized to UTC.
    """

    monthly: MonthlyAnalysisReport
    taxes: TaxSummaryReport
    payments: PaymentSummaryReport
    quality: QualitySnapshot
    period: AnalysisPeriod | tuple[date, date] | None = None
    generated_at: datetime | None = None
    payroll: PayrollSummaryReport | None = None

    def __post_init__(self) -> None:
        required = (
            ("monthly", self.monthly, MonthlyAnalysisReport),
            ("taxes", self.taxes, TaxSummaryReport),
            ("payments", self.payments, PaymentSummaryReport),
            ("quality", self.quality, QualitySnapshot),
        )
        for name, value, expected in required:
            if not isinstance(value, expected):
                raise TypeError(f"analysis-{name}-section-required")
        if self.payroll is not None and not isinstance(self.payroll, PayrollSummaryReport):
            raise TypeError("analysis-payroll-section-required")
        object.__setattr__(self, "period", _normalize_period(self.period))
        object.__setattr__(self, "generated_at", _normalize_generated_at(self.generated_at))
        _validate_reports(self)

    @property
    def section_statuses(self) -> Mapping[str, str]:
        """Return immutable aggregate status for each included section."""

        return MappingProxyType({name: state[0] for name, state in self._section_states().items()})

    @property
    def section_completeness(self) -> Mapping[str, str]:
        """Return immutable completeness for each included section."""

        return MappingProxyType({name: state[1] for name, state in self._section_states().items()})

    def as_dict(self) -> dict[str, Any]:
        """Return a deterministic JSON-serializable aggregate projection.

        Decimal amounts are strings in fixed-point notation.  The projection
        contains no identifiers, names, raw XML/ZIP, paths, hashes, tokens, or
        source objects.
        """

        states = self._section_states()
        statuses = {name: state[0] for name, state in states.items()}
        completeness = {name: state[1] for name, state in states.items()}
        sections: dict[str, dict[str, Any]] = {
            "monthly": {
                "status": statuses["monthly"],
                "completeness": completeness["monthly"],
                "rows": [
                    _monthly_row(row)
                    for row in sorted(self.monthly.rows, key=lambda item: (item.month, item.direction, item.currency))
                ],
                "trends": [
                    _monthly_trend(trend)
                    for trend in sorted(
                        self.monthly.trends,
                        key=lambda item: (item.month, item.direction, item.currency),
                    )
                ],
            },
            "taxes": {
                "status": statuses["taxes"],
                "completeness": completeness["taxes"],
                "incomplete_count": self.taxes.incomplete_count,
                "rows": [
                    _tax_row(row)
                    for row in sorted(self.taxes.rows, key=lambda item: (item.tax_type, item.tax, item.factor_type))
                ],
            },
            "payments": {
                "status": statuses["payments"],
                "completeness": completeness["payments"],
                "incomplete_count": self.payments.incomplete_count,
                "rows": [
                    _payment_row(row)
                    for row in sorted(
                        self.payments.rows, key=lambda item: (item.month, item.currency, item.payment_form)
                    )
                ],
            },
            **(
                {
                    "payroll": {
                        "status": statuses["payroll"],
                        "completeness": completeness["payroll"],
                        "record_count": self.payroll.record_count,
                        "incomplete_count": self.payroll.incomplete_count,
                        "rows": [
                            _payroll_row(row)
                            for row in sorted(
                                self.payroll.rows,
                                key=lambda item: (item.month, item.payroll_type),
                            )
                        ],
                    }
                }
                if self.payroll is not None
                else {}
            ),
            "quality": {
                "status": statuses["quality"],
                "completeness": completeness["quality"],
                "total_observations": self.quality.total_observations,
                "counts": dict(self.quality.counts),
            },
        }
        return {
            "period": self.period.as_dict() if self.period is not None else None,
            "generated_at": _generated_at_text(self.generated_at),
            "section_statuses": statuses,
            "section_completeness": completeness,
            "sections": sections,
        }

    def to_public_dict(self) -> dict[str, Any]:
        """Alias for :meth:`as_dict` used by status/reporting adapters."""

        return self.as_dict()

    def __repr__(self) -> str:
        """Return a representation that never includes section contents."""

        return "FinancialAnalysisReport(<redacted>)"

    def _section_states(self) -> dict[str, tuple[str, str]]:
        monthly_count = sum(row.count for row in self.monthly.rows)
        metadata_count = sum(row.metadata_count for row in self.monthly.rows)
        monthly_status = "empty" if monthly_count == 0 else "partial" if metadata_count else "complete"
        tax_status = _normalized_status(self.taxes.source_status)
        payment_status = _normalized_status(self.payments.source_status)
        quality_status = "empty" if self.quality.total_observations == 0 else "complete"
        states = {
            "monthly": (monthly_status, monthly_status),
            "taxes": (tax_status, tax_status),
            "payments": (payment_status, payment_status),
        }
        if self.payroll is not None:
            payroll_status = _normalized_status(self.payroll.source_status)
            states["payroll"] = (payroll_status, payroll_status)
        states["quality"] = (quality_status, quality_status)
        return states


def _normalize_period(value: AnalysisPeriod | tuple[date, date] | None) -> AnalysisPeriod | None:
    if value is None or isinstance(value, AnalysisPeriod):
        return value
    if isinstance(value, tuple) and len(value) == 2:
        return AnalysisPeriod(value[0], value[1])
    raise TypeError("analysis-period-required")


def _normalize_generated_at(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("analysis-generated-at-utc-required")
    if value.utcoffset() != timedelta(0):
        raise ValueError("analysis-generated-at-utc-required")
    return value.astimezone(UTC)


def _normalized_status(value: str) -> str:
    status = str(value).strip().lower()
    if status not in _SECTION_STATUSES:
        raise ValueError("analysis-section-status-invalid")
    return status


def _validate_reports(report: FinancialAnalysisReport) -> None:
    _normalized_status(report.taxes.source_status)
    _normalized_status(report.payments.source_status)
    _require_nonnegative_int(report.taxes.incomplete_count, "analysis-count-invalid")
    _require_nonnegative_int(report.payments.incomplete_count, "analysis-count-invalid")
    for row in report.monthly.rows:
        _require_dimension(row.month, _MONTH, "analysis-month-invalid")
        _require_choice(row.direction, _DIRECTIONS, "analysis-direction-invalid")
        _require_dimension(row.currency, _CURRENCY, "analysis-currency-invalid")
        _require_nonnegative_int(row.count, "analysis-count-invalid")
        _require_nonnegative_int(row.cancelled_count, "analysis-count-invalid")
        _require_nonnegative_int(row.metadata_count, "analysis-count-invalid")
        _require_nonnegative_int(row.xml_count, "analysis-count-invalid")
        _require_nonnegative_int(row.active_count, "analysis-count-invalid")
        _require_nonnegative_int(row.unknown_status_count, "analysis-count-invalid")
        _decimal_text(row.subtotal)
        _decimal_text(row.total)
    for trend in report.monthly.trends:
        _validate_monthly_trend(trend)
    for row in report.taxes.rows:
        _require_choice(row.tax_type, _TAX_TYPES, "analysis-tax-type-invalid")
        _require_choice(row.tax, _TAXES, "analysis-tax-invalid")
        _require_choice(row.factor_type, _FACTORS, "analysis-factor-invalid")
        _require_nonnegative_int(row.count, "analysis-count-invalid")
        _require_nonnegative_int(row.incomplete_count, "analysis-count-invalid")
        _decimal_optional_text(row.base)
        _decimal_optional_text(row.amount)
        _decimal_optional_text(row.rate_or_quota)
    for row in report.payments.rows:
        _require_dimension(row.month, _MONTH, "analysis-month-invalid")
        _require_dimension(row.currency, _CURRENCY, "analysis-currency-invalid")
        _require_dimension(row.payment_form, _PAYMENT_FORM, "analysis-payment-form-invalid")
        _require_nonnegative_int(row.count, "analysis-count-invalid")
        _require_nonnegative_int(row.related_document_count, "analysis-count-invalid")
        _require_nonnegative_int(row.incomplete_count, "analysis-count-invalid")
        _decimal_optional_text(row.amount)
    if report.payroll is not None:
        _normalized_status(report.payroll.source_status)
        _require_nonnegative_int(report.payroll.incomplete_count, "analysis-count-invalid")
        _require_nonnegative_int(report.payroll.record_count, "analysis-count-invalid")
        for row in report.payroll.rows:
            _require_dimension(row.month, _MONTH, "analysis-month-invalid")
            _require_choice(row.payroll_type, _PAYROLL_TYPES, "analysis-payroll-type-invalid")
            _require_nonnegative_int(row.count, "analysis-count-invalid")
            _require_nonnegative_int(row.incomplete_count, "analysis-count-invalid")
            _decimal_optional_text(row.paid_days)
            _decimal_optional_text(row.total_perceptions)
            _decimal_optional_text(row.total_deductions)
            _decimal_optional_text(row.total_other_payments)


def _require_nonnegative_int(value: object, error: str) -> None:
    if type(value) is not int or value < 0:
        raise TypeError(error)


def _require_optional_int(value: object, error: str) -> None:
    if value is not None and type(value) is not int:
        raise TypeError(error)


def _require_dimension(value: object, pattern: re.Pattern[str], error: str) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(error)


def _require_choice(value: object, choices: frozenset[str], error: str) -> None:
    if value not in choices:
        raise ValueError(error)


def _decimal_optional_text(value: Decimal | None) -> str | None:
    return None if value is None else _decimal_text(value)


def _decimal_text(value: Decimal) -> str:
    if not isinstance(value, Decimal):
        raise TypeError("analysis-decimal-required")
    if not value.is_finite():
        raise ValueError("analysis-decimal-non-finite")
    return format(value, "f")


def _generated_at_text(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat().replace("+00:00", "Z")


def _monthly_row(row: object) -> dict[str, Any]:
    return {
        "month": row.month,
        "direction": row.direction,
        "currency": row.currency,
        "count": row.count,
        "subtotal": _decimal_text(row.subtotal),
        "total": _decimal_text(row.total),
        "cancelled_count": row.cancelled_count,
        "metadata_count": row.metadata_count,
        "xml_count": row.xml_count,
        "active_count": row.active_count,
        "unknown_status_count": row.unknown_status_count,
    }


def _monthly_trend(trend: MonthlyTrend) -> dict[str, Any]:
    return {
        "month": trend.month,
        "direction": trend.direction,
        "currency": trend.currency,
        "prior_month": trend.prior_month,
        "prior_available": trend.prior_available,
        "count_delta": trend.count_delta,
        "subtotal_delta": _decimal_optional_text(trend.subtotal_delta),
        "total_delta": _decimal_optional_text(trend.total_delta),
        "cancelled_count_delta": trend.cancelled_count_delta,
        "active_count_delta": trend.active_count_delta,
        "unknown_status_count_delta": trend.unknown_status_count_delta,
        "metadata_count_delta": trend.metadata_count_delta,
        "xml_count_delta": trend.xml_count_delta,
    }


def _validate_monthly_trend(trend: MonthlyTrend) -> None:
    _require_dimension(trend.month, _MONTH, "analysis-month-invalid")
    _require_choice(trend.direction, _DIRECTIONS, "analysis-direction-invalid")
    _require_dimension(trend.currency, _CURRENCY, "analysis-currency-invalid")
    _require_dimension(trend.prior_month, _MONTH, "analysis-month-invalid")
    if type(trend.prior_available) is not bool:
        raise TypeError("analysis-trend-baseline-invalid")
    for value in (
        trend.count_delta,
        trend.cancelled_count_delta,
        trend.active_count_delta,
        trend.unknown_status_count_delta,
        trend.metadata_count_delta,
        trend.xml_count_delta,
    ):
        _require_optional_int(value, "analysis-trend-delta-invalid")
    _decimal_optional_text(trend.subtotal_delta)
    _decimal_optional_text(trend.total_delta)
    if not trend.prior_available and any(
        value is not None
        for value in (
            trend.count_delta,
            trend.subtotal_delta,
            trend.total_delta,
            trend.cancelled_count_delta,
            trend.active_count_delta,
            trend.unknown_status_count_delta,
            trend.metadata_count_delta,
            trend.xml_count_delta,
        )
    ):
        raise ValueError("analysis-trend-baseline-invalid")


def _tax_row(row: object) -> dict[str, Any]:
    return {
        "tax_type": row.tax_type,
        "tax": row.tax,
        "factor_type": row.factor_type,
        "count": row.count,
        "base": _decimal_optional_text(row.base),
        "amount": _decimal_optional_text(row.amount),
        "rate_or_quota": _decimal_optional_text(row.rate_or_quota),
        "incomplete_count": row.incomplete_count,
    }


def _payment_row(row: object) -> dict[str, Any]:
    return {
        "month": row.month,
        "currency": row.currency,
        "payment_form": row.payment_form,
        "count": row.count,
        "amount": _decimal_optional_text(row.amount),
        "related_document_count": row.related_document_count,
        "incomplete_count": row.incomplete_count,
    }


def _payroll_row(row: object) -> dict[str, Any]:
    return {
        "month": row.month,
        "payroll_type": row.payroll_type,
        "count": row.count,
        "incomplete_count": row.incomplete_count,
        "paid_days": _decimal_optional_text(row.paid_days),
        "total_perceptions": _decimal_optional_text(row.total_perceptions),
        "total_deductions": _decimal_optional_text(row.total_deductions),
        "total_other_payments": _decimal_optional_text(row.total_other_payments),
    }
