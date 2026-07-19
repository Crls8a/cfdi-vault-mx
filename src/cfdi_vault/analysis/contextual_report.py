"""Compose contextual accounting views into one sanitized operator bundle.

This internal module owns only deterministic, aggregate composition.  It does
not read PostgreSQL, persist reports, contact SAT, infer missing months, or
make tax, cash, or legal conclusions.  The child reports remain the source of
truth for their own completeness fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cfdi_vault.analysis.payment_context import PaymentContextReport
from cfdi_vault.analysis.quality_context import QualityContextReport
from cfdi_vault.analysis.tax_context import TaxContextReport

__all__ = ["ContextualReportBundle", "compose_contextual_report_bundle"]


@dataclass(frozen=True, slots=True)
class ContextualReportBundle:
    """Aggregate-only composition of tax, payment, and quality contexts.

    The bundle accepts the month bounds explicitly represented by each child
    report's rows.  All non-empty child bounds must match; an empty child is
    retained as missing evidence rather than treated as a date.  The bundle
    never fills missing interior months or creates rows.  Child
    status/completeness values are preserved in :meth:`as_dict`.
    """

    taxes: TaxContextReport
    payments: PaymentContextReport
    quality: QualityContextReport
    source_status: str = field(init=False)
    month_bounds: tuple[str, str] | None = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.taxes, TaxContextReport):
            raise TypeError("tax-context-report-required")
        if not isinstance(self.payments, PaymentContextReport):
            raise TypeError("payment-context-report-required")
        if not isinstance(self.quality, QualityContextReport):
            raise TypeError("quality-context-report-required")

        bounds = tuple(_month_bounds(report) for report in (self.taxes, self.payments, self.quality))
        populated_bounds = tuple(bound for bound in bounds if bound is not None)
        if len(set(populated_bounds)) > 1:
            raise ValueError("contextual-report-period-mismatch")
        object.__setattr__(self, "month_bounds", populated_bounds[0] if populated_bounds else None)
        object.__setattr__(self, "source_status", _bundle_status(self._child_statuses()))

    def _child_statuses(self) -> tuple[str, str, str]:
        return (self.taxes.source_status, self.payments.source_status, self.quality.source_status)

    def as_dict(self) -> dict[str, Any]:
        """Return deterministic aggregate views without source identifiers."""

        start_month, end_month = self.month_bounds or (None, None)
        return {
            "status": self.source_status,
            "period": {"start_month": start_month, "end_month": end_month},
            "taxes": self.taxes.as_dict(),
            "payments": self.payments.as_dict(),
            "quality": self.quality.as_dict(),
        }

    def __repr__(self) -> str:
        return "ContextualReportBundle(<redacted>)"


def compose_contextual_report_bundle(
    taxes: TaxContextReport,
    payments: PaymentContextReport,
    quality: QualityContextReport,
) -> ContextualReportBundle:
    """Validate and compose the three required contextual reports.

    ``unsupported`` outranks ``partial``; a mixture of ``empty`` and a
    populated child is ``partial``; all-empty children remain ``empty``.
    These rules describe source completeness only and do not calculate tax
    liability, cash paid, or any accounting conclusion.
    """

    return ContextualReportBundle(taxes, payments, quality)


def _month_bounds(report: object) -> tuple[str, str] | None:
    rows = report.rows  # all accepted report types expose a validated tuple
    if not rows:
        return None
    return rows[0].month, rows[-1].month


def _bundle_status(statuses: tuple[str, str, str]) -> str:
    if "unsupported" in statuses:
        return "unsupported"
    if "partial" in statuses or "empty" in statuses:
        return "partial" if any(status != "empty" for status in statuses) else "empty"
    return "complete"
