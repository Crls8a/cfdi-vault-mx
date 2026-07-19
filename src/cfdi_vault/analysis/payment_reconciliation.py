"""Pure aggregate reconciliation of normalized payment applications.

No database, artifact, SAT, or legal-payment decision is performed.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType

RECONCILIATION_CATEGORIES: tuple[str, ...] = (
    "applied",
    "unapplied",
    "missing_identity",
    "duplicate_conflict",
    "invalid_partial",
)

_CATEGORY_SET = frozenset(RECONCILIATION_CATEGORIES)
_STATUS_SET = frozenset({"complete", "partial", "unsupported", "empty"})
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_OPAQUE_REF = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
_UUID_REF = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
_RFC_REF = re.compile(r"^[A-Z&Ñ]{3,4}[0-9]{6}[A-Z0-9]{3}$", re.IGNORECASE)
_SAT_REF = re.compile(r"^(?:SAT|UUID|RFC|IDSOLICITUD|IDPAQUETE)[-_.:]?[A-Z0-9]+$", re.IGNORECASE)
_ZERO = Decimal("0")


@dataclass(frozen=True, slots=True)
class InvoiceApplicationCandidate:
    """Invoice balance candidate; missing values remain reportable evidence gaps."""

    invoice_ref: str | None
    currency: str | None
    amount_due: Decimal | None
    evidence_status: str = "complete"

    def __post_init__(self) -> None:
        object.__setattr__(self, "invoice_ref", _optional_ref(self.invoice_ref, "invoice-ref"))
        object.__setattr__(self, "currency", _optional_currency(self.currency))
        object.__setattr__(self, "amount_due", _optional_amount(self.amount_due, "invoice-amount"))
        object.__setattr__(self, "evidence_status", _status(self.evidence_status))

    def __repr__(self) -> str:
        return "InvoiceApplicationCandidate(<redacted>)"


@dataclass(frozen=True, slots=True)
class PaymentApplicationCandidate:
    """Normalized payment-to-invoice link; repeated pairs are duplicate links."""

    payment_ref: str | None
    invoice_ref: str | None
    currency: str | None
    amount: Decimal | None
    evidence_status: str = "complete"

    def __post_init__(self) -> None:
        object.__setattr__(self, "payment_ref", _optional_ref(self.payment_ref, "payment-ref"))
        object.__setattr__(self, "invoice_ref", _optional_ref(self.invoice_ref, "invoice-ref"))
        object.__setattr__(self, "currency", _optional_currency(self.currency))
        object.__setattr__(self, "amount", _optional_amount(self.amount, "payment-amount"))
        object.__setattr__(self, "evidence_status", _status(self.evidence_status))

    def __repr__(self) -> str:
        return "PaymentApplicationCandidate(<redacted>)"


@dataclass(frozen=True, slots=True)
class PaymentReconciliationRow:
    """Aggregate count and amount for one category/currency bucket."""

    category: str
    currency: str
    count: int
    amount: Decimal | None
    incomplete_count: int = 0

    def __post_init__(self) -> None:
        if self.category not in _CATEGORY_SET:
            raise ValueError("payment-reconciliation-category-invalid")
        if not isinstance(self.currency, str) or not _CURRENCY.fullmatch(self.currency) and self.currency != "UNKNOWN":
            raise ValueError("payment-reconciliation-currency-invalid")
        if type(self.count) is not int or self.count < 0:
            raise TypeError("payment-reconciliation-count-invalid")
        if self.amount is not None and (not isinstance(self.amount, Decimal) or not self.amount.is_finite()):
            raise TypeError("payment-reconciliation-amount-invalid")
        if type(self.incomplete_count) is not int or self.incomplete_count < 0:
            raise TypeError("payment-reconciliation-incomplete-invalid")

    def as_dict(self) -> dict[str, object]:
        """Return an aggregate-only JSON-safe row."""

        return {
            "category": self.category,
            "currency": self.currency,
            "count": self.count,
            "amount": None if self.amount is None else format(self.amount, "f"),
            "incomplete_count": self.incomplete_count,
        }


@dataclass(frozen=True, slots=True)
class PaymentReconciliationReport:
    """Aggregate result; complete source evidence does not mean every payment was applied."""

    rows: tuple[PaymentReconciliationRow, ...]
    source_status: str
    invoice_count: int
    application_count: int
    incomplete_count: int

    def __post_init__(self) -> None:
        if self.source_status not in _STATUS_SET:
            raise ValueError("payment-reconciliation-status-invalid")
        if type(self.invoice_count) is not int or self.invoice_count < 0:
            raise TypeError("payment-reconciliation-invoice-count-invalid")
        if type(self.application_count) is not int or self.application_count < 0:
            raise TypeError("payment-reconciliation-application-count-invalid")
        if type(self.incomplete_count) is not int or self.incomplete_count < 0:
            raise TypeError("payment-reconciliation-incomplete-count-invalid")
        if type(self.rows) is not tuple or any(not isinstance(row, PaymentReconciliationRow) for row in self.rows):
            raise TypeError("payment-reconciliation-rows-required")

    @property
    def status(self) -> str:
        """Return source completeness under the common analysis name."""

        return self.source_status

    @property
    def complete(self) -> bool:
        """Return whether source evidence was complete and structurally valid."""

        return self.source_status == "complete"

    @property
    def allocation_complete(self) -> bool:
        """Return whether every supplied application was applied exactly."""

        return self.application_count > 0 and self.counts["applied"] == self.application_count

    @property
    def counts(self) -> Mapping[str, int]:
        """Return immutable counts for every fixed category."""

        values = {category: 0 for category in RECONCILIATION_CATEGORIES}
        for row in self.rows:
            values[row.category] += row.count
        return MappingProxyType(values)

    def as_dict(self) -> dict[str, object]:
        """Return only deterministic aggregate values; references are omitted."""

        return {
            "source_status": self.source_status,
            "status": self.source_status,
            "complete": self.complete,
            "allocation_complete": self.allocation_complete,
            "invoice_count": self.invoice_count,
            "application_count": self.application_count,
            "incomplete_count": self.incomplete_count,
            "counts": dict(self.counts),
            "rows": [row.as_dict() for row in self.rows],
        }

    def __repr__(self) -> str:
        return "PaymentReconciliationReport(<redacted>)"


def reconcile_payment_applications(
    invoices: Iterable[InvoiceApplicationCandidate],
    applications: Iterable[PaymentApplicationCandidate],
    *,
    source_status: str | None = None,
) -> PaymentReconciliationReport:
    """Classify application candidates without inferring payment or tax status.

    Valid links allocate only within the matching invoice/currency bucket.
    Amounts beyond the candidate balance are ``duplicate_conflict`` and are
    not silently clipped.  A payment with no invoice identity is
    ``unapplied``; an unknown or absent identity is ``missing_identity``.
    Mixed currencies and incomplete/unsupported evidence are
    ``invalid_partial`` and never net against another currency.

    Raises:
        TypeError: if inputs are not iterables of the candidate types.
        ValueError: if ``source_status`` is not a recognized status.
    """

    invoice_items = sorted(
        _materialize(invoices, InvoiceApplicationCandidate, "invoice-candidates-required"),
        key=lambda x: x.invoice_ref or "",
    )
    application_items = sorted(
        _materialize(applications, PaymentApplicationCandidate, "payment-applications-required"),
        key=_application_sort_key,
    )
    invoice_map: dict[str, InvoiceApplicationCandidate] = {}
    duplicate_invoice_refs: set[str] = set()
    for invoice in invoice_items:
        if invoice.invoice_ref is not None:
            if invoice.invoice_ref in invoice_map:
                duplicate_invoice_refs.add(invoice.invoice_ref)
            invoice_map.setdefault(invoice.invoice_ref, invoice)

    allocated: defaultdict[str, Decimal] = defaultdict(lambda: _ZERO)
    buckets: defaultdict[tuple[str, str], dict[str, object]] = defaultdict(_new_bucket)
    seen_links: set[tuple[str, str]] = set()
    evidence_statuses = [invoice.evidence_status for invoice in invoice_items]
    evidence_statuses.extend(application.evidence_status for application in application_items)
    for application in application_items:
        category, amount_currency, amount, incomplete = _classify(
            application, invoice_map, duplicate_invoice_refs, allocated, seen_links
        )
        bucket = buckets[(category, amount_currency)]
        bucket["count"] = int(bucket["count"]) + 1
        bucket["incomplete_count"] = int(bucket["incomplete_count"]) + incomplete
        if amount is not None:
            bucket["amount"] = bucket["amount"] + amount
            bucket["amount_count"] = int(bucket["amount_count"]) + 1

    rows = tuple(
        PaymentReconciliationRow(
            category=category,
            currency=currency,
            count=int(values["count"]),
            amount=values["amount"] if int(values["amount_count"]) else None,
            incomplete_count=int(values["incomplete_count"]),
        )
        for (category, currency), values in sorted(
            buckets.items(), key=lambda item: (RECONCILIATION_CATEGORIES.index(item[0][0]), item[0][1])
        )
    )
    incomplete_count = sum(row.incomplete_count for row in rows)
    status = _report_status(source_status, evidence_statuses, rows, bool(invoice_items or application_items))
    return PaymentReconciliationReport(
        rows=rows,
        source_status=status,
        invoice_count=len(invoice_items),
        application_count=len(application_items),
        incomplete_count=incomplete_count,
    )


def _classify(
    application: PaymentApplicationCandidate,
    invoice_map: dict[str, InvoiceApplicationCandidate],
    duplicate_invoice_refs: set[str],
    allocated: defaultdict[str, Decimal],
    seen_links: set[tuple[str, str]],
) -> tuple[str, str, Decimal | None, int]:
    currency = application.currency or "UNKNOWN"
    amount = application.amount
    if application.evidence_status != "complete" or amount is None or amount <= _ZERO:
        return "invalid_partial", currency, amount, 1
    if application.payment_ref is None:
        return "missing_identity", currency, amount, 1
    if application.invoice_ref is None:
        return "unapplied", currency, amount, 0
    invoice = invoice_map.get(application.invoice_ref)
    if invoice is None or application.invoice_ref in duplicate_invoice_refs:
        return "missing_identity", currency, amount, 1
    if invoice.evidence_status != "complete" or invoice.currency is None or invoice.amount_due is None:
        return "invalid_partial", currency, amount, 1
    if application.currency != invoice.currency:
        return "invalid_partial", currency, amount, 1
    link_key = (application.payment_ref, application.invoice_ref)
    if link_key in seen_links:
        return "duplicate_conflict", currency, amount, 1
    seen_links.add(link_key)
    remaining = invoice.amount_due - allocated[application.invoice_ref]
    if amount > remaining:
        return "duplicate_conflict", currency, amount, 1
    allocated[application.invoice_ref] += amount
    return "applied", currency, amount, 0


def _report_status(
    explicit: str | None,
    evidence_statuses: list[str],
    rows: tuple[PaymentReconciliationRow, ...],
    has_input: bool,
) -> str:
    if explicit is not None:
        normalized = _status(explicit)
        if normalized == "unsupported":
            return normalized
        if normalized == "partial":
            return normalized
        if normalized == "empty" and not has_input:
            return normalized
    if any(status == "unsupported" for status in evidence_statuses):
        return "unsupported"
    if not has_input:
        return "empty"
    if any(status == "partial" for status in evidence_statuses):
        return "partial"
    if any(row.category in {"missing_identity", "duplicate_conflict", "invalid_partial"} for row in rows):
        return "partial"
    return "complete"


def _new_bucket() -> dict[str, object]:
    return {"count": 0, "amount": _ZERO, "amount_count": 0, "incomplete_count": 0}


def _application_sort_key(application: PaymentApplicationCandidate) -> tuple[str, str, str, tuple[bool, Decimal], str]:
    """Canonicalize allocation order so replay/reversal cannot change results."""

    return (
        application.payment_ref or "",
        application.invoice_ref or "",
        application.currency or "UNKNOWN",
        (application.amount is None, application.amount or _ZERO),
        application.evidence_status,
    )


def _materialize(values: Iterable[object], expected: type, error: str) -> tuple[object, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(error)
    try:
        items = tuple(values)
    except TypeError as exc:
        raise TypeError(error) from exc
    if any(not isinstance(item, expected) for item in items):
        raise TypeError(error)
    return items


def _status(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("payment-reconciliation-status-required")
    normalized = value.strip().lower().replace("_", "-")
    if normalized == "unsupported-error":
        normalized = "unsupported"
    if normalized not in _STATUS_SET:
        raise ValueError("payment-reconciliation-status-invalid")
    return normalized


def _optional_ref(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{field_name}-required")
    if (
        not _OPAQUE_REF.fullmatch(value)
        or "/" in value
        or "\\" in value
        or re.match(r"^[A-Za-z]:", value)
        or _UUID_REF.fullmatch(value)
        or _RFC_REF.fullmatch(value)
        or _SAT_REF.fullmatch(value)
        or value.isdecimal()
    ):
        raise ValueError(f"{field_name}-invalid")
    return value


def _optional_currency(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("payment-reconciliation-currency-required")
    normalized = value.strip().upper()
    if not _CURRENCY.fullmatch(normalized):
        raise ValueError("payment-reconciliation-currency-invalid")
    return normalized


def _optional_amount(value: Decimal | None, field_name: str) -> Decimal | None:
    if value is None:
        return None
    if not isinstance(value, Decimal) or not value.is_finite() or value < _ZERO:
        raise ValueError(f"{field_name}-invalid")
    return value


__all__ = [
    "RECONCILIATION_CATEGORIES",
    "InvoiceApplicationCandidate",
    "PaymentApplicationCandidate",
    "PaymentReconciliationRow",
    "PaymentReconciliationReport",
    "reconcile_payment_applications",
]
