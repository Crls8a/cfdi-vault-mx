"""Read-only PostgreSQL inputs for private accounting analysis.

This adapter reads the normalized child tables without writing state, reading
artifact bytes, contacting SAT, or exposing source identifiers.  It is an
interim read model: the current schema does not retain every normalized field
(notably payment related-document identity and payroll amounts), so those
gaps are returned as explicit ``partial``/``money_available=False`` evidence.
The future V5 tenant-safe ledger migration remains a dependency for durable
worker ingestion and complete accounting dimensions.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any, Generic, NoReturn, TypeVar

from sqlalchemy.orm import Session

from cfdi_vault.analysis.payments import PaymentRecord
from cfdi_vault.analysis.postgres_payroll import PayrollReadRow
from cfdi_vault.analysis.postgres_quality import quality_observations_statement
from cfdi_vault.analysis.quality import QualityObservation
from cfdi_vault.analysis.taxes import TaxRecord

SessionFactory = Callable[[], Session]
_PROVENANCE = "postgres-row"
_T = TypeVar("_T")
_PARSER_STATUSES = frozenset({"complete", "partial", "empty", "unsupported"})
_V5_REQUIRED = ("tenant_safe_child_key", "v5_accounting_ledger")


@dataclass(frozen=True, slots=True)
class AccountingReadResult(Sequence[_T], Generic[_T]):
    """Aggregate-safe rows plus parser completeness evidence.

    The sequence contains only normalized DTOs, never identifiers or source
    payloads.  ``unavailable_fields`` documents columns missing from the
    current schema; ``money_available`` is false for the payroll read because
    ``CfdiPayroll`` has no amount fields.
    """

    rows: tuple[_T, ...]
    parser_status: str
    unavailable_fields: tuple[str, ...] = ()
    money_available: bool = True

    def __post_init__(self) -> None:
        if self.parser_status not in _PARSER_STATUSES:
            raise ValueError("analysis-source-status-invalid")
        if type(self.rows) is not tuple:
            raise TypeError("analysis-rows-required")
        if type(self.unavailable_fields) is not tuple or any(
            not isinstance(value, str) or not value for value in self.unavailable_fields
        ):
            raise TypeError("analysis-unavailable-fields-invalid")
        if type(self.money_available) is not bool:
            raise TypeError("analysis-money-availability-invalid")

    @property
    def source_status(self) -> str:
        """Return the parser status under the accounting-report name."""

        return self.parser_status

    def __iter__(self) -> Iterator[_T]:
        return iter(self.rows)

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int | slice) -> _T | tuple[_T, ...]:
        return self.rows[index]

    def __repr__(self) -> str:
        """Avoid exposing rows or schema field values in diagnostics."""

        return (
            "AccountingReadResult(<redacted>, "
            f"parser_status={self.parser_status!r}, money_available={self.money_available!r})"
        )


def tax_records_statement(
    tenant_id: str,
    *,
    start: date | None = None,
    end: date | None = None,
) -> NoReturn:
    """Reject legacy tax SQL until V5 provides tenant-safe child keys."""

    _guard_v5_statement(tenant_id, start, end)


def payment_records_statement(
    tenant_id: str,
    *,
    start: date | None = None,
    end: date | None = None,
) -> NoReturn:
    """Reject legacy payment SQL until V5 provides tenant-safe child keys."""

    _guard_v5_statement(tenant_id, start, end)


def payroll_records_statement(
    tenant_id: str,
    *,
    start: date | None = None,
    end: date | None = None,
) -> NoReturn:
    """Reject legacy payroll SQL until V5 provides tenant-safe child keys."""

    _guard_v5_statement(tenant_id, start, end)


class AccountingPostgresAdapter:
    """Read accounting normalizers' inputs through short DB transactions."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def tax_records(
        self, tenant_id: str, *, start: date | None = None, end: date | None = None
    ) -> AccountingReadResult[TaxRecord]:
        """Return no legacy child rows until V5 can prove tenant ownership."""

        _validate_period(tenant_id, start, end)
        return self._legacy_child_unavailable("tax_rows")

    def payment_records(
        self, tenant_id: str, *, start: date | None = None, end: date | None = None
    ) -> AccountingReadResult[PaymentRecord]:
        """Return no legacy child rows until V5 can prove tenant ownership."""

        _validate_period(tenant_id, start, end)
        return self._legacy_child_unavailable("payment_rows", "exchange_rate", "related_document_identity")

    def payroll_records(
        self, tenant_id: str, *, start: date | None = None, end: date | None = None
    ) -> AccountingReadResult[PayrollReadRow]:
        """Return no legacy child rows until V5 can prove tenant ownership."""

        _validate_period(tenant_id, start, end)
        return self._legacy_child_unavailable(
            "payroll_rows",
            "payment_date",
            "paid_days",
            "total_perceptions",
            "total_deductions",
            "total_other_payments",
        )

    def quality_observations(
        self, tenant_id: str, *, start: date | None = None, end: date | None = None
    ) -> tuple[QualityObservation, ...]:
        """Read redacted metadata/XML quality observations only."""

        rows = self._execute(quality_observations_statement(tenant_id, start=start, end=end))
        return tuple(
            QualityObservation(
                metadata_present=bool(_value(row, "metadata_present")),
                xml_present=bool(_value(row, "xml_present")),
                cancelled_metadata=bool(_value(row, "cancelled_metadata")),
                xml_conflict=bool(_value(row, "xml_conflict")),
                payment_expected=bool(_value(row, "payment_expected")),
                payment_present=bool(_value(row, "payment_present")),
                payment_evidence_available=False,
                parser_status=_optional_text(row, "parser_status") or "partial",
                reconciliation_state=_optional_text(row, "reconciliation_state") or "unknown",
            )
            for row in rows
        )

    def _execute(self, statement: Any) -> list[Any]:
        with self._session_factory() as session:
            return list(session.execute(statement).all())

    def _legacy_child_unavailable(self, *fields: str) -> AccountingReadResult[Any]:
        return AccountingReadResult(
            (),
            "partial",
            _V5_REQUIRED + fields,
            money_available=False,
        )


def _validate_period(tenant_id: str, start: date | None, end: date | None) -> None:
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("analysis-tenant-required")
    if start is not None and type(start) is not date:
        raise TypeError("analysis-date-invalid")
    if end is not None and type(end) is not date:
        raise TypeError("analysis-date-invalid")
    if start is not None and end is not None and start > end:
        raise ValueError("analysis-period-invalid")


def _value(row: object, name: str) -> Any:
    mapping = getattr(row, "_mapping", None)
    if mapping is not None:
        return mapping[name]
    return getattr(row, name)


def _optional_text(row: object, name: str) -> str | None:
    value = _value(row, name)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _guard_v5_statement(tenant_id: str, start: date | None, end: date | None) -> NoReturn:
    _validate_period(tenant_id, start, end)
    raise RuntimeError("analysis-v5-tenant-safe-ledger-required")
