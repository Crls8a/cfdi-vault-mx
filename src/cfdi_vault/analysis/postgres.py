"""Tenant-scoped PostgreSQL adapter for monthly analysis inputs.

The adapter reads only normalized accounting fields from the metadata ledger and
CFDI header. It never returns identifiers, parties, raw payloads, storage keys,
or hashes, and it does not contact SAT or read artifact bytes.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from sqlalchemy import Select, and_, exists, select
from sqlalchemy.orm import Session

from cfdi_vault.analysis.monthly import MonthlyAnalysisRecord
from cfdi_vault.recovery_db import CfdiDocument, CfdiMetadataLedger, XmlEvidence

SessionFactory = Callable[[], Session]
_UTC = timezone.utc


def monthly_records_statement(
    tenant_id: str,
    *,
    start: date | None = None,
    end: date | None = None,
) -> Select[tuple[Any, ...]]:
    """Build a tenant-scoped, inclusive monthly-analysis source query.

    ``start`` and ``end`` are inclusive calendar dates. Datetime values in the
    database are filtered using UTC boundaries: a naive value is interpreted
    as UTC, while an aware value is converted to UTC before its calendar date
    is used by the adapter. Only aggregate inputs are selected; UUIDs and
    sensitive evidence columns are used neither in the result nor the DTO.

    Raises:
        ValueError: if ``tenant_id`` is blank or the date range is inverted.
    """

    _validate_period(tenant_id, start, end)
    conditions = [
        CfdiMetadataLedger.tenant_id == tenant_id,
        CfdiMetadataLedger.issue_date.is_not(None),
    ]
    if start is not None:
        conditions.append(CfdiMetadataLedger.issue_date >= _utc_start(start))
    if end is not None:
        conditions.append(CfdiMetadataLedger.issue_date < _utc_start(end + timedelta(days=1)))

    xml_backed = and_(
        CfdiDocument.id.is_not(None),
        exists(
            select(1).where(
                XmlEvidence.tenant_id == CfdiMetadataLedger.tenant_id,
                XmlEvidence.uuid == CfdiMetadataLedger.uuid,
            )
        ),
    ).label("xml_backed")
    return (
        select(
            CfdiMetadataLedger.direction.label("direction"),
            CfdiMetadataLedger.issue_date.label("issue_date"),
            CfdiMetadataLedger.total.label("metadata_total"),
            CfdiMetadataLedger.status.label("metadata_status"),
            xml_backed,
            CfdiDocument.currency.label("document_currency"),
            CfdiDocument.subtotal.label("document_subtotal"),
            CfdiDocument.total.label("document_total"),
            CfdiDocument.status.label("document_status"),
        )
        .select_from(CfdiMetadataLedger)
        .outerjoin(
            CfdiDocument,
            and_(
                CfdiDocument.tenant_id == CfdiMetadataLedger.tenant_id,
                CfdiDocument.uuid == CfdiMetadataLedger.uuid,
            ),
        )
        .where(*conditions)
        .order_by(CfdiMetadataLedger.issue_date, CfdiMetadataLedger.direction, CfdiMetadataLedger.id)
    )


class MonthlyAnalysisPostgresAdapter:
    """Read monthly-analysis records through short PostgreSQL transactions."""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    def records_for_period(
        self,
        tenant_id: str,
        *,
        start: date | None = None,
        end: date | None = None,
    ) -> tuple[MonthlyAnalysisRecord, ...]:
        """Return sanitized ledger/document records for one tenant and period.

        Metadata rows without a matching document are included with
        ``source_kind='metadata'``, ``subtotal=None`` and ``currency='UNKNOWN'``.
        Matching XML evidence uses document fields, with each missing field
        falling back to its metadata value where one exists. Rows with no issue
        date are excluded by the SQL predicate and by a defensive post-query
        check.
        """

        statement = monthly_records_statement(tenant_id, start=start, end=end)
        with self._session_factory() as session:
            rows = session.execute(statement).all()
        return tuple(_record_from_row(row) for row in rows if _row_value(row, "issue_date") is not None)


def _record_from_row(row: object) -> MonthlyAnalysisRecord:
    issue_date = _utc_date(_row_value(row, "issue_date"))
    if not _row_value(row, "xml_backed"):
        return MonthlyAnalysisRecord(
            issue_date=issue_date,
            direction=_row_value(row, "direction") or "unknown",
            currency="UNKNOWN",
            subtotal=None,
            total=_row_value(row, "metadata_total"),
            status=_row_value(row, "metadata_status"),
            source_kind="metadata",
        )
    document_total = _row_value(row, "document_total")
    metadata_total = _row_value(row, "metadata_total")
    return MonthlyAnalysisRecord(
        issue_date=issue_date,
        direction=_row_value(row, "direction") or "unknown",
        currency=_row_value(row, "document_currency") or "UNKNOWN",
        subtotal=_row_value(row, "document_subtotal"),
        total=document_total if document_total is not None else metadata_total,
        status=_row_value(row, "document_status") or _row_value(row, "metadata_status"),
        source_kind="xml",
    )


def _row_value(row: object, name: str) -> Any:
    mapping = getattr(row, "_mapping", None)
    if mapping is not None:
        return mapping[name]
    return getattr(row, name)


def _utc_date(value: object) -> date:
    if isinstance(value, datetime):
        normalized = value.replace(tzinfo=_UTC) if value.tzinfo is None else value.astimezone(_UTC)
        return normalized.date()
    if isinstance(value, date):
        return value
    raise TypeError("analysis-date-invalid")


def _utc_start(value: date) -> datetime:
    return datetime.combine(value, time.min, tzinfo=_UTC)


def _validate_period(tenant_id: str, start: date | None, end: date | None) -> None:
    if not tenant_id.strip():
        raise ValueError("analysis-tenant-required")
    if start is not None and end is not None and start > end:
        raise ValueError("analysis-period-invalid")
