"""Identifier-free quality query builders for the accounting DB adapter."""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from sqlalchemy import Select, and_, exists, func, literal, select, union_all
from sqlalchemy.orm import aliased

from cfdi_vault.recovery_db import CfdiDocument, CfdiMetadataLedger, XmlEvidence

_UTC = timezone.utc


def quality_observations_statement(
    tenant_id: str,
    *,
    start: date | None = None,
    end: date | None = None,
) -> Select[tuple[Any, ...]]:
    """Build aggregate-safe quality observations for metadata and XML sides."""

    _validate_period(tenant_id, start, end)
    return union_all(
        _metadata_quality_statement(tenant_id, start, end),
        _document_quality_statement(tenant_id, start, end),
    )


def _metadata_quality_statement(tenant_id: str, start: date | None, end: date | None) -> Select[Any]:
    tenant_column, uuid_column = CfdiMetadataLedger.tenant_id, CfdiMetadataLedger.uuid
    conditions = [tenant_column == tenant_id, *_date_conditions(CfdiMetadataLedger.issue_date, start, end)]
    return (
        select(
            literal(True).label("metadata_present"),
            _xml_exists(tenant_column, uuid_column).label("xml_present"),
            func.lower(func.coalesce(CfdiMetadataLedger.status, ""))
            .in_(("cancelado", "cancelled", "canceled"))
            .label("cancelled_metadata"),
            _xml_conflict(tenant_column, uuid_column).label("xml_conflict"),
            (func.upper(func.coalesce(CfdiDocument.payment_method, "")) == "PPD").label("payment_expected"),
            literal(False).label("payment_present"),
            func.coalesce(CfdiDocument.parser_status, "partial").label("parser_status"),
            func.coalesce(CfdiMetadataLedger.reconciliation_state, "unknown").label("reconciliation_state"),
        )
        .select_from(CfdiMetadataLedger)
        .outerjoin(CfdiDocument, and_(CfdiDocument.tenant_id == tenant_column, CfdiDocument.uuid == uuid_column))
        .where(*conditions)
    )


def _document_quality_statement(tenant_id: str, start: date | None, end: date | None) -> Select[Any]:
    tenant_column, uuid_column = CfdiDocument.tenant_id, CfdiDocument.uuid
    metadata = aliased(CfdiMetadataLedger)
    metadata_exists = exists(
        select(1).select_from(metadata).where(metadata.tenant_id == tenant_column, metadata.uuid == uuid_column)
    )
    conditions = [tenant_column == tenant_id, ~metadata_exists, *_date_conditions(CfdiDocument.issue_date, start, end)]
    return (
        select(
            literal(False).label("metadata_present"),
            _xml_exists(tenant_column, uuid_column).label("xml_present"),
            literal(False).label("cancelled_metadata"),
            _xml_conflict(tenant_column, uuid_column).label("xml_conflict"),
            (func.upper(func.coalesce(CfdiDocument.payment_method, "")) == "PPD").label("payment_expected"),
            literal(False).label("payment_present"),
            func.coalesce(CfdiDocument.parser_status, "partial").label("parser_status"),
            literal("unknown").label("reconciliation_state"),
        )
        .select_from(CfdiDocument)
        .where(*conditions)
    )


def _xml_exists(tenant_column: Any, uuid_column: Any) -> Any:
    evidence = aliased(XmlEvidence)
    return exists(
        select(1).select_from(evidence).where(evidence.tenant_id == tenant_column, evidence.uuid == uuid_column)
    )


def _xml_conflict(tenant_column: Any, uuid_column: Any) -> Any:
    evidence = aliased(XmlEvidence)
    return exists(
        select(1)
        .select_from(evidence)
        .where(evidence.tenant_id == tenant_column, evidence.uuid == uuid_column)
        .group_by(evidence.tenant_id, evidence.uuid)
        .having(func.count(func.distinct(evidence.xml_sha256)) > 1)
    )


def _date_conditions(column: Any, start: date | None, end: date | None) -> list[Any]:
    conditions: list[Any] = []
    if start is not None:
        conditions.append(column >= _utc_start(start))
    if end is not None:
        conditions.append(column < _utc_start(end + timedelta(days=1)))
    return conditions


def _validate_period(tenant_id: str, start: date | None, end: date | None) -> None:
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("analysis-tenant-required")
    if start is not None and type(start) is not date:
        raise TypeError("analysis-date-invalid")
    if end is not None and type(end) is not date:
        raise TypeError("analysis-date-invalid")
    if start is not None and end is not None and start > end:
        raise ValueError("analysis-period-invalid")


def _utc_start(value: date) -> datetime:
    return datetime.combine(value, time.min, tzinfo=_UTC)
