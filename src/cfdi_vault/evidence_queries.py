"""PostgreSQL query shapes for durable evidence and processing state.

The builders return SQLAlchemy statements only. They never read evidence bytes,
resolve adapter paths, or depend on API, queue, cache, or object-storage clients.
Every builder rejects non-positive limits; key/hash lookups also validate input.
"""

from __future__ import annotations

import re

from sqlalchemy import Select, select

from cfdi_vault.recovery_db import (
    CfdiDocument,
    CfdiMetadataLedger,
    DownloadJob,
    QueueJobEvent,
    XmlEvidence,
)
from cfdi_vault.storage_contract import StorageKey


_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def xml_evidence_by_storage_key(
    tenant_id: str, storage_key: str | StorageKey, *, limit: int = 100
) -> Select[tuple[XmlEvidence]]:
    """Build a tenant-scoped lookup for a relative object key.

    ``StorageKey`` validation rejects absolute adapter paths before SQL is built.
    """

    key = str(StorageKey.parse(storage_key))
    return _limited(
        select(XmlEvidence).where(
            XmlEvidence.tenant_id == tenant_id,
            XmlEvidence.storage_key == key,
        ),
        limit,
    )


def xml_evidence_by_sha256(
    tenant_id: str, sha256: str, *, limit: int = 100
) -> Select[tuple[XmlEvidence]]:
    """Build a tenant-scoped evidence-hash lookup."""

    digest = _sha256(sha256)
    return _limited(
        select(XmlEvidence).where(
            XmlEvidence.tenant_id == tenant_id,
            XmlEvidence.xml_sha256 == digest,
        ),
        limit,
    )


def xml_evidence_by_parser_status(
    tenant_id: str, parser_status: str, *, limit: int = 100
) -> Select[tuple[XmlEvidence]]:
    """Build the newest-first XML-evidence parser backlog query."""

    statement = select(XmlEvidence).where(
        XmlEvidence.tenant_id == tenant_id,
        XmlEvidence.parser_status == parser_status,
    )
    return _limited(statement.order_by(XmlEvidence.created_at.desc()), limit)


def documents_by_parser_status(
    tenant_id: str, parser_status: str, *, limit: int = 100
) -> Select[tuple[CfdiDocument]]:
    """Build the recent-document query used for parser follow-up."""

    statement = select(CfdiDocument).where(
        CfdiDocument.tenant_id == tenant_id,
        CfdiDocument.parser_status == parser_status,
    )
    return _limited(statement.order_by(CfdiDocument.updated_at.desc()), limit)


def reconciliation_by_state(
    tenant_id: str, state: str, *, limit: int = 100
) -> Select[tuple[CfdiMetadataLedger]]:
    """Build the most recently observed reconciliation backlog query."""

    statement = select(CfdiMetadataLedger).where(
        CfdiMetadataLedger.tenant_id == tenant_id,
        CfdiMetadataLedger.reconciliation_state == state,
    )
    return _limited(statement.order_by(CfdiMetadataLedger.last_seen_at.desc()), limit)


def jobs_by_status(
    tenant_id: str, status: str, *, limit: int = 100
) -> Select[tuple[DownloadJob]]:
    """Build the recent durable-job status query."""

    statement = select(DownloadJob).where(
        DownloadJob.tenant_id == tenant_id,
        DownloadJob.status == status,
    )
    return _limited(statement.order_by(DownloadJob.updated_at.desc()), limit)


def job_events_for_job(job_id: str, *, limit: int = 100) -> Select[tuple[QueueJobEvent]]:
    """Build a newest-first audit-event query for one durable job id."""

    statement = select(QueueJobEvent).where(QueueJobEvent.job_id == job_id)
    return _limited(statement.order_by(QueueJobEvent.created_at.desc()), limit)


def _limited(statement: Select[tuple[object]], limit: int) -> Select[tuple[object]]:
    if limit <= 0:
        raise ValueError("query limit must be positive")
    return statement.limit(limit)


def _sha256(value: str) -> str:
    if not _SHA256.fullmatch(value):
        raise ValueError("evidence SHA-256 must be 64 hexadecimal characters")
    return value.lower()
