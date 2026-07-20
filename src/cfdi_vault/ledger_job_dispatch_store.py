"""PostgreSQL dispatch metadata hydration for durable parse consumers."""

from __future__ import annotations

from sqlalchemy import Column, MetaData, SmallInteger, String, Table, select

from cfdi_vault.accounting_ledger_worker import LedgerDispatchMetadata
from cfdi_vault.domain import QueueName
from cfdi_vault.queue_safety import validate_reference_string

_METADATA = MetaData()
_JOBS = Table(
    "ledger_jobs",
    _METADATA,
    Column("job_id", String(96)),
    Column("tenant_id", String(64)),
    Column("job_type", String(64)),
    Column("queue_name", String(128)),
    Column("artifact_ref", String(192)),
    Column("idempotency_key", String(192)),
)
_OUTBOX = Table(
    "ledger_outbox",
    _METADATA,
    Column("event_id", String(96)),
    Column("job_id", String(96)),
    Column("event_type", String(64)),
    Column("routing_key", String(128)),
    Column("idempotency_key", String(192)),
    Column("schema_version", SmallInteger),
)


class LedgerDispatchStoreMixin:
    """Add one short read transaction for event/job identity hydration."""

    def get_dispatch_metadata(self, event_id: str, job_id: str) -> LedgerDispatchMetadata | None:
        event_id = validate_reference_string("event_id", event_id)
        job_id = validate_reference_string("job_id", job_id)
        with self._engine.connect() as connection:
            row = connection.execute(
                select(
                    _JOBS.c.tenant_id,
                    _JOBS.c.job_type,
                    _JOBS.c.queue_name,
                    _OUTBOX.c.event_type,
                    _OUTBOX.c.routing_key,
                    _JOBS.c.artifact_ref,
                    _JOBS.c.idempotency_key,
                    _OUTBOX.c.idempotency_key.label("event_idempotency_key"),
                    _OUTBOX.c.schema_version,
                )
                .join(_OUTBOX, _OUTBOX.c.job_id == _JOBS.c.job_id)
                .where(_OUTBOX.c.event_id == event_id, _JOBS.c.job_id == job_id)
            ).first()
        if row is None or row.idempotency_key != row.event_idempotency_key:
            return None
        try:
            queue_name = QueueName(row.queue_name)
        except ValueError:
            return None
        return LedgerDispatchMetadata(
            tenant_id=row.tenant_id,
            job_type=row.job_type,
            queue_name=queue_name,
            event_type=row.event_type,
            routing_key=row.routing_key,
            artifact_ref=row.artifact_ref,
            idempotency_key=row.idempotency_key,
            schema_version=row.schema_version,
        )
