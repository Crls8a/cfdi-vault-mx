"""Durable ledger handoff for campaign package parsing.

This adapter owns the small translation between SAT campaign artifacts and the
V6 ledger jobs/outbox.  It never stores package bytes or publishes a payload;
the optional publisher only sends the reference-only envelope produced by the
durable outbox publisher.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from cfdi_vault.domain import QueueName
from cfdi_vault.ledger_outbox_publisher import LedgerOutboxPublisher, PublisherReport
from cfdi_vault.queueing import RabbitMqQueue


class LedgerJobOutboxStore(Protocol):
    """Store port required to create one idempotent ledger handoff."""

    def create_job_on_connection(self, connection: object, **kwargs: object) -> bool: ...

    def create_outbox_event_on_connection(self, connection: object, **kwargs: object) -> bool: ...


@dataclass(frozen=True, slots=True)
class DurableHandoffResult:
    """Sanitized result of one job/outbox registration."""

    job_created: bool
    event_created: bool
    dispatch: PublisherReport | None


@dataclass(slots=True)
class DurableArtifactJobHandoff:
    """Create and optionally dispatch a reference-only parse job."""

    store: LedgerJobOutboxStore
    publisher: LedgerOutboxPublisher | None = None
    worker_ref: str = "sat-monitor"

    def persist_on_connection(
        self,
        connection: object,
        *,
        tenant_id: str,
        artifact_ref: str,
        kind: str,
        now: datetime,
    ) -> DurableHandoffResult:
        """Register a parse job and outbox event on an existing transaction.

        The caller owns the transaction and must commit it before invoking
        :meth:`publish_after_commit`.  This is the transaction boundary that
        ties artifact metadata to its durable parsing handoff; this method
        deliberately never contacts RabbitMQ.
        """

        queue, job_type, values = self._registration_values(
            tenant_id=tenant_id,
            artifact_ref=artifact_ref,
            kind=kind,
            now=now,
        )
        create_job = getattr(self.store, "create_job_on_connection", None)
        create_event = getattr(self.store, "create_outbox_event_on_connection", None)
        if not callable(create_job) or not callable(create_event):
            raise TypeError("ledger store does not support atomic handoff")
        job_created = create_job(connection, **values[0])
        event_created = create_event(connection, **values[1])
        return DurableHandoffResult(job_created, event_created, None)

    def publish_after_commit(self, *, now: datetime) -> PublisherReport | None:
        """Publish due outbox entries after the caller commits its transaction."""

        if self.publisher is None:
            return None
        return self.publisher.run_once(now=_utc(now), worker_ref=self.worker_ref)

    def enqueue(
        self,
        *,
        tenant_id: str,
        artifact_ref: str,
        kind: str,
        now: datetime,
    ) -> DurableHandoffResult:
        """Persist atomically, then optionally publish after the DB commit.

        The convenience method is DB-backed by design. It refuses stores that
        cannot expose a transaction boundary rather than recreating the old
        job-then-outbox split transaction.
        """

        engine = getattr(self.store, "_engine", None)
        begin = getattr(engine, "begin", None)
        if not callable(begin):
            raise TypeError("ledger store does not support atomic handoff")
        with begin() as connection:
            result = self.persist_on_connection(
                connection,
                tenant_id=tenant_id,
                artifact_ref=artifact_ref,
                kind=kind,
                now=now,
            )
        job_created, event_created = result.job_created, result.event_created
        dispatch = self.publish_after_commit(now=now)
        return DurableHandoffResult(job_created, event_created, dispatch)

    @staticmethod
    def _registration_values(
        *,
        tenant_id: str,
        artifact_ref: str,
        kind: str,
        now: datetime,
    ) -> tuple[QueueName, str, tuple[dict[str, object], dict[str, object]]]:
        if kind not in {"metadata_zip", "metadata_txt", "cfdi_zip", "cfdi_xml"}:
            raise ValueError("artifact job kind is invalid")
        stamp = _utc(now)
        queue = QueueName.CFDI_PARSE_METADATA if kind in {"metadata_zip", "metadata_txt"} else QueueName.CFDI_PARSE_XML
        job_type = "metadata_parse" if queue is QueueName.CFDI_PARSE_METADATA else "xml_parse"
        digest = hashlib.sha256(f"{tenant_id}\0{artifact_ref}\0{job_type}".encode("utf-8")).hexdigest()
        job_id = f"ledger-job-{digest[:32]}"
        event_id = f"ledger-event-{digest[32:64]}"
        idempotency_key = f"parse:{artifact_ref}"
        return (
            queue,
            job_type,
            (
                {
                    "job_id": job_id,
                    "tenant_id": tenant_id,
                    "job_type": job_type,
                    "queue_name": queue.value,
                    "artifact_ref": artifact_ref,
                    "idempotency_key": idempotency_key,
                    "available_at": stamp,
                },
                {
                    "event_id": event_id,
                    "job_id": job_id,
                    "event_type": job_type,
                    "routing_key": queue.value,
                    "idempotency_key": idempotency_key,
                    "available_at": stamp,
                },
            ),
        )


def build_durable_handoff(
    engine: object, rabbitmq_url: str, *, worker_ref: str = "sat-monitor"
) -> DurableArtifactJobHandoff:
    """Build the DB-backed handoff without opening a broker connection."""

    from cfdi_vault.accounting_ledger_jobs_v6 import LedgerJobStoreV6

    store = LedgerJobStoreV6(engine)  # type: ignore[arg-type]
    queue = RabbitMqQueue(rabbitmq_url)
    publisher = LedgerOutboxPublisher(store=store, publisher=queue)
    return DurableArtifactJobHandoff(store=store, publisher=publisher, worker_ref=worker_ref)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
