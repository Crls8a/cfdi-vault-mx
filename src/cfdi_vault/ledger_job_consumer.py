"""Durable consumer boundary for metadata and XML parse jobs.

RabbitMQ carries only the existing ``QueueMessage`` references.  The consumer
hydrates artifact and dispatch metadata from PostgreSQL, records inbox receipt,
and invokes the parser only after a durable ledger claim.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from cfdi_vault.accounting_ledger_worker import (
    LedgerDispatchMetadata,
    LedgerDispatchStore,
    LedgerJobStore,
    LedgerParseAggregate,
    LedgerParseJob,
    LedgerWorker,
)
from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_contract import DeliveryAction, DeliveryOutcome, RetryableQueueError, TerminalQueueError
from cfdi_vault.queue_safety import validate_reason_code, validate_reference_string

_PARSE_JOB_TYPES = {
    QueueName.CFDI_PARSE_METADATA: "metadata_parse",
    QueueName.CFDI_PARSE_XML: "xml_parse",
}


class ReliableQueue(Protocol):
    """Subset of queue adapters needed for one reliable delivery."""

    def consume_one_reliably(
        self,
        queue_name: str,
        handler: Callable[[QueueMessage], object],
    ) -> DeliveryOutcome | None: ...


class LedgerConsumerStore(LedgerDispatchStore, LedgerJobStore, Protocol):
    """Combined durable inbox, metadata, claim, and result port."""


class LedgerJobConsumerError(TerminalQueueError):
    """Classified delivery failure that must not expose raw storage errors."""


class LedgerJobConsumerRetryableError(RetryableQueueError):
    """Durable claim or inbox transition was stale and may be retried."""


@dataclass(frozen=True, slots=True, repr=False)
class LedgerConsumerReport:
    """Sanitized result of one queue delivery."""

    status: str
    aggregate: LedgerParseAggregate = field(default_factory=LedgerParseAggregate)
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"idle", "succeeded", "duplicate", "failed", "dead_letter"}:
            raise ValueError("unsupported ledger consumer status")
        if self.reason_code is not None:
            validate_reason_code(self.reason_code)

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"status": self.status, "aggregates": self.aggregate.as_dict()}
        if self.reason_code is not None:
            result["reason_code"] = self.reason_code
        return result

    def __repr__(self) -> str:
        return f"LedgerConsumerReport({self.as_dict()!r})"


class LedgerJobConsumer:
    """Consume one parse message with durable inbox and job fencing."""

    def __init__(
        self,
        store: LedgerConsumerStore,
        parser: Callable[[LedgerParseJob], LedgerParseAggregate],
        *,
        consumer_name: str,
        worker_ref: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        validate_reference_string("consumer_name", consumer_name)
        validate_reference_string("worker_ref", worker_ref)
        self._store = store
        self._parser = parser
        self._consumer_name = consumer_name
        self._worker = LedgerWorker(store, worker_ref=worker_ref, clock=clock)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def handle(self, message: QueueMessage) -> LedgerConsumerReport:
        """Handle one message; returning means the adapter may acknowledge it."""

        if not isinstance(message, QueueMessage):
            raise LedgerJobConsumerError("invalid_message")
        if message.queue not in _PARSE_JOB_TYPES:
            raise LedgerJobConsumerError("not_parse_queue")
        received_at = self._stamp(self._clock())
        try:
            first_receipt = self._store.register_inbox_event(
                message.message_id,
                self._consumer_name,
                received_at=received_at,
            )
        except Exception:
            raise LedgerJobConsumerError("inbox_register_failed") from None
        if first_receipt.status == "duplicate":
            return LedgerConsumerReport("duplicate", reason_code="duplicate_delivery")
        if first_receipt.status == "in_flight":
            raise LedgerJobConsumerRetryableError("inbox_in_flight")

        try:
            metadata = self._store.get_dispatch_metadata(message.message_id, message.job_id)
        except Exception:
            raise LedgerJobConsumerError("dispatch_lookup_failed") from None
        invalid_reason = self._validate_identity(message, metadata)
        if invalid_reason is not None:
            return self._finish_inbox(message, "failed", invalid_reason)
        assert metadata is not None
        job = LedgerParseJob(
            tenant_id=metadata.tenant_id,
            artifact_ref=metadata.artifact_ref or "",
            queue=metadata.queue_name,
            idempotency_key=metadata.idempotency_key,
            job_id=message.job_id,
        )
        worker_report = self._worker.run_hydrated(job, self._parser)
        if worker_report.status == "stale":
            raise LedgerJobConsumerRetryableError("claim_stale")
        return self._finish_inbox(message, worker_report.status, worker_report.reason_code, worker_report.aggregate)

    def run_once(self, queue: ReliableQueue, *, queue_name: QueueName) -> LedgerConsumerReport:
        """Consume one message through the existing reliable queue contract."""

        outcome = queue.consume_one_reliably(queue_name.value, self.handle)
        if outcome is None:
            return LedgerConsumerReport("idle")
        if outcome.action is DeliveryAction.ACK:
            result = outcome.result
            if isinstance(result, LedgerConsumerReport):
                return result
            return LedgerConsumerReport("succeeded")
        if outcome.action is DeliveryAction.RETRY:
            return LedgerConsumerReport("failed", reason_code=outcome.reason_code or "retry_scheduled")
        return LedgerConsumerReport("dead_letter", reason_code=outcome.reason_code or "delivery_failed")

    def _finish_inbox(
        self,
        message: QueueMessage,
        status: str,
        reason_code: str | None,
        aggregate: LedgerParseAggregate | None = None,
    ) -> LedgerConsumerReport:
        result_code = reason_code or ("parse_succeeded" if status == "succeeded" else f"parse_{status}")
        try:
            processed = self._store.mark_inbox_processed(
                message.message_id,
                self._consumer_name,
                result_code,
                now=self._stamp(self._clock()),
            )
        except Exception:
            raise LedgerJobConsumerError("inbox_process_failed") from None
        if not processed:
            raise LedgerJobConsumerError("inbox_process_failed")
        return LedgerConsumerReport(status, aggregate or LedgerParseAggregate(), reason_code)

    @staticmethod
    def _validate_identity(message: QueueMessage, metadata: LedgerDispatchMetadata | None) -> str | None:
        if metadata is None:
            return "dispatch_not_found"
        expected_type = _PARSE_JOB_TYPES.get(metadata.queue_name)
        expected_queue = metadata.queue_name.value
        if metadata.schema_version != 1:
            return "unsupported_envelope"
        if (
            metadata.tenant_id != message.tenant_id
            or metadata.queue_name is not message.queue
            or metadata.event_type != expected_type
            or metadata.routing_key != expected_queue
            or metadata.idempotency_key != message.idempotency_key
            or metadata.job_type != expected_type
        ):
            return "dispatch_mismatch"
        if metadata.artifact_ref is None:
            return "artifact_missing"
        return None

    @staticmethod
    def _stamp(value: datetime) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("ledger consumer timestamp must be timezone-aware")
        return value
