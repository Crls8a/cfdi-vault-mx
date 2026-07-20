from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from cfdi_vault.accounting_ledger_worker import (
    LedgerClaim,
    LedgerDispatchMetadata,
    LedgerInboxReceipt,
    LedgerParseAggregate,
    LedgerParseError,
)
from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.ledger_job_consumer import LedgerJobConsumer, LedgerJobConsumerRetryableError
from cfdi_vault.queueing import InMemoryQueue

NOW = datetime(2026, 1, 15, tzinfo=timezone.utc)


def _message(*, job_id: str = "job-synthetic", event_id: str = "event-synthetic") -> QueueMessage:
    return QueueMessage(
        queue=QueueName.CFDI_PARSE_METADATA,
        tenant_id="tenant-synthetic",
        job_id=job_id,
        correlation_id=job_id,
        message_id=event_id,
        idempotency_key="idem-synthetic",
        created_at=NOW,
    )


@dataclass
class FakeStore:
    metadata: LedgerDispatchMetadata | None = LedgerDispatchMetadata(
        tenant_id="tenant-synthetic",
        job_type="metadata_parse",
        queue_name=QueueName.CFDI_PARSE_METADATA,
        event_type="metadata_parse",
        routing_key="cfdi.parse.metadata",
        artifact_ref="artifact-synthetic",
        idempotency_key="idem-synthetic",
        schema_version=1,
    )
    accepted: bool = True

    def __post_init__(self) -> None:
        self.events: list[str] = []
        self.received: set[str] = set()
        self.processed: set[str] = set()
        self.transaction_open = False
        self.completed: list[LedgerParseAggregate] = []
        self.failed: list[str] = []

    def register_inbox_event(self, event_id: str, consumer_name: str, *, received_at: datetime) -> LedgerInboxReceipt:
        self.events.append("inbox_register")
        if event_id in self.received:
            return LedgerInboxReceipt("duplicate" if event_id in self.processed else "in_flight")
        self.received.add(event_id)
        return LedgerInboxReceipt("new")

    def mark_inbox_processed(self, event_id: str, consumer_name: str, result_code: str, *, now: datetime) -> bool:
        self.events.append("inbox_processed")
        self.processed.add(event_id)
        return True

    def get_dispatch_metadata(self, event_id: str, job_id: str) -> LedgerDispatchMetadata | None:
        self.events.append("hydrate")
        if event_id != "event-synthetic" or job_id != "job-synthetic":
            return None
        return self.metadata

    def claim_parse_job(self, job, *, worker_ref, now):  # type: ignore[no-untyped-def]
        self.events.append("claim")
        self.transaction_open = True
        result = LedgerClaim("claim-synthetic", self.accepted)
        self.transaction_open = False
        return result

    def complete_parse_job(self, claim_ref, aggregate, *, now):  # type: ignore[no-untyped-def]
        assert not self.transaction_open
        self.events.append("complete")
        self.completed.append(aggregate)
        return True

    def fail_parse_job(self, claim_ref, reason_code, *, now):  # type: ignore[no-untyped-def]
        assert not self.transaction_open
        self.events.append("fail")
        self.failed.append(reason_code)
        return True


def _consumer(store: FakeStore, parser) -> LedgerJobConsumer:  # type: ignore[no-untyped-def]
    return LedgerJobConsumer(
        store,
        parser,
        consumer_name="ledger-consumer-synthetic",
        worker_ref="worker-synthetic",
        clock=lambda: NOW,
    )


def test_queue_message_round_trips_without_payload_fields() -> None:
    message = _message()
    decoded = QueueMessage.from_dict(message.as_dict())

    assert decoded == message
    assert "artifact_ref" not in message.as_dict()
    assert "payload" not in message.as_dict()


def test_duplicate_inbox_receipt_acknowledges_without_parser() -> None:
    store = FakeStore()
    parsed = 0

    def parser(job):  # type: ignore[no-untyped-def]
        nonlocal parsed
        parsed += 1
        return LedgerParseAggregate(records_seen=1)

    consumer = _consumer(store, parser)
    first = consumer.handle(_message())
    second = consumer.handle(_message())

    assert first.status == "succeeded"
    assert second.as_dict() == {"status": "duplicate", "aggregates": {}, "reason_code": "duplicate_delivery"}
    assert parsed == 1


def test_in_flight_inbox_receipt_is_retried_without_ack() -> None:
    store = FakeStore()
    store.received.add("event-synthetic")

    with pytest.raises(LedgerJobConsumerRetryableError) as caught:
        _consumer(store, lambda job: LedgerParseAggregate()).handle(_message())

    assert caught.value.reason_code == "inbox_in_flight"
    assert "inbox_processed" not in store.events


def test_event_and_job_mismatch_is_durable_failure_without_parser() -> None:
    store = FakeStore()
    parsed = False

    def parser(job):  # type: ignore[no-untyped-def]
        nonlocal parsed
        parsed = True
        return LedgerParseAggregate(records_seen=1)

    result = _consumer(store, parser).handle(_message(job_id="other-job"))

    assert result.as_dict() == {"status": "failed", "aggregates": {}, "reason_code": "dispatch_not_found"}
    assert parsed is False
    assert store.events == ["inbox_register", "hydrate", "inbox_processed"]


def test_hydrated_artifact_claims_before_parser_and_completes_before_inbox_ack() -> None:
    store = FakeStore()
    observed: list[tuple[str, str, bool]] = []

    def parser(job):  # type: ignore[no-untyped-def]
        observed.append((job.job_id or "", job.artifact_ref, store.transaction_open))
        return LedgerParseAggregate(records_seen=2, records_written=2)

    result = _consumer(store, parser).handle(_message())

    assert result.status == "succeeded"
    assert observed == [("job-synthetic", "artifact-synthetic", False)]
    assert store.events == ["inbox_register", "hydrate", "claim", "complete", "inbox_processed"]


def test_parser_failure_is_categorized_and_inbox_is_processed() -> None:
    store = FakeStore()

    def parser(job):  # type: ignore[no-untyped-def]
        raise LedgerParseError("parse_invalid")

    result = _consumer(store, parser).handle(_message())

    assert result.as_dict() == {"status": "failed", "aggregates": {}, "reason_code": "parse_invalid"}
    assert store.failed == ["parse_invalid"]
    assert store.events[-2:] == ["fail", "inbox_processed"]


def test_in_memory_queue_redelivery_does_not_duplicate_parser() -> None:
    store = FakeStore()
    parsed = 0

    def parser(job):  # type: ignore[no-untyped-def]
        nonlocal parsed
        parsed += 1
        return LedgerParseAggregate(records_seen=1)

    queue = InMemoryQueue()
    consumer = _consumer(store, parser)
    queue.publish(_message())
    first = consumer.run_once(queue, queue_name=QueueName.CFDI_PARSE_METADATA)
    queue.publish(_message())
    second = consumer.run_once(queue, queue_name=QueueName.CFDI_PARSE_METADATA)

    assert first.status == "succeeded"
    assert second.status == "duplicate"
    assert parsed == 1


def test_metadata_and_report_repr_redact_references() -> None:
    store = FakeStore()
    result = _consumer(store, lambda job: LedgerParseAggregate()).handle(_message())

    for rendered in (repr(store.metadata), repr(result)):
        assert "tenant-synthetic" not in rendered
        assert "artifact-synthetic" not in rendered
        assert "job-synthetic" not in rendered


def test_parser_claim_rejection_is_duplicate_without_external_parser() -> None:
    store = FakeStore(accepted=False)
    called = False

    def parser(job):  # type: ignore[no-untyped-def]
        nonlocal called
        called = True
        return LedgerParseAggregate(records_seen=1)

    result = _consumer(store, parser).handle(_message())

    assert result.status == "duplicate"
    assert called is False
    assert store.events[-1] == "inbox_processed"
