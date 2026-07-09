from __future__ import annotations

from datetime import datetime, timezone

from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_contract import DeliveryAction, RetryPolicy, RetryableQueueError
from cfdi_vault.queueing import InMemoryQueue

NOW = datetime(2026, 7, 9, tzinfo=timezone.utc)


def _message(*, attempt: int = 0, message_id: str = "message-001") -> QueueMessage:
    return QueueMessage(
        queue=QueueName.CFDI_PARSE_XML,
        tenant_id="synthetic-tenant",
        profile_id="profile-ref-001",
        job_id="job-001",
        correlation_id="correlation-001",
        attempt=attempt,
        created_at=NOW,
        message_id=message_id,
        idempotency_key="idem-001",
    )


class _Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now = self.now.replace(second=self.now.second + seconds)


def test_in_memory_keeps_delivery_queued_until_handler_success() -> None:
    clock = _Clock()
    queue = InMemoryQueue(clock=clock)
    events: list[str] = []
    queue.publish(_message())

    outcome = queue.consume_one_reliably(
        QueueName.CFDI_PARSE_XML.value,
        lambda message: events.append(f"handled-with-{queue.pending_count()}-pending") or "ok",
    )

    assert events == ["handled-with-1-pending"]
    assert outcome is not None and outcome.action is DeliveryAction.ACK
    assert outcome.result == "ok"
    assert queue.pending_count() == 0


def test_in_memory_retry_and_dead_letter_are_bounded_and_redacted() -> None:
    clock = _Clock()
    queue = InMemoryQueue(retry_policy=RetryPolicy(max_attempts=2, backoff_seconds=(5,)), clock=clock)
    queue.publish(_message())
    retry = queue.consume_one_reliably(
        QueueName.CFDI_PARSE_XML.value,
        lambda message: (_ for _ in ()).throw(RetryableQueueError("transport_unavailable")),
    )
    retried = queue.peek(QueueName.CFDI_PARSE_XML.value)
    assert retry is not None and retry.action is DeliveryAction.RETRY
    assert retried is not None and retried.attempt == 1
    assert retried.idempotency_key == "idem-001" and retried.message_id != "message-001"

    assert queue.consume_one_reliably(QueueName.CFDI_PARSE_XML.value, lambda message: "too-early") is None
    clock.advance(5)
    exhausted = queue.consume_one_reliably(
        QueueName.CFDI_PARSE_XML.value,
        lambda message: (_ for _ in ()).throw(RetryableQueueError("transport_unavailable")),
    )
    assert exhausted is not None and exhausted.action is DeliveryAction.DEAD_LETTER
    assert "payload" not in queue.dead_letters()[0].as_dict()
    assert "profile-ref-001" not in str(queue.dead_letters()[0].as_dict())


def test_in_memory_scheduled_head_preserves_queue_order() -> None:
    clock = _Clock()
    queue = InMemoryQueue(retry_policy=RetryPolicy(max_attempts=2, backoff_seconds=(5,)), clock=clock)
    queue.publish(_message(message_id="first"))
    queue.consume_one_reliably(
        QueueName.CFDI_PARSE_XML.value,
        lambda message: (_ for _ in ()).throw(RetryableQueueError("transient")),
    )
    queue.publish(_message(message_id="second"))
    seen: list[str] = []

    assert queue.consume_one_reliably(QueueName.CFDI_PARSE_XML.value, lambda message: seen.append(message.message_id)) is None
    clock.advance(5)
    queue.consume_one_reliably(QueueName.CFDI_PARSE_XML.value, lambda message: seen.append(message.message_id))
    queue.consume_one_reliably(QueueName.CFDI_PARSE_XML.value, lambda message: seen.append(message.message_id))

    assert seen[1:] == ["second"]
    assert seen[0] != "first"  # retry receives a new delivery identifier


def test_in_memory_exposes_no_destructive_consume_without_handler() -> None:
    queue = InMemoryQueue()

    assert not hasattr(queue, "consume_one")
    assert not hasattr(queue, "consume_one_with_handler")
