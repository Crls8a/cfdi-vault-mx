from __future__ import annotations

from dataclasses import dataclass

from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_contract import DeliveryAction, DeliveryOutcome, RetryableQueueError, WorkerJobEnvelope
from cfdi_vault.queueing import InMemoryQueue
from cfdi_vault.worker import InMemoryIdempotencyStore, RecoveryWorker


def _message(message_id: str) -> QueueMessage:
    return QueueMessage(
        queue=QueueName.CFDI_PARSE_XML,
        tenant_id="synthetic-tenant",
        profile_id="profile-ref-001",
        job_id="job-001",
        correlation_id="correlation-001",
        message_id=message_id,
        idempotency_key="idem-001",
    )


@dataclass(frozen=True)
class _Result:
    job_id: str = "job-001"
    status: str = "succeeded"


class _Service:
    def __init__(self, queue: InMemoryQueue) -> None:
        self.queue = queue
        self.calls = 0
        self.envelopes: list[WorkerJobEnvelope] = []

    def process_worker_job_envelope(self, envelope: WorkerJobEnvelope, *, worker_ref: str) -> _Result:
        self.calls += 1
        self.envelopes.append(envelope)
        return _Result(job_id=envelope.job_id)

    def process_queue_message(self, message: QueueMessage) -> _Result:
        self.calls += 1
        return _Result()

    def queue_status(self) -> tuple[object, ...]:
        return ()


def test_worker_process_local_idempotency_suppresses_duplicate_without_exactly_once_claim() -> None:
    queue = InMemoryQueue()
    service = _Service(queue)
    worker = RecoveryWorker(service)  # type: ignore[arg-type]
    queue.publish(_message("message-001"))
    queue.publish(_message("message-002"))

    first = worker.run_once(queue_name=QueueName.CFDI_PARSE_XML.value)
    duplicate = worker.run_once(queue_name=QueueName.CFDI_PARSE_XML.value)

    assert first.processed == 1
    assert duplicate.processed == 0
    assert duplicate.detail == "Duplicate delivery acknowledged; durable idempotency is not configured."
    assert service.calls == 1


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_process_local_idempotency_claim_expires() -> None:
    clock = _Clock()
    store = InMemoryIdempotencyStore(max_entries=2, ttl_seconds=10, clock=clock)
    assert store.acquire("job-a") is True
    store.complete("job-a")
    assert store.acquire("job-a") is False

    clock.now = 11

    assert store.acquire("job-a") is True


def test_process_local_idempotency_evicts_least_recent_completed_claim() -> None:
    clock = _Clock()
    store = InMemoryIdempotencyStore(max_entries=2, ttl_seconds=60, clock=clock)
    assert store.acquire("job-a") is True
    store.complete("job-a")
    clock.now = 1
    assert store.acquire("job-b") is True
    store.complete("job-b")

    clock.now = 2
    assert store.acquire("job-c") is True
    store.release("job-c")
    assert store.acquire("job-a") is True


class _UnsafeQueue:
    def consume_one_with_handler(self, queue_name: str, handler: object) -> object:
        raise AssertionError("unsafe fallback must not be called")


def test_worker_requires_reliable_queue_consumption() -> None:
    service = _Service(_UnsafeQueue())  # type: ignore[arg-type]
    worker = RecoveryWorker(service)  # type: ignore[arg-type]

    try:
        worker.run_once()
    except RuntimeError as exc:
        assert str(exc) == "Queue adapter does not support reliable consumption."
    else:
        raise AssertionError("worker accepted an unsafe queue adapter")


def test_worker_passes_typed_envelope_to_services_that_support_it() -> None:
    queue = InMemoryQueue()
    service = _Service(queue)
    worker = RecoveryWorker(service, worker_id="worker-001")  # type: ignore[arg-type]
    queue.publish(_message("message-001"))

    report = worker.run_once(queue_name=QueueName.CFDI_PARSE_XML.value)

    assert report.processed == 1
    assert service.envelopes[0].job_id == "job-001"
    assert service.envelopes[0].queue is QueueName.CFDI_PARSE_XML
    assert service.envelopes[0].idempotency_key == "idem-001"


def test_worker_reports_safe_retry_reason() -> None:
    class _RetryService(_Service):
        def process_worker_job_envelope(self, envelope: WorkerJobEnvelope, *, worker_ref: str) -> _Result:
            raise RetryableQueueError("storage_temporarily_unavailable")

    queue = InMemoryQueue()
    service = _RetryService(queue)
    worker = RecoveryWorker(service)  # type: ignore[arg-type]
    queue.publish(_message("message-001"))

    report = worker.run_once(queue_name=QueueName.CFDI_PARSE_XML.value)

    assert report.processed == 0
    assert report.detail == "Retry scheduled after classified reason: storage_temporarily_unavailable."


class _UnsafeReasonQueue:
    def consume_one_reliably(self, queue_name: str, handler: object) -> object:
        return DeliveryOutcome(
            DeliveryAction.RETRY,
            _message("message-unsafe"),
            reason_code="<soap:Envelope>must-not-enter</soap:Envelope>",
        )


def test_worker_cannot_echo_unsafe_adapter_reason_code() -> None:
    service = _Service(_UnsafeReasonQueue())  # type: ignore[arg-type]
    worker = RecoveryWorker(service)  # type: ignore[arg-type]

    try:
        worker.run_once(queue_name=QueueName.CFDI_PARSE_XML.value)
    except ValueError as exc:
        assert "reason_code" in str(exc)
    else:
        raise AssertionError("worker echoed an unsafe adapter-provided reason code")
