from __future__ import annotations

import time
from datetime import datetime, timezone
from threading import Event, Thread

from cfdi_vault.cache import InMemoryCache
from cfdi_vault.cache_contract import WorkerEvent, WorkerEventType
from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.ledger_job_consumer import LedgerConsumerReport
from cfdi_vault.queueing import InMemoryQueue
from cfdi_vault.worker import RecoveryWorker

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


class _Service:
    def __init__(self, cache: object) -> None:
        self.cache = cache
        self.queue = InMemoryQueue()

    def process_queue_message_for_worker(self, message: QueueMessage, *, worker_ref: str):
        return type("Result", (), {"job_id": message.job_id, "status": "succeeded"})()


def test_worker_event_contract_is_redacted_and_round_trips() -> None:
    event = WorkerEvent("worker-001", WorkerEventType.STARTED, NOW)

    assert event.as_dict() == {
        "worker_id": "worker-001",
        "event_type": "worker_started",
        "occurred_at": NOW.isoformat(),
    }
    assert WorkerEvent.from_dict(event.as_dict()) == event
    assert "tenant" not in event.as_dict()
    assert "job" not in event.as_dict()


def test_run_forever_publishes_all_lifecycle_events() -> None:
    cache = InMemoryCache(clock=lambda: NOW)
    worker = RecoveryWorker(_Service(cache), worker_id="worker-001", clock=lambda: NOW)  # type: ignore[arg-type]
    calls = 0

    def stop() -> bool:
        nonlocal calls
        calls += 1
        return calls > 1

    worker.run_forever(poll_seconds=0, stop=stop)

    for event_type in WorkerEventType:
        event = cache.get_worker_event("worker-001", event_type.value)
        assert event is not None
        assert event.event_type is event_type


def test_cache_event_failure_does_not_break_worker_work() -> None:
    class BrokenCache:
        def record_heartbeat(self, *_args: object) -> None:
            pass

        def publish_worker_event(self, *_args: object) -> None:
            raise RuntimeError("cache unavailable")

    service = _Service(BrokenCache())
    service.queue.publish(QueueMessage(queue=QueueName.SAT_REQUEST, tenant_id="tenant-demo", job_id="job-001"))
    report = RecoveryWorker(service, worker_id="worker-001", clock=lambda: NOW).run_once()  # type: ignore[arg-type]

    assert report.processed == 1


def test_heartbeat_cache_failure_does_not_break_worker_work() -> None:
    class BrokenHeartbeatCache:
        def record_heartbeat(self, *_args: object) -> None:
            raise RuntimeError("redis unavailable")

        def publish_worker_event(self, *_args: object) -> None:
            raise RuntimeError("redis unavailable")

    service = _Service(BrokenHeartbeatCache())
    service.queue.publish(QueueMessage(queue=QueueName.SAT_REQUEST, tenant_id="tenant-demo", job_id="job-001"))
    report = RecoveryWorker(service, worker_id="worker-001", clock=lambda: NOW).run_once()  # type: ignore[arg-type]

    assert report.processed == 1


def test_heartbeat_renewal_cache_failure_does_not_retry_a_slow_job() -> None:
    class BrokenHeartbeatCache:
        def record_heartbeat(self, *_args: object) -> None:
            raise RuntimeError("redis unavailable")

        def publish_worker_event(self, *_args: object) -> None:
            raise RuntimeError("redis unavailable")

    class SlowService(_Service):
        def __init__(self, cache: object) -> None:
            super().__init__(cache)
            self.started = Event()
            self.release = Event()

        def process_queue_message_for_worker(self, message: QueueMessage, *, worker_ref: str):
            self.started.set()
            assert self.release.wait(timeout=1)
            return super().process_queue_message_for_worker(message, worker_ref=worker_ref)

    service = SlowService(BrokenHeartbeatCache())
    service.queue.publish(QueueMessage(queue=QueueName.SAT_REQUEST, tenant_id="tenant-demo", job_id="job-001"))
    worker = RecoveryWorker(
        service,  # type: ignore[arg-type]
        worker_id="worker-001",
        clock=lambda: NOW,
        heartbeat_interval_seconds=0.005,
    )
    result: list[object] = []
    thread = Thread(target=lambda: result.append(worker.run_once()))
    thread.start()
    assert service.started.wait(timeout=1)
    time.sleep(0.03)
    service.release.set()
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert result and result[0].processed == 1  # type: ignore[union-attr]


def test_durable_parse_jobs_renew_heartbeat_during_long_processing() -> None:
    class RecordingCache:
        def __init__(self) -> None:
            self.heartbeats = []
            self.renewed = Event()

        def record_heartbeat(self, heartbeat: object, ttl_seconds: int) -> None:
            self.heartbeats.append(heartbeat)
            if len(self.heartbeats) >= 2:
                self.renewed.set()

        def publish_worker_event(self, *_args: object) -> None:
            pass

    cache = RecordingCache()
    service = _Service(cache)
    started = Event()
    release = Event()

    class SlowLedgerConsumer:
        def handle(self, message: QueueMessage) -> LedgerConsumerReport:
            started.set()
            assert release.wait(timeout=1)
            return LedgerConsumerReport("succeeded")

    service.queue.publish(QueueMessage(queue=QueueName.CFDI_PARSE_XML, tenant_id="tenant-demo", job_id="job-001"))
    worker = RecoveryWorker(
        service,  # type: ignore[arg-type]
        worker_id="worker-001",
        clock=lambda: NOW,
        heartbeat_interval_seconds=0.005,
        ledger_consumer=SlowLedgerConsumer(),  # type: ignore[arg-type]
    )
    result: list[object] = []
    thread = Thread(target=lambda: result.append(worker.run_once(queue_name=QueueName.CFDI_PARSE_XML.value)))
    thread.start()
    assert started.wait(timeout=1)
    assert cache.renewed.wait(timeout=1)
    release.set()
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert result and result[0].processed == 1  # type: ignore[union-attr]
    assert len(cache.heartbeats) >= 2


def test_run_one_shot_emits_stopped_once_after_the_poll() -> None:
    class RecordingCache:
        def __init__(self) -> None:
            self.events: list[WorkerEventType] = []

        def record_heartbeat(self, *_args: object) -> None:
            pass

        def publish_worker_event(self, event: WorkerEvent, _ttl_seconds: int) -> None:
            self.events.append(event.event_type)

    cache = RecordingCache()
    report = RecoveryWorker(_Service(cache), worker_id="worker-001", clock=lambda: NOW).run_one_shot()

    assert report.processed == 0
    assert cache.events == [
        WorkerEventType.STARTED,
        WorkerEventType.HEARTBEAT,
        WorkerEventType.IDLE,
        WorkerEventType.STOPPED,
    ]


def test_worker_idle_is_not_emitted_after_processing_a_job() -> None:
    cache = InMemoryCache(clock=lambda: NOW)
    service = _Service(cache)
    service.queue.publish(QueueMessage(queue=QueueName.SAT_REQUEST, tenant_id="tenant-demo", job_id="job-001"))

    report = RecoveryWorker(service, worker_id="worker-001", clock=lambda: NOW).run_once()  # type: ignore[arg-type]

    assert report.processed == 1
    assert cache.get_worker_event("worker-001", WorkerEventType.IDLE.value) is None
