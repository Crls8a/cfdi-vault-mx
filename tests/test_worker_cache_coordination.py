from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from threading import Event, Lock, Thread
import time

import pytest

from cfdi_vault.cache import InMemoryCache
from cfdi_vault.cache_contract import HeartbeatState, ProgressObservation, ProgressStatus
from cfdi_vault.cache_recovery import AbandonedJobRecovery
from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_contract import RetryableQueueError
from cfdi_vault.queueing import InMemoryQueue
from cfdi_vault.worker import RecoveryWorker


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        self._lock = Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self.now

    def advance(self, seconds: int) -> None:
        with self._lock:
            self.now += timedelta(seconds=seconds)


@dataclass(frozen=True)
class _Result:
    job_id: str = "job-001"
    status: str = "succeeded"


class _Service:
    def __init__(self, cache: InMemoryCache) -> None:
        self.queue = InMemoryQueue()
        self.cache = cache
        self.worker_refs: list[str] = []

    def process_queue_message_for_worker(
        self,
        message: QueueMessage,
        *,
        worker_ref: str,
    ) -> _Result:
        self.worker_refs.append(worker_ref)
        return _Result(job_id=message.job_id)


class _LongService(_Service):
    def __init__(self, cache: InMemoryCache) -> None:
        super().__init__(cache)
        self.started = Event()
        self.release = Event()

    def process_queue_message_for_worker(
        self,
        message: QueueMessage,
        *,
        worker_ref: str,
    ) -> _Result:
        self.worker_refs.append(worker_ref)
        self.started.set()
        assert self.release.wait(timeout=2)
        return _Result(job_id=message.job_id)


class _DurableJobs:
    def __init__(self) -> None:
        self.calls = 0

    def mark_job_abandoned(self, observation: object) -> bool:
        self.calls += 1
        return True


@pytest.mark.parametrize("interval", [0, 10, 11])
def test_worker_requires_heartbeat_interval_shorter_than_ttl(interval: float) -> None:
    cache = InMemoryCache()
    service = _Service(cache)

    with pytest.raises(ValueError, match="less than the heartbeat TTL"):
        RecoveryWorker(
            service,  # type: ignore[arg-type]
            heartbeat_ttl_seconds=10,
            heartbeat_interval_seconds=interval,
        )


def test_worker_records_and_renews_heartbeat_on_each_poll() -> None:
    clock = _Clock()
    cache = InMemoryCache(clock=clock)
    service = _Service(cache)
    worker = RecoveryWorker(
        service,  # type: ignore[arg-type]
        worker_id="worker-001",
        clock=clock,
        heartbeat_ttl_seconds=10,
    )

    worker.run_once()
    first = cache.get_heartbeat("worker-001")
    assert first is not None
    assert first.updated_at == clock()

    clock.advance(9)
    worker.run_once()
    renewed = cache.get_heartbeat("worker-001")
    assert renewed is not None
    assert renewed.updated_at == clock()
    clock.advance(10)
    assert cache.get_heartbeat("worker-001") is None


def test_worker_passes_opaque_worker_reference_to_recovery_service() -> None:
    clock = _Clock()
    cache = InMemoryCache(clock=clock)
    service = _Service(cache)
    worker = RecoveryWorker(
        service,  # type: ignore[arg-type]
        worker_id="worker-001",
        clock=clock,
    )
    service.queue.publish(
        QueueMessage(
            queue=QueueName.SAT_REQUEST,
            tenant_id="tenant-demo",
            job_id="job-001",
        )
    )

    report = worker.run_once()

    assert report.processed == 1
    assert service.worker_refs == ["worker-001"]


def test_long_handler_renews_heartbeat_and_prevents_false_abandonment() -> None:
    clock = _Clock()
    cache = InMemoryCache(clock=clock)
    service = _LongService(cache)
    worker = RecoveryWorker(
        service,  # type: ignore[arg-type]
        worker_id="worker-001",
        clock=clock,
        heartbeat_ttl_seconds=10,
        heartbeat_interval_seconds=0.01,
    )
    message = QueueMessage(
        queue=QueueName.SAT_REQUEST,
        tenant_id="tenant-demo",
        job_id="job-001",
    )
    service.queue.publish(message)
    progress = ProgressObservation(
        job_id="job-001",
        tenant_id="tenant-demo",
        worker_ref="worker-001",
        status=ProgressStatus.RUNNING,
        percent=50,
        updated_at=clock(),
    )
    cache.set_progress(progress, 120)
    durable = _DurableJobs()
    recovery = AbandonedJobRecovery(
        cache,
        durable,
        clock=clock,
        stale_after_seconds=5,
    )
    thread = Thread(target=worker.run_once)
    thread.start()
    assert service.started.wait(timeout=1)

    clock.advance(6)
    deadline = time.monotonic() + 1
    while (
        cache.get_heartbeat("worker-001") is None
        or cache.get_heartbeat("worker-001").updated_at != clock()  # type: ignore[union-attr]
    ) and time.monotonic() < deadline:
        time.sleep(0.01)

    result = recovery.recover(progress)
    service.release.set()
    thread.join(timeout=1)

    assert result.heartbeat_state is HeartbeatState.ALIVE
    assert result.durable_transitioned is False
    assert durable.calls == 0
    assert not thread.is_alive()


def test_heartbeat_renewal_failure_is_classified_and_releases_idempotency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _Service(InMemoryCache())
    renewal_failed = Event()
    classified: list[Exception] = []
    worker = RecoveryWorker(
        service,  # type: ignore[arg-type]
        heartbeat_interval_seconds=0.01,
        classify_failure=lambda error: (
            classified.append(error) or RetryableQueueError("heartbeat_renewal_failed")
        ),
    )
    heartbeat_attempts = 0

    def fail_on_renewal() -> None:
        nonlocal heartbeat_attempts
        heartbeat_attempts += 1
        if heartbeat_attempts > 1:
            renewal_failed.set()
            raise RuntimeError("cache unavailable")

    def finish_after_renewal_failure(message: QueueMessage, *, worker_ref: str) -> _Result:
        assert renewal_failed.wait(timeout=1)
        return _Result(job_id=message.job_id)

    monkeypatch.setattr(worker, "_record_heartbeat", fail_on_renewal)
    monkeypatch.setattr(service, "process_queue_message_for_worker", finish_after_renewal_failure)
    message = QueueMessage(queue=QueueName.SAT_REQUEST, tenant_id="tenant-demo", job_id="job-001")
    service.queue.publish(message)

    report = worker.run_once()

    assert report.processed == 0
    assert report.detail == "Retry scheduled after classified reason: heartbeat_renewal_failed."
    assert str(classified[0]) == "worker heartbeat renewal failed"
    assert service.queue.pending_count(QueueName.SAT_REQUEST.value) == 1
    assert worker.idempotency.acquire(message.idempotency_key) is True
    worker.idempotency.release(message.idempotency_key)
    worker.idempotency.release(message.idempotency_key)
    assert worker.idempotency.acquire(message.idempotency_key) is True
