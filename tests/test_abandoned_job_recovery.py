from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cfdi_vault.cache import InMemoryCache
from cfdi_vault.cache_contract import HeartbeatState, ProgressObservation, ProgressStatus, WorkerHeartbeat
from cfdi_vault.cache_recovery import AbandonedJobObservation, AbandonedJobRecovery


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


@dataclass
class _DurableJobs:
    accept: bool = True

    def __post_init__(self) -> None:
        self.observations: list[AbandonedJobObservation] = []

    def mark_job_abandoned(self, observation: AbandonedJobObservation) -> bool:
        self.observations.append(observation)
        return self.accept


def _progress(clock: _Clock, status: ProgressStatus = ProgressStatus.RUNNING) -> ProgressObservation:
    return ProgressObservation(
        job_id="job-001",
        tenant_id="tenant-demo",
        worker_ref="worker-001",
        status=status,
        percent=40,
        updated_at=clock(),
    )


def test_alive_worker_does_not_delegate_a_durable_transition() -> None:
    clock = _Clock()
    cache = InMemoryCache(clock=clock)
    durable = _DurableJobs()
    progress = _progress(clock)
    cache.set_progress(progress, 120)
    cache.record_heartbeat(WorkerHeartbeat("worker-001", clock()), 120)
    recovery = AbandonedJobRecovery(cache, durable, clock=clock, stale_after_seconds=30)

    result = recovery.recover(progress)

    assert result.heartbeat_state is HeartbeatState.ALIVE
    assert result.durable_transitioned is False
    assert durable.observations == []


def test_stale_worker_delegates_then_marks_transient_progress_abandoned() -> None:
    clock = _Clock()
    cache = InMemoryCache(clock=clock)
    durable = _DurableJobs()
    progress = _progress(clock)
    cache.set_progress(progress, 120)
    cache.record_heartbeat(WorkerHeartbeat("worker-001", clock()), 120)
    clock.advance(30)
    recovery = AbandonedJobRecovery(cache, durable, clock=clock, stale_after_seconds=30)

    result = recovery.recover(progress)

    assert result.heartbeat_state is HeartbeatState.STALE
    assert result.durable_transitioned is True
    assert durable.observations == [
        AbandonedJobObservation(
            job_id="job-001",
            tenant_id="tenant-demo",
            worker_ref="worker-001",
            observed_at=clock(),
            reason_code="worker_heartbeat_stale",
        )
    ]
    updated = cache.get_progress("tenant-demo", "job-001")
    assert updated is not None
    assert updated.status is ProgressStatus.ABANDONED
    assert updated.percent == 40


def test_missing_heartbeat_is_observable_but_durable_port_decides_transition() -> None:
    clock = _Clock()
    cache = InMemoryCache(clock=clock)
    durable = _DurableJobs(accept=False)
    progress = _progress(clock)
    cache.set_progress(progress, 120)
    recovery = AbandonedJobRecovery(cache, durable, clock=clock, stale_after_seconds=30)

    result = recovery.recover(progress)

    assert result.heartbeat_state is HeartbeatState.MISSING
    assert result.durable_transitioned is False
    assert durable.observations[0].reason_code == "worker_heartbeat_missing"
    assert cache.get_progress("tenant-demo", "job-001") == progress


def test_terminal_progress_is_never_recovered_from_redis_observation() -> None:
    clock = _Clock()
    cache = InMemoryCache(clock=clock)
    durable = _DurableJobs()
    progress = _progress(clock, ProgressStatus.SUCCEEDED)
    recovery = AbandonedJobRecovery(cache, durable, clock=clock, stale_after_seconds=30)

    result = recovery.recover(progress)

    assert result.durable_transitioned is False
    assert result.reason_code == "progress_not_running"
    assert durable.observations == []
