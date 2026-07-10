from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cfdi_vault.cache import InMemoryCache
from cfdi_vault.cache_contract import ProgressObservation, ProgressStatus, WorkerHeartbeat
from cfdi_vault.worker_progress import DurableWorkerJobState, WorkerProgressReadModel


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _durable(status: str = "running") -> DurableWorkerJobState:
    return DurableWorkerJobState(
        job_id="job-001",
        tenant_id="tenant-demo",
        status=status,
        updated_at=NOW,
    )


def _progress(updated_at: datetime = NOW) -> ProgressObservation:
    return ProgressObservation(
        job_id="job-001",
        tenant_id="tenant-demo",
        worker_ref="worker-001",
        status=ProgressStatus.RUNNING,
        percent=35,
        updated_at=updated_at,
    )


def test_progress_read_model_returns_durable_status_without_cache_progress() -> None:
    cache = InMemoryCache(clock=lambda: NOW)
    reader = WorkerProgressReadModel(cache, clock=lambda: NOW)

    snapshot = reader.get(_durable("pending"))

    assert snapshot == {
        "job_id": "job-001",
        "tenant_id": "tenant-demo",
        "durable_status": "pending",
        "durable_updated_at": "2026-01-01T12:00:00+00:00",
        "transient_available": True,
        "transient_progress": None,
        "worker_ref": None,
        "worker_heartbeat_state": "missing",
    }


def test_progress_read_model_shows_alive_worker_from_transient_heartbeat() -> None:
    cache = InMemoryCache(clock=lambda: NOW)
    cache.set_progress(_progress(), 120)
    cache.record_heartbeat(WorkerHeartbeat("worker-001", NOW), 120)
    reader = WorkerProgressReadModel(cache, clock=lambda: NOW + timedelta(seconds=29), stale_after_seconds=30)

    snapshot = reader.get(_durable())

    assert snapshot["durable_status"] == "running"
    assert snapshot["worker_ref"] == "worker-001"
    assert snapshot["worker_heartbeat_state"] == "alive"
    assert snapshot["transient_progress"] == _progress().as_dict()


def test_progress_read_model_shows_stale_worker_without_changing_durable_status() -> None:
    cache = InMemoryCache(clock=lambda: NOW)
    cache.set_progress(_progress(), 120)
    cache.record_heartbeat(WorkerHeartbeat("worker-001", NOW), 120)
    reader = WorkerProgressReadModel(cache, clock=lambda: NOW + timedelta(seconds=30), stale_after_seconds=30)

    snapshot = reader.get(_durable("running"))

    assert snapshot["durable_status"] == "running"
    assert snapshot["worker_heartbeat_state"] == "stale"
    assert cache.get_progress("tenant-demo", "job-001") == _progress()


def test_progress_read_model_keeps_terminal_durable_status_over_stale_cache() -> None:
    cache = InMemoryCache(clock=lambda: NOW)
    cache.set_progress(_progress(updated_at=NOW - timedelta(minutes=5)), 120)
    cache.record_heartbeat(WorkerHeartbeat("worker-001", NOW - timedelta(minutes=5)), 120)
    reader = WorkerProgressReadModel(cache, clock=lambda: NOW, stale_after_seconds=30)

    snapshot = reader.get(_durable("succeeded"))

    assert snapshot["durable_status"] == "succeeded"
    assert snapshot["transient_progress"] == _progress(updated_at=NOW - timedelta(minutes=5)).as_dict()
    assert snapshot["worker_heartbeat_state"] == "stale"


def test_progress_read_model_keeps_durable_status_when_transient_cache_is_unavailable() -> None:
    class BrokenCache:
        def get_progress(self, tenant_id: str, job_id: str) -> ProgressObservation | None:
            raise RuntimeError("redis unavailable")

        def get_heartbeat(self, worker_id: str) -> WorkerHeartbeat | None:
            raise RuntimeError("redis unavailable")

    reader = WorkerProgressReadModel(BrokenCache(), clock=lambda: NOW)  # type: ignore[arg-type]

    snapshot = reader.get(_durable("retry_scheduled"))

    assert snapshot["durable_status"] == "retry_scheduled"
    assert snapshot["transient_available"] is False
    assert snapshot["transient_progress"] is None
    assert snapshot["worker_heartbeat_state"] is None
