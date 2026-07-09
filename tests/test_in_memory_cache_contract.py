from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cfdi_vault.cache import InMemoryCache
from cfdi_vault.cache_contract import ProgressObservation, ProgressStatus, WorkerHeartbeat


class _Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


def _progress(clock: _Clock) -> ProgressObservation:
    return ProgressObservation(
        job_id="job-001",
        tenant_id="tenant-demo",
        worker_ref="worker-001",
        status=ProgressStatus.RUNNING,
        percent=25,
        updated_at=clock(),
    )


def test_json_ttl_expires_at_the_exact_boundary() -> None:
    clock = _Clock()
    cache = InMemoryCache(clock=clock)
    cache.set_json("observation", {"status": "safe"}, ttl_seconds=10)

    clock.advance(9)
    assert cache.get_json("observation") == {"status": "safe"}
    clock.advance(1)
    assert cache.get_json("observation") is None


@pytest.mark.parametrize("ttl", [0, -1, True, 1.5])
def test_ttl_must_be_a_positive_integer(ttl: object) -> None:
    cache = InMemoryCache()

    with pytest.raises(ValueError, match="positive integer"):
        cache.set_json("observation", {}, ttl_seconds=ttl)  # type: ignore[arg-type]


def test_lock_acquire_contention_release_and_owner_checks_are_atomic() -> None:
    clock = _Clock()
    cache = InMemoryCache(clock=clock)

    assert cache.acquire_lock("lock:criteria:tenant-demo:criteria-a1", "owner-a", 30) is True
    assert cache.acquire_lock("lock:criteria:tenant-demo:criteria-a1", "owner-b", 30) is False
    assert cache.renew_lock("lock:criteria:tenant-demo:criteria-a1", "owner-b", 60) is False
    assert cache.release_lock("lock:criteria:tenant-demo:criteria-a1", "owner-b") is False
    assert cache.release_lock("lock:criteria:tenant-demo:criteria-a1", "owner-a") is True
    assert cache.acquire_lock("lock:criteria:tenant-demo:criteria-a1", "owner-b", 30) is True


def test_lock_renewal_extends_only_the_current_owner_lease() -> None:
    clock = _Clock()
    cache = InMemoryCache(clock=clock)
    key = "lock:criteria:tenant-demo:criteria-a1"
    assert cache.acquire_lock(key, "owner-a", 10) is True

    clock.advance(9)
    assert cache.renew_lock(key, "owner-a", 10) is True
    clock.advance(2)
    assert cache.acquire_lock(key, "owner-b", 10) is False
    clock.advance(8)
    assert cache.acquire_lock(key, "owner-b", 10) is True
    assert cache.release_lock(key, "owner-a") is False


def test_progress_and_heartbeat_use_typed_reference_only_payloads() -> None:
    clock = _Clock()
    cache = InMemoryCache(clock=clock)
    progress = _progress(clock)
    heartbeat = WorkerHeartbeat(worker_id="worker-001", updated_at=clock())

    cache.set_progress(progress, ttl_seconds=20)
    cache.record_heartbeat(heartbeat, ttl_seconds=10)

    assert cache.get_progress("tenant-demo", "job-001") == progress
    assert cache.get_heartbeat("worker-001") == heartbeat
    clock.advance(10)
    assert cache.get_heartbeat("worker-001") is None
    assert cache.get_progress("tenant-demo", "job-001") == progress
    clock.advance(10)
    assert cache.get_progress("tenant-demo", "job-001") is None


@pytest.mark.parametrize("owner_id", ["", " ", "owner/id", "owner\nline", "a" * 129])
def test_lock_owner_id_must_be_a_bounded_safe_opaque_value(owner_id: str) -> None:
    cache = InMemoryCache()

    with pytest.raises(ValueError, match="safe opaque owner"):
        cache.acquire_lock("lock:criteria:tenant-demo:criteria-a1", owner_id, 30)
    assert not hasattr(cache, "get_lock_owner")
