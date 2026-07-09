from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cfdi_vault.cache_contract import (
    CacheKeys,
    HeartbeatState,
    ProgressObservation,
    ProgressStatus,
    WorkerHeartbeat,
    classify_heartbeat,
)


NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def test_cache_keys_are_tenant_scoped_and_reference_only() -> None:
    assert CacheKeys.progress("tenant-demo", "job-001") == "progress:tenant-demo:job-001"
    assert CacheKeys.criteria_lock("tenant-demo", "criteria-a1") == "lock:criteria:tenant-demo:criteria-a1"
    assert CacheKeys.heartbeat("worker-001") == "heartbeat:worker-001"


@pytest.mark.parametrize("unsafe", ["", " has-space", "../escape", "a/b", "key=value"])
def test_cache_keys_reject_unsafe_references(unsafe: str) -> None:
    with pytest.raises(ValueError, match="safe opaque reference"):
        CacheKeys.progress("tenant-demo", unsafe)


def test_progress_observation_round_trips_exact_safe_fields() -> None:
    observation = ProgressObservation(
        job_id="job-001",
        tenant_id="tenant-demo",
        worker_ref="worker-001",
        status=ProgressStatus.RUNNING,
        percent=37.5,
        updated_at=NOW,
    )

    payload = observation.as_dict()

    assert payload == {
        "job_id": "job-001",
        "tenant_id": "tenant-demo",
        "worker_ref": "worker-001",
        "status": "running",
        "percent": 37.5,
        "updated_at": "2026-01-01T12:00:00+00:00",
    }
    assert ProgressObservation.from_dict(payload) == observation


@pytest.mark.parametrize("percent", [-0.1, 100.1, True, "50"])
def test_progress_observation_rejects_invalid_percent(percent: object) -> None:
    with pytest.raises(ValueError, match="percent"):
        ProgressObservation(
            job_id="job-001",
            tenant_id="tenant-demo",
            worker_ref="worker-001",
            status=ProgressStatus.RUNNING,
            percent=percent,  # type: ignore[arg-type]
            updated_at=NOW,
        )


def test_progress_observation_rejects_naive_time_and_unknown_payload_fields() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        ProgressObservation(
            job_id="job-001",
            tenant_id="tenant-demo",
            worker_ref="worker-001",
            status=ProgressStatus.RUNNING,
            percent=10,
            updated_at=datetime(2026, 1, 1, 12, 0),
        )

    payload = {
        "job_id": "job-001",
        "tenant_id": "tenant-demo",
        "worker_ref": "worker-001",
        "status": "running",
        "percent": 10,
        "updated_at": NOW.isoformat(),
        "raw_payload": "forbidden",
    }
    with pytest.raises(ValueError, match="unknown progress fields"):
        ProgressObservation.from_dict(payload)


def test_heartbeat_stale_boundary_is_deterministic() -> None:
    heartbeat = WorkerHeartbeat(worker_id="worker-001", updated_at=NOW)

    assert classify_heartbeat(heartbeat, now=NOW + timedelta(seconds=29), stale_after_seconds=30) is HeartbeatState.ALIVE
    assert classify_heartbeat(heartbeat, now=NOW + timedelta(seconds=30), stale_after_seconds=30) is HeartbeatState.STALE
    assert classify_heartbeat(None, now=NOW, stale_after_seconds=30) is HeartbeatState.MISSING


def test_heartbeat_rejects_invalid_ttl_and_future_timestamp() -> None:
    heartbeat = WorkerHeartbeat(worker_id="worker-001", updated_at=NOW + timedelta(seconds=1))

    with pytest.raises(ValueError, match="positive integer"):
        classify_heartbeat(heartbeat, now=NOW, stale_after_seconds=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="future"):
        classify_heartbeat(heartbeat, now=NOW, stale_after_seconds=30)
