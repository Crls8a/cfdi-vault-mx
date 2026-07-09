from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

import cfdi_vault.cache as cache_module
from cfdi_vault.cache import RedisCache
from cfdi_vault.cache_contract import ProgressObservation, ProgressStatus, WorkerHeartbeat


class _RedisClient:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    def set(self, key: str, value: str, *, nx: bool = False, ex: int | None = None) -> bool:
        if nx and key in self.values:
            return False
        self.values[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    def setex(self, key: str, ttl: int, value: str) -> bool:
        self.values[key] = value
        self.ttls[key] = ttl
        return True

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def eval(self, script: str, _keys: int, key: str, owner: str, *args: object) -> int:
        if self.values.get(key) != owner:
            return 0
        if "del" in script:
            self.values.pop(key, None)
            self.ttls.pop(key, None)
            return 1
        self.ttls[key] = int(args[0])
        return 1


class _RedisModule:
    def __init__(self, client: _RedisClient) -> None:
        self.client = client

    def from_url(self, url: str, *, decode_responses: bool) -> _RedisClient:
        assert url == "redis://cache.invalid/0"
        assert decode_responses is True
        return self.client


def _cache(monkeypatch: pytest.MonkeyPatch) -> tuple[RedisCache, _RedisClient]:
    client = _RedisClient()
    monkeypatch.setattr(cache_module, "_load_redis", lambda: _RedisModule(client))
    return RedisCache("redis://cache.invalid/0", prefix="test-cache"), client


def test_redis_lock_uses_nx_ttl_and_owner_checked_scripts(monkeypatch: pytest.MonkeyPatch) -> None:
    cache, client = _cache(monkeypatch)
    key = "lock:criteria:tenant-demo:criteria-a1"

    assert cache.acquire_lock(key, "owner-a", 30) is True
    assert client.values["test-cache:lock:criteria:tenant-demo:criteria-a1"] == "owner-a"
    assert client.ttls["test-cache:lock:criteria:tenant-demo:criteria-a1"] == 30
    assert cache.acquire_lock(key, "owner-b", 30) is False
    assert cache.renew_lock(key, "owner-b", 60) is False
    assert cache.renew_lock(key, "owner-a", 60) is True
    assert client.ttls["test-cache:lock:criteria:tenant-demo:criteria-a1"] == 60
    assert cache.release_lock(key, "owner-b") is False
    assert cache.release_lock(key, "owner-a") is True


def test_redis_progress_and_heartbeat_round_trip_typed_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    cache, client = _cache(monkeypatch)
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    progress = ProgressObservation(
        job_id="job-001",
        tenant_id="tenant-demo",
        worker_ref="worker-001",
        status=ProgressStatus.RUNNING,
        percent=50,
        updated_at=now,
    )
    heartbeat = WorkerHeartbeat(worker_id="worker-001", updated_at=now)

    cache.set_progress(progress, 120)
    cache.record_heartbeat(heartbeat, 30)

    assert cache.get_progress("tenant-demo", "job-001") == progress
    assert cache.get_heartbeat("worker-001") == heartbeat
    stored = json.loads(client.values["test-cache:progress:tenant-demo:job-001"])
    assert set(stored) == {"job_id", "tenant_id", "worker_ref", "status", "percent", "updated_at"}
    assert client.ttls["test-cache:heartbeat:worker-001"] == 30


def test_redis_adapter_rejects_invalid_owner_and_ttl_before_io(monkeypatch: pytest.MonkeyPatch) -> None:
    cache, client = _cache(monkeypatch)

    with pytest.raises(ValueError, match="safe opaque owner"):
        cache.acquire_lock("lock:key", "", 30)
    with pytest.raises(ValueError, match="positive integer"):
        cache.acquire_lock("lock:key", "owner-a", True)  # type: ignore[arg-type]
    assert client.values == {}


def test_redis_get_json_treats_malformed_json_as_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    cache, client = _cache(monkeypatch)
    client.values["test-cache:broken"] = "{not-json"

    assert cache.get_json("broken") is None
