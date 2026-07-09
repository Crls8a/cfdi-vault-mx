from __future__ import annotations

from datetime import datetime, timezone
import os
import time
from uuid import uuid4

import pytest

from cfdi_vault.cache import RedisCache
from cfdi_vault.cache_contract import CacheKeys, ProgressObservation, ProgressStatus, WorkerHeartbeat


REDIS_URL = os.getenv("CFDI_VAULT_TEST_REDIS_URL")
pytestmark = pytest.mark.skipif(
    not REDIS_URL,
    reason="CFDI_VAULT_TEST_REDIS_URL is required for Redis integration tests.",
)


def test_real_redis_owner_leases_progress_heartbeat_and_expiry() -> None:
    prefix = f"cfdi-vault-test:{uuid4().hex}"
    cache = RedisCache(str(REDIS_URL), prefix=prefix)
    now = datetime.now(timezone.utc)
    lock_key = CacheKeys.criteria_lock("tenant-demo", "criteria-a1")
    progress = ProgressObservation(
        job_id="job-001",
        tenant_id="tenant-demo",
        worker_ref="worker-001",
        status=ProgressStatus.RUNNING,
        percent=50,
        updated_at=now,
    )
    heartbeat = WorkerHeartbeat(worker_id="worker-001", updated_at=now)
    redis_keys = (
        cache._key(lock_key),
        cache._key(CacheKeys.progress(progress.tenant_id, progress.job_id)),
        cache._key(CacheKeys.heartbeat(heartbeat.worker_id)),
    )

    try:
        assert cache.acquire_lock(lock_key, "owner-a", 5) is True
        assert cache.acquire_lock(lock_key, "owner-b", 5) is False
        assert cache.renew_lock(lock_key, "owner-b", 10) is False
        assert cache.renew_lock(lock_key, "owner-a", 10) is True
        assert cache.release_lock(lock_key, "owner-b") is False
        assert cache.release_lock(lock_key, "owner-a") is True

        cache.set_progress(progress, 5)
        cache.record_heartbeat(heartbeat, 1)
        assert cache.get_progress("tenant-demo", "job-001") == progress
        assert cache.get_heartbeat("worker-001") == heartbeat

        deadline = time.monotonic() + 3
        while cache.get_heartbeat("worker-001") is not None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert cache.get_heartbeat("worker-001") is None
    finally:
        cache.client.delete(*redis_keys)
