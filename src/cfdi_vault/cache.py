"""Cache adapters for transient recovery state.

Redis is the production adapter. The in-memory adapter keeps unit tests and fake
SAT workflows deterministic.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any

from cfdi_vault.cache_contract import CacheKeys, ProgressObservation, WorkerHeartbeat

@dataclass(frozen=True)
class _CacheItem:
    value: dict[str, object]
    expires_at: datetime | None


@dataclass(frozen=True)
class _LeaseItem:
    owner_id: str
    expires_at: datetime


class InMemoryCache:
    """Deterministic transient cache and lease adapter for tests."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._items: dict[str, _CacheItem] = {}
        self._leases: dict[str, _LeaseItem] = {}
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def set_json(self, key: str, value: dict[str, object], ttl_seconds: int | None = None) -> None:
        """Store a copied JSON object with an optional validated TTL."""

        expires_at = self._expiry(ttl_seconds) if ttl_seconds is not None else None
        self._items[key] = _CacheItem(value=dict(value), expires_at=expires_at)

    def get_json(self, key: str) -> dict[str, object] | None:
        """Return a copied JSON object while lazily removing expired values."""

        item = self._items.get(key)
        if item is None:
            return None
        if item.expires_at is not None and item.expires_at <= self.clock():
            self._items.pop(key, None)
            return None
        return dict(item.value)

    def acquire_lock(self, key: str, owner_id: str, ttl_seconds: int) -> bool:
        """Acquire a lease only when no unexpired owner currently holds it."""

        owner = _owner_id(owner_id)
        now = self.clock()
        current = self._leases.get(key)
        if current is not None and current.expires_at > now:
            return False
        self._leases[key] = _LeaseItem(owner, self._expiry(ttl_seconds, now=now))
        return True

    def renew_lock(self, key: str, owner_id: str, ttl_seconds: int) -> bool:
        """Renew a lease only when the unexpired owner token matches."""

        owner = _owner_id(owner_id)
        now = self.clock()
        current = self._leases.get(key)
        if current is None or current.expires_at <= now or current.owner_id != owner:
            if current is not None and current.expires_at <= now:
                self._leases.pop(key, None)
            return False
        self._leases[key] = _LeaseItem(owner, self._expiry(ttl_seconds, now=now))
        return True

    def release_lock(self, key: str, owner_id: str) -> bool:
        """Release a lease only when the unexpired owner token matches."""

        owner = _owner_id(owner_id)
        current = self._leases.get(key)
        if current is None:
            return False
        if current.expires_at <= self.clock():
            self._leases.pop(key, None)
            return False
        if current.owner_id != owner:
            return False
        self._leases.pop(key, None)
        return True

    def set_progress(self, observation: ProgressObservation, ttl_seconds: int) -> None:
        """Store one reference-only progress observation."""

        self.set_json(
            CacheKeys.progress(observation.tenant_id, observation.job_id),
            observation.as_dict(),
            ttl_seconds,
        )

    def get_progress(self, tenant_id: str, job_id: str) -> ProgressObservation | None:
        """Return one typed progress observation, or None after expiry."""

        value = self.get_json(CacheKeys.progress(tenant_id, job_id))
        return ProgressObservation.from_dict(value) if value is not None else None

    def record_heartbeat(self, heartbeat: WorkerHeartbeat, ttl_seconds: int) -> None:
        """Store one worker heartbeat with a finite TTL."""

        self.set_json(CacheKeys.heartbeat(heartbeat.worker_id), heartbeat.as_dict(), ttl_seconds)

    def get_heartbeat(self, worker_id: str) -> WorkerHeartbeat | None:
        """Return one typed heartbeat, or None after expiry."""

        value = self.get_json(CacheKeys.heartbeat(worker_id))
        return WorkerHeartbeat.from_dict(value) if value is not None else None

    def _expiry(self, ttl_seconds: int, *, now: datetime | None = None) -> datetime:
        _positive_ttl(ttl_seconds)
        return (now or self.clock()) + timedelta(seconds=ttl_seconds)


class RedisCache:
    """Redis adapter for transient JSON, owner leases, and observations."""

    def __init__(self, url: str, *, prefix: str = "cfdi-vault") -> None:
        redis = _load_redis()
        self.client = redis.from_url(url, decode_responses=True)
        self.prefix = prefix.rstrip(":")

    def set_json(self, key: str, value: dict[str, object], ttl_seconds: int | None = None) -> None:
        payload = json.dumps(value, sort_keys=True, default=str)
        redis_key = self._key(key)
        if ttl_seconds is None:
            self.client.set(redis_key, payload)
        else:
            self.client.setex(redis_key, ttl_seconds, payload)

    def get_json(self, key: str) -> dict[str, object] | None:
        payload = self.client.get(self._key(key))
        if payload is None:
            return None
        data: Any = json.loads(payload)
        if not isinstance(data, dict):
            return None
        return data

    def _key(self, key: str) -> str:
        return f"{self.prefix}:{key}"


def _load_redis():
    try:
        import redis  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("Redis support requires the infra extra: pip install -e .[infra]") from exc
    return redis


def _positive_ttl(ttl_seconds: int) -> int:
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds < 1:
        raise ValueError("ttl_seconds must be a positive integer")
    return ttl_seconds


def _owner_id(owner_id: str) -> str:
    if not isinstance(owner_id, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", owner_id) is None:
        raise ValueError("lock owner id must be a safe opaque owner value")
    return owner_id
