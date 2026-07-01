"""Cache adapters for transient recovery state.

Redis is the production adapter. The in-memory adapter keeps unit tests and fake
SAT workflows deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from typing import Any


@dataclass(frozen=True)
class _CacheItem:
    value: dict[str, object]
    expires_at: datetime | None


class InMemoryCache:
    """Simple JSON cache with optional TTL semantics."""

    def __init__(self) -> None:
        self._items: dict[str, _CacheItem] = {}

    def set_json(self, key: str, value: dict[str, object], ttl_seconds: int | None = None) -> None:
        expires_at = None
        if ttl_seconds is not None:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        self._items[key] = _CacheItem(value=dict(value), expires_at=expires_at)

    def get_json(self, key: str) -> dict[str, object] | None:
        item = self._items.get(key)
        if item is None:
            return None
        if item.expires_at is not None and item.expires_at < datetime.now(timezone.utc):
            self._items.pop(key, None)
            return None
        return dict(item.value)


class RedisCache:
    """Redis JSON-string adapter for progress, locks, rate limits, and tokens."""

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
