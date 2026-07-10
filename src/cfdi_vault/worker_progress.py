"""Read model that joins durable worker job state with transient cache observations.

PostgreSQL/durable state remains the source of truth. Redis/cache observations
only add short-lived progress and heartbeat visibility for CLI/API callers.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from cfdi_vault.cache_contract import (
    HeartbeatState,
    ProgressObservation,
    WorkerHeartbeat,
    classify_heartbeat,
)


class WorkerProgressCachePort(Protocol):
    """Transient cache operations used by the worker progress read model."""

    def get_progress(self, tenant_id: str, job_id: str) -> ProgressObservation | None:
        """Return transient progress, or None when absent/expired."""

    def get_heartbeat(self, worker_id: str) -> WorkerHeartbeat | None:
        """Return transient heartbeat, or None when absent/expired."""


@dataclass(frozen=True)
class DurableWorkerJobState:
    """Durable job state used as source of truth for progress reads."""

    job_id: str
    tenant_id: str
    status: str
    updated_at: datetime


class WorkerProgressReadModel:
    """Join durable job state with optional transient progress observations."""

    def __init__(
        self,
        cache: WorkerProgressCachePort,
        *,
        clock: Callable[[], datetime] | None = None,
        stale_after_seconds: int = 30,
    ) -> None:
        if isinstance(stale_after_seconds, bool) or not isinstance(stale_after_seconds, int) or stale_after_seconds < 1:
            raise ValueError("stale_after_seconds must be a positive integer")
        self.cache = cache
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.stale_after_seconds = stale_after_seconds

    def get(self, durable: DurableWorkerJobState) -> dict[str, object]:
        """Return a CLI/API-safe progress snapshot for one durable job.

        Cache failures are reported as transient unavailability instead of
        hiding or rewriting the durable job status.
        """

        snapshot: dict[str, object] = {
            "job_id": durable.job_id,
            "tenant_id": durable.tenant_id,
            "durable_status": durable.status,
            "durable_updated_at": _iso(durable.updated_at),
            "transient_available": True,
            "transient_progress": None,
            "worker_ref": None,
            "worker_heartbeat_state": None,
        }
        try:
            progress = self.cache.get_progress(durable.tenant_id, durable.job_id)
            if progress is None:
                snapshot["worker_heartbeat_state"] = HeartbeatState.MISSING.value
                return snapshot
            heartbeat = self.cache.get_heartbeat(progress.worker_ref)
            heartbeat_state = classify_heartbeat(
                heartbeat,
                now=self.clock(),
                stale_after_seconds=self.stale_after_seconds,
            )
        except Exception:
            snapshot["transient_available"] = False
            return snapshot

        snapshot["transient_progress"] = progress.as_dict()
        snapshot["worker_ref"] = progress.worker_ref
        snapshot["worker_heartbeat_state"] = heartbeat_state.value
        return snapshot


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc).isoformat()
    return value.astimezone(timezone.utc).isoformat()
