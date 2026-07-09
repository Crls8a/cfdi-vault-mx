"""Coordinate stale-worker observations with durable recovery state.

Redis supplies only heartbeat/progress observations. A caller-provided durable
port decides whether PostgreSQL job state may transition.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Protocol

from cfdi_vault.cache_contract import (
    CacheKeys,
    HeartbeatState,
    ProgressObservation,
    ProgressStatus,
    WorkerHeartbeat,
    classify_heartbeat,
)


class CacheObservationPort(Protocol):
    """Transient cache behavior required by abandoned-job coordination."""

    def get_heartbeat(self, worker_id: str) -> WorkerHeartbeat | None:
        """Return the latest heartbeat, or None when absent/expired."""

    def set_progress(self, observation: ProgressObservation, ttl_seconds: int) -> None:
        """Store a transient progress observation."""


class DurableJobRecoveryPort(Protocol):
    """Durable boundary that conditionally transitions a PostgreSQL job."""

    def mark_job_abandoned(self, observation: "AbandonedJobObservation") -> bool:
        """Return True only when durable state accepted the transition."""


@dataclass(frozen=True)
class AbandonedJobObservation:
    """Safe evidence that a running job lost its worker heartbeat."""

    job_id: str
    tenant_id: str
    worker_ref: str
    observed_at: datetime
    reason_code: str

    def __post_init__(self) -> None:
        CacheKeys.progress(self.tenant_id, self.job_id)
        CacheKeys.heartbeat(self.worker_ref)
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("abandoned observation timestamp must be timezone-aware")
        object.__setattr__(self, "observed_at", self.observed_at.astimezone(timezone.utc))
        if self.reason_code not in {"worker_heartbeat_missing", "worker_heartbeat_stale"}:
            raise ValueError("unsupported abandoned observation reason_code")


@dataclass(frozen=True)
class AbandonedRecoveryResult:
    """Observable outcome of one conditional recovery decision."""

    heartbeat_state: HeartbeatState
    durable_transitioned: bool
    reason_code: str


class AbandonedJobRecovery:
    """Detect stale ownership and delegate the durable transition decision."""

    def __init__(
        self,
        cache: CacheObservationPort,
        durable_jobs: DurableJobRecoveryPort,
        *,
        clock: Callable[[], datetime],
        stale_after_seconds: int,
        progress_ttl_seconds: int = 3_600,
    ) -> None:
        _positive_seconds(stale_after_seconds, "stale_after_seconds")
        _positive_seconds(progress_ttl_seconds, "progress_ttl_seconds")
        self.cache = cache
        self.durable_jobs = durable_jobs
        self.clock = clock
        self.stale_after_seconds = stale_after_seconds
        self.progress_ttl_seconds = progress_ttl_seconds

    def recover(self, progress: ProgressObservation) -> AbandonedRecoveryResult:
        """Recover one running observation only after durable state agrees.

        Redis absence alone never mutates business state. The durable port must
        independently validate the referenced job and current status.
        """

        if progress.status is not ProgressStatus.RUNNING:
            return AbandonedRecoveryResult(
                HeartbeatState.MISSING,
                False,
                "progress_not_running",
            )
        now = self.clock()
        heartbeat = self.cache.get_heartbeat(progress.worker_ref)
        state = classify_heartbeat(
            heartbeat,
            now=now,
            stale_after_seconds=self.stale_after_seconds,
        )
        if state is HeartbeatState.ALIVE:
            return AbandonedRecoveryResult(state, False, "worker_heartbeat_alive")
        reason_code = (
            "worker_heartbeat_stale"
            if state is HeartbeatState.STALE
            else "worker_heartbeat_missing"
        )
        observation = AbandonedJobObservation(
            job_id=progress.job_id,
            tenant_id=progress.tenant_id,
            worker_ref=progress.worker_ref,
            observed_at=now,
            reason_code=reason_code,
        )
        transitioned = self.durable_jobs.mark_job_abandoned(observation)
        if transitioned:
            self.cache.set_progress(
                replace(
                    progress,
                    status=ProgressStatus.ABANDONED,
                    updated_at=now,
                ),
                self.progress_ttl_seconds,
            )
        return AbandonedRecoveryResult(state, transitioned, reason_code)


def _positive_seconds(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value
