"""Reference-only contracts for transient progress, locks, and heartbeats.

These values describe Redis observations. They do not replace durable job,
queue-audit, or evidence state in PostgreSQL.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import re


_SAFE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PROGRESS_FIELDS = frozenset(
    {"job_id", "tenant_id", "worker_ref", "status", "percent", "updated_at"}
)
_HEARTBEAT_FIELDS = frozenset({"worker_id", "updated_at"})


class CacheKeys:
    """Build namespaced keys from opaque, non-sensitive references."""

    @staticmethod
    def progress(tenant_id: str, job_id: str) -> str:
        """Return the transient progress key for one durable job reference."""

        return f"progress:{_reference(tenant_id)}:{_reference(job_id)}"

    @staticmethod
    def criteria_lock(tenant_id: str, criteria_ref: str) -> str:
        """Return the lease key for one tenant-scoped criteria hash/reference."""

        return f"lock:criteria:{_reference(tenant_id)}:{_reference(criteria_ref)}"

    @staticmethod
    def heartbeat(worker_id: str) -> str:
        """Return the heartbeat key for one opaque worker identifier."""

        return f"heartbeat:{_reference(worker_id)}"


class ProgressStatus(StrEnum):
    """Allowed transient progress states for a durable recovery job."""

    PENDING = "pending"
    RUNNING = "running"
    RETRY_SCHEDULED = "retry_scheduled"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    MANUAL_REVIEW = "manual_review"
    ABANDONED = "abandoned"


@dataclass(frozen=True)
class ProgressObservation:
    """Reference-only, transient progress reported by one worker.

    The observation is safe to expire. Callers must read durable job state from
    PostgreSQL when Redis has no value.
    """

    job_id: str
    tenant_id: str
    worker_ref: str
    status: ProgressStatus
    percent: float
    updated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "job_id", _reference(self.job_id))
        object.__setattr__(self, "tenant_id", _reference(self.tenant_id))
        object.__setattr__(self, "worker_ref", _reference(self.worker_ref))
        if not isinstance(self.status, ProgressStatus):
            raise ValueError("status must be a ProgressStatus")
        if isinstance(self.percent, bool) or not isinstance(self.percent, (int, float)):
            raise ValueError("percent must be a number from 0 through 100")
        if not 0 <= float(self.percent) <= 100:
            raise ValueError("percent must be a number from 0 through 100")
        object.__setattr__(self, "percent", float(self.percent))
        object.__setattr__(self, "updated_at", _aware_utc(self.updated_at))

    def as_dict(self) -> dict[str, object]:
        """Return the exact JSON-safe cache payload without business data."""

        return {
            "job_id": self.job_id,
            "tenant_id": self.tenant_id,
            "worker_ref": self.worker_ref,
            "status": self.status.value,
            "percent": self.percent,
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "ProgressObservation":
        """Validate and decode one exact progress payload.

        Raises:
            ValueError: If fields are missing, unknown, malformed, or unsafe.
        """

        fields = frozenset(value)
        if fields != _PROGRESS_FIELDS:
            raise ValueError("unknown progress fields or required fields missing")
        try:
            updated_at = datetime.fromisoformat(str(value["updated_at"]))
            status = ProgressStatus(value["status"])
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid progress payload") from exc
        return cls(
            job_id=value["job_id"],  # type: ignore[arg-type]
            tenant_id=value["tenant_id"],  # type: ignore[arg-type]
            worker_ref=value["worker_ref"],  # type: ignore[arg-type]
            status=status,
            percent=value["percent"],  # type: ignore[arg-type]
            updated_at=updated_at,
        )


@dataclass(frozen=True)
class WorkerHeartbeat:
    """Last transient observation for one worker process."""

    worker_id: str
    updated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_id", _reference(self.worker_id))
        object.__setattr__(self, "updated_at", _aware_utc(self.updated_at))

    def as_dict(self) -> dict[str, object]:
        """Return the exact JSON-safe heartbeat payload."""

        return {"worker_id": self.worker_id, "updated_at": self.updated_at.isoformat()}

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "WorkerHeartbeat":
        """Validate and decode one exact heartbeat payload."""

        if frozenset(value) != _HEARTBEAT_FIELDS:
            raise ValueError("unknown heartbeat fields or required fields missing")
        try:
            return cls(
                worker_id=value["worker_id"],  # type: ignore[arg-type]
                updated_at=datetime.fromisoformat(str(value["updated_at"])),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid heartbeat payload") from exc


class HeartbeatState(StrEnum):
    """Observable classification for a worker heartbeat."""

    ALIVE = "alive"
    STALE = "stale"
    MISSING = "missing"


def classify_heartbeat(
    heartbeat: WorkerHeartbeat | None,
    *,
    now: datetime,
    stale_after_seconds: int,
) -> HeartbeatState:
    """Classify a heartbeat against an injected time boundary.

    Raises:
        ValueError: If the threshold is invalid or timestamps are inconsistent.
    """

    current = _aware_utc(now)
    if isinstance(stale_after_seconds, bool) or not isinstance(stale_after_seconds, int) or stale_after_seconds < 1:
        raise ValueError("stale_after_seconds must be a positive integer")
    if heartbeat is None:
        return HeartbeatState.MISSING
    if heartbeat.updated_at > current:
        raise ValueError("heartbeat timestamp cannot be in the future")
    age = (current - heartbeat.updated_at).total_seconds()
    return HeartbeatState.STALE if age >= stale_after_seconds else HeartbeatState.ALIVE


def _reference(value: str) -> str:
    if not isinstance(value, str) or _SAFE_REFERENCE.fullmatch(value) is None:
        raise ValueError("cache identifiers must be a safe opaque reference")
    return value


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("cache timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)
