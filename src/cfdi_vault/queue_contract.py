"""Delivery contract shared by queue adapters and workers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol

from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_safety import validate_reason_code, validate_reference_string


class WorkerJobType(StrEnum):
    """Typed worker job families supported by the reference queue system."""

    SAT_REQUEST = "sat.request"
    SAT_VERIFY = "sat.verify"
    SAT_DOWNLOAD = "sat.download"
    CFDI_PARSE_METADATA = "cfdi.parse.metadata"
    CFDI_PARSE_XML = "cfdi.parse.xml"
    CFDI_RECONCILE = "cfdi.reconcile"
    CFDI_EXPORT = "cfdi.export"


_WORKER_JOB_QUEUE: dict[WorkerJobType, QueueName] = {
    WorkerJobType.SAT_REQUEST: QueueName.SAT_REQUEST,
    WorkerJobType.SAT_VERIFY: QueueName.SAT_VERIFY,
    WorkerJobType.SAT_DOWNLOAD: QueueName.SAT_DOWNLOAD,
    WorkerJobType.CFDI_PARSE_METADATA: QueueName.CFDI_PARSE_METADATA,
    WorkerJobType.CFDI_PARSE_XML: QueueName.CFDI_PARSE_XML,
    WorkerJobType.CFDI_RECONCILE: QueueName.CFDI_RECONCILE,
    WorkerJobType.CFDI_EXPORT: QueueName.CFDI_EXPORT,
}


@dataclass(frozen=True)
class WorkerJobEnvelope:
    """Typed worker contract that keeps queue payloads reference-only.

    The envelope mirrors the transport metadata workers need to hydrate durable
    state by reference. It intentionally has no arbitrary payload field and no
    XML, ZIP, SOAP, criteria, RFC, credential, or secret fields.
    """

    job_type: WorkerJobType
    queue: QueueName
    tenant_id: str
    job_id: str
    profile_id: str | None
    message_id: str
    correlation_id: str
    idempotency_key: str
    attempt: int
    envelope_version: int
    created_at: datetime
    not_before: datetime | None = None

    def __post_init__(self) -> None:
        expected_queue = _WORKER_JOB_QUEUE[self.job_type]
        if self.queue is not expected_queue:
            raise ValueError("worker job_type must match queue")
        if isinstance(self.envelope_version, bool) or self.envelope_version != 1:
            raise ValueError("unsupported worker envelope version")
        if isinstance(self.attempt, bool) or not isinstance(self.attempt, int) or self.attempt < 0:
            raise ValueError("worker attempt must be a non-negative integer")
        for name, value in (
            ("tenant_id", self.tenant_id),
            ("job_id", self.job_id),
            ("message_id", self.message_id),
            ("correlation_id", self.correlation_id),
            ("idempotency_key", self.idempotency_key),
        ):
            validate_reference_string(name, value)
        if self.profile_id is not None:
            validate_reference_string("profile_id", self.profile_id)
        if not isinstance(self.created_at, datetime) or (
            self.not_before is not None and not isinstance(self.not_before, datetime)
        ):
            raise TypeError("worker timestamps must be datetime values")

    @classmethod
    def from_message(cls, message: QueueMessage) -> "WorkerJobEnvelope":
        """Create a typed worker envelope from the safe transport envelope."""

        return cls(
            job_type=WorkerJobType(message.queue.value),
            queue=message.queue,
            tenant_id=message.tenant_id,
            job_id=message.job_id,
            profile_id=message.profile_id,
            message_id=message.message_id,
            correlation_id=message.correlation_id,
            idempotency_key=message.idempotency_key,
            attempt=message.attempt,
            envelope_version=message.envelope_version,
            created_at=message.created_at,
            not_before=message.not_before,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WorkerJobEnvelope":
        """Decode only the documented worker envelope fields."""

        allowed = {
            "job_type",
            "queue",
            "tenant_id",
            "job_id",
            "profile_id",
            "message_id",
            "correlation_id",
            "idempotency_key",
            "attempt",
            "envelope_version",
            "created_at",
            "not_before",
        }
        unknown = set(data) - allowed
        missing = allowed - set(data)
        if unknown:
            raise ValueError(f"unsupported worker envelope fields: {sorted(unknown)}")
        if missing:
            raise ValueError(f"missing worker envelope fields: {sorted(missing)}")
        for name in ("job_type", "queue", "tenant_id", "job_id", "message_id", "correlation_id", "idempotency_key", "created_at"):
            if not isinstance(data[name], str):
                raise TypeError(f"worker {name} must be a string")
        if data["profile_id"] is not None and not isinstance(data["profile_id"], str):
            raise TypeError("worker profile_id must be a string or null")
        for name in ("attempt", "envelope_version"):
            if isinstance(data[name], bool) or not isinstance(data[name], int):
                raise TypeError(f"worker {name} must be an integer")
        not_before = data["not_before"]
        if not_before is not None and not isinstance(not_before, str):
            raise TypeError("worker not_before must be an ISO datetime string or null")
        return cls(
            job_type=WorkerJobType(data["job_type"]),
            queue=QueueName(data["queue"]),
            tenant_id=data["tenant_id"],
            job_id=data["job_id"],
            profile_id=data["profile_id"],
            message_id=data["message_id"],
            correlation_id=data["correlation_id"],
            idempotency_key=data["idempotency_key"],
            attempt=data["attempt"],
            envelope_version=data["envelope_version"],
            created_at=datetime.fromisoformat(data["created_at"]),
            not_before=datetime.fromisoformat(not_before) if not_before is not None else None,
        )

    def as_dict(self) -> dict[str, str | int | None]:
        return {
            "job_type": self.job_type.value,
            "queue": self.queue.value,
            "tenant_id": self.tenant_id,
            "job_id": self.job_id,
            "profile_id": self.profile_id,
            "message_id": self.message_id,
            "correlation_id": self.correlation_id,
            "idempotency_key": self.idempotency_key,
            "attempt": self.attempt,
            "envelope_version": self.envelope_version,
            "created_at": self.created_at.isoformat(),
            "not_before": self.not_before.isoformat() if self.not_before else None,
        }

    def audit_event(
        self,
        action: "DeliveryAction",
        *,
        reason_code: str | None = None,
        occurred_at: datetime | None = None,
    ) -> "QueueAuditEvent":
        """Build a redacted queue audit event for this worker delivery."""

        return QueueAuditEvent(
            job_id=self.job_id,
            tenant_id=self.tenant_id,
            queue=self.queue.value,
            message_id=self.message_id,
            correlation_id=self.correlation_id,
            idempotency_key=self.idempotency_key,
            attempt=self.attempt,
            action=action,
            reason_code=reason_code,
            occurred_at=occurred_at or datetime.now(timezone.utc),
        )


class DeliveryAction(StrEnum):
    """Terminal transition selected for one broker delivery."""

    ACK = "ack"
    RETRY = "retry"
    DEAD_LETTER = "dead_letter"


class QueueHandlerError(RuntimeError):
    """Classified worker failure with a safe, non-sensitive reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = validate_reason_code(reason_code)
        super().__init__(reason_code)


class RetryableQueueError(QueueHandlerError):
    """Failure eligible for a bounded retry."""


class TerminalQueueError(QueueHandlerError):
    """Failure that must move directly to dead letter."""


class IdempotencyPort(Protocol):
    """Claim lifecycle; durable implementations belong to later work."""

    def acquire(self, key: str) -> bool:
        """Return True only when this process may start the work."""

    def complete(self, key: str) -> None:
        """Mark a successfully completed idempotency key."""

    def release(self, key: str) -> None:
        """Release a failed in-progress claim so delivery may retry."""


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded total-attempt policy with representable retry delays."""

    max_attempts: int = 3
    backoff_seconds: tuple[int, ...] = (5, 30)

    def __post_init__(self) -> None:
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int) or self.max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer")
        if not self.backoff_seconds or any(
            isinstance(delay, bool) or not isinstance(delay, int) or delay < 0
            for delay in self.backoff_seconds
        ):
            raise ValueError("backoff_seconds must contain non-negative integers")

    def delay_after_failure(self, attempt: int) -> int | None:
        """Return retry delay, or None when this delivery exhausts the policy."""

        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 0:
            raise ValueError("attempt must be a non-negative integer")
        if attempt + 1 >= self.max_attempts:
            return None
        return self.backoff_seconds[min(attempt, len(self.backoff_seconds) - 1)]


@dataclass(frozen=True)
class DeadLetterRecord:
    """Redacted DLQ metadata; it intentionally excludes the message payload."""

    original_queue: str
    job_id: str
    tenant_id: str
    message_id: str
    correlation_id: str
    idempotency_key: str
    attempt: int
    reason_code: str

    def __post_init__(self) -> None:
        validate_reason_code(self.reason_code)

    def as_dict(self) -> dict[str, str | int]:
        return {
            "original_queue": self.original_queue,
            "job_id": self.job_id,
            "tenant_id": self.tenant_id,
            "message_id": self.message_id,
            "correlation_id": self.correlation_id,
            "idempotency_key": self.idempotency_key,
            "attempt": self.attempt,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class DeliveryOutcome:
    """Observable result of one at-least-once delivery transition."""

    action: DeliveryAction
    message: QueueMessage | None
    result: object | None = None
    reason_code: str | None = None
    delay_seconds: int | None = None

    def __post_init__(self) -> None:
        if self.reason_code is not None:
            validate_reason_code(self.reason_code)


@dataclass(frozen=True)
class QueueAuditEvent:
    """Correlatable redacted queue transition shape for durable adapters."""

    job_id: str
    tenant_id: str
    queue: str
    message_id: str
    correlation_id: str
    idempotency_key: str
    attempt: int
    action: DeliveryAction
    reason_code: str | None
    occurred_at: datetime

    def __post_init__(self) -> None:
        if self.reason_code is not None:
            validate_reason_code(self.reason_code)

    @classmethod
    def from_delivery(
        cls,
        message: QueueMessage,
        action: DeliveryAction,
        *,
        reason_code: str | None = None,
        occurred_at: datetime | None = None,
    ) -> "QueueAuditEvent":
        return cls(
            job_id=message.job_id,
            tenant_id=message.tenant_id,
            queue=message.queue.value,
            message_id=message.message_id,
            correlation_id=message.correlation_id,
            idempotency_key=message.idempotency_key,
            attempt=message.attempt,
            action=action,
            reason_code=reason_code,
            occurred_at=occurred_at or datetime.now(timezone.utc),
        )

    def as_dict(self) -> dict[str, str | int | None]:
        return {
            "job_id": self.job_id,
            "tenant_id": self.tenant_id,
            "queue": self.queue,
            "message_id": self.message_id,
            "correlation_id": self.correlation_id,
            "idempotency_key": self.idempotency_key,
            "attempt": self.attempt,
            "action": self.action.value,
            "reason_code": self.reason_code,
            "occurred_at": self.occurred_at.isoformat(),
        }
