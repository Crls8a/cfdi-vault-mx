"""Delivery contract shared by queue adapters and workers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import re
from typing import Protocol

from cfdi_vault.domain import QueueMessage


_REASON_CODE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class DeliveryAction(StrEnum):
    """Terminal transition selected for one broker delivery."""

    ACK = "ack"
    RETRY = "retry"
    DEAD_LETTER = "dead_letter"


class QueueHandlerError(RuntimeError):
    """Classified worker failure with a safe, non-sensitive reason code."""

    def __init__(self, reason_code: str) -> None:
        if not _REASON_CODE.fullmatch(reason_code):
            raise ValueError("queue reason_code must be a safe machine identifier")
        self.reason_code = reason_code
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

    @classmethod
    def from_delivery(
        cls,
        message: QueueMessage,
        action: DeliveryAction,
        *,
        reason_code: str | None = None,
        occurred_at: datetime | None = None,
    ) -> "QueueAuditEvent":
        if reason_code is not None and not _REASON_CODE.fullmatch(reason_code):
            raise ValueError("queue reason_code must be a safe machine identifier")
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
