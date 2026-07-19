"""Durable ledger outbox publisher.

The publisher is intentionally small: PostgreSQL owns the claim and fencing
token, while the queue adapter owns publisher confirms.  Only opaque
references cross the broker boundary; payloads and fiscal contents never do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from cfdi_vault.accounting_ledger_outbox_v6 import OutboxClaim
from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_safety import validate_reason_code, validate_reference_string

_REFERENCE_LIMITS = {
    "event_id": 96,
    "job_id": 96,
    "tenant_id": 64,
    "event_type": 64,
    "routing_key": 128,
    "job_type": 64,
    "artifact_ref": 192,
    "idempotency_key": 192,
    "correlation_id": 96,
}


def _reference(name: str, value: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"outbox {name} must be a string")
    if not allow_empty and not value.strip():
        raise ValueError(f"outbox {name} cannot be empty")
    validate_reference_string(name, value)
    if len(value) > _REFERENCE_LIMITS[name]:
        raise ValueError(f"outbox {name} exceeds its maximum length")
    return value


def _reason(value: str) -> str:
    return validate_reason_code(value)


class OutboxPublisherStore(Protocol):
    """Minimal durable store port used by the publisher."""

    def claim_outbox_event(self, now: datetime, worker_ref: str, lease: timedelta) -> OutboxClaim | None: ...

    def mark_outbox_published(self, event_id: str, claim_id: str, *, now: datetime | None = None) -> bool: ...

    def mark_outbox_failed(
        self, event_id: str, claim_id: str, reason_code: str, *, now: datetime | None = None
    ) -> bool: ...

    def mark_outbox_uncertain(
        self, event_id: str, claim_id: str, reason_code: str, *, now: datetime | None = None
    ) -> bool: ...


class ReferenceQueuePublisher(Protocol):
    """Queue adapter port accepting reference-only envelopes."""

    def publish(self, message: QueueMessage) -> bool: ...


class OutboxPublishFailure(Exception):
    """A broker failure known not to have accepted the message."""

    def __init__(self, reason_code: str = "publish_failed") -> None:
        self.reason_code = _reason(reason_code)
        super().__init__(self.reason_code)

    def __repr__(self) -> str:
        return "OutboxPublishFailure(reason_code=<redacted>)"


class OutboxPublishAmbiguous(Exception):
    """A broker outcome that cannot safely be retried automatically."""

    def __init__(self, reason_code: str = "publish_uncertain") -> None:
        self.reason_code = _reason(reason_code)
        super().__init__(self.reason_code)

    def __repr__(self) -> str:
        return "OutboxPublishAmbiguous(reason_code=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class PublisherReport:
    """Sanitized result of one publisher pass."""

    status: str
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"idle", "published", "failed", "uncertain", "stale", "invalid"}:
            raise ValueError("unsupported outbox publisher status")
        if self.reason_code is not None:
            _reason(self.reason_code)

    def __repr__(self) -> str:
        return f"PublisherReport(status={self.status!r}, reason_code={self.reason_code!r})"

    def as_dict(self) -> dict[str, str | None]:
        return {"status": self.status, "reason_code": self.reason_code}


@dataclass(slots=True)
class LedgerOutboxPublisher:
    """Publish at most one durable outbox event per one-shot invocation.

    Dispatch metadata and artifact references remain in PostgreSQL.  Consumers
    will resolve them by ``job_id`` in the worker phase; the wire envelope is
    intentionally the existing v1 ``QueueMessage`` contract.
    """

    store: OutboxPublisherStore
    publisher: ReferenceQueuePublisher
    lease: timedelta = field(default_factory=lambda: timedelta(minutes=5))

    def __post_init__(self) -> None:
        if self.lease <= timedelta(0):
            raise ValueError("outbox publisher lease must be positive")

    def run_once(self, *, now: datetime, worker_ref: str) -> PublisherReport:
        """Claim, publish, and fence one event without local idempotency state."""

        now = self._stamp(now)
        claim = self.store.claim_outbox_event(now, worker_ref, self.lease)
        if claim is None:
            return PublisherReport("idle")

        try:
            envelope = self._envelope(claim, now)
        except (TypeError, ValueError):
            if not self.store.mark_outbox_failed(claim.event_id, claim.claim_id, "invalid_reference", now=now):
                return PublisherReport("stale", "stale_claim")
            return PublisherReport("invalid", "invalid_reference")

        try:
            confirmed = self.publisher.publish(envelope)
            if confirmed is not True:
                if not self.store.mark_outbox_uncertain(claim.event_id, claim.claim_id, "publish_uncertain", now=now):
                    return PublisherReport("stale", "stale_claim")
                return PublisherReport("uncertain", "publish_uncertain")
        except OutboxPublishFailure as exc:
            if not self.store.mark_outbox_failed(claim.event_id, claim.claim_id, exc.reason_code, now=now):
                return PublisherReport("stale", "stale_claim")
            return PublisherReport("failed", exc.reason_code)
        except (OutboxPublishAmbiguous, TimeoutError):
            if not self.store.mark_outbox_uncertain(claim.event_id, claim.claim_id, "publish_uncertain", now=now):
                return PublisherReport("stale", "stale_claim")
            return PublisherReport("uncertain", "publish_uncertain")
        except Exception:
            # Any transport exception can happen after the broker accepted the
            # message.  Never retry automatically or claim it was published.
            if not self.store.mark_outbox_uncertain(claim.event_id, claim.claim_id, "publish_uncertain", now=now):
                return PublisherReport("stale", "stale_claim")
            return PublisherReport("uncertain", "publish_uncertain")

        if not self.store.mark_outbox_published(claim.event_id, claim.claim_id, now=now):
            return PublisherReport("stale", "stale_claim")
        return PublisherReport("published")

    @staticmethod
    def _stamp(value: datetime) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("outbox publisher timestamp must be timezone-aware")
        return value

    @staticmethod
    def _envelope(claim: OutboxClaim, now: datetime) -> QueueMessage:
        if type(claim.schema_version) is not int or claim.schema_version != 1:
            raise ValueError("unsupported outbox schema_version")
        _reference("event_id", claim.event_id)
        _reference("job_id", claim.job_id)
        _reference("tenant_id", claim.tenant_id)
        _reference("event_type", claim.event_type)
        _reference("routing_key", claim.routing_key)
        _reference("job_type", claim.job_type)
        _reference("idempotency_key", claim.idempotency_key)
        if claim.event_type in {"metadata_parse", "xml_parse"} and claim.artifact_ref is None:
            raise ValueError("parse outbox artifact_ref is required")
        if claim.artifact_ref is not None:
            _reference("artifact_ref", claim.artifact_ref)
        if claim.event_type != claim.job_type or claim.routing_key != claim.queue_name:
            raise ValueError("outbox dispatch metadata mismatch")
        queue = QueueName(claim.routing_key)
        correlation_id = claim.job_id
        return QueueMessage(
            queue=queue,
            tenant_id=claim.tenant_id,
            job_id=claim.job_id,
            profile_id=None,
            correlation_id=correlation_id,
            attempt=0,
            created_at=now,
            message_id=claim.event_id,
            idempotency_key=claim.idempotency_key,
            envelope_version=1,
            not_before=None,
        )
