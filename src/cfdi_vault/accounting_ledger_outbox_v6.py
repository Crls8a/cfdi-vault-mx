"""Focused V6 outbox/inbox repository mixin.

The mixin is deliberately separate from job claiming so broker handoff can be
tested and operated independently. It stores only opaque references and fixed
reason codes; RabbitMQ integration belongs to a later phase.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import Column, DateTime, Integer, MetaData, SmallInteger, String, Table, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from cfdi_vault.queue_safety import validate_reason_code, validate_reference_string

_METADATA = MetaData()
_REASON = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_OUTBOX = Table(
    "ledger_outbox",
    _METADATA,
    Column("event_id", String(96)),
    Column("job_id", String(96)),
    Column("event_type", String(64)),
    Column("routing_key", String(128)),
    Column("schema_version", SmallInteger),
    Column("idempotency_key", String(192)),
    Column("status", String(16)),
    Column("available_at", DateTime(timezone=True)),
    Column("publish_attempts", Integer),
    Column("lease_until", DateTime(timezone=True)),
    Column("published_at", DateTime(timezone=True)),
    Column("last_error_code", String(64)),
    Column("created_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
    Column("claim_id", String(96)),
    Column("claimed_by", String(128)),
)
_INBOX = Table(
    "ledger_inbox",
    _METADATA,
    Column("event_id", String(96)),
    Column("consumer_name", String(128)),
    Column("received_at", DateTime(timezone=True)),
    Column("processed_at", DateTime(timezone=True)),
    Column("result_code", String(64)),
)


def _stamp(value: datetime | None = None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None:
        raise ValueError("ledger timestamp must be timezone-aware")
    return result


def _ref(name: str, value: str, limit: int) -> str:
    validate_reference_string(name, value)
    if len(value) > limit:
        raise ValueError(f"ledger {name} exceeds its maximum length")
    return value


def _reason(value: str) -> str:
    value = validate_reason_code(value)
    if _REASON.fullmatch(value) is None:
        raise ValueError("ledger reason_code must begin with a lowercase letter")
    return value


def _opaque(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


@dataclass(frozen=True, slots=True, repr=False)
class OutboxClaim:
    """Opaque outbox lease returned before broker I/O."""

    event_id: str
    job_id: str
    claim_id: str

    def __repr__(self) -> str:
        return "OutboxClaim(references_redacted=True)"


class LedgerOutboxStoreMixin:
    """Concrete outbox and inbox operations for an object with ``_engine``."""

    def create_outbox_event(
        self,
        *,
        event_id: str,
        job_id: str,
        event_type: str,
        routing_key: str,
        idempotency_key: str,
        schema_version: int = 1,
        available_at: datetime | None = None,
    ) -> bool:
        """Insert one broker handoff, returning false for an idempotent duplicate."""
        values = {
            "event_id": _ref("event_id", event_id, 96),
            "job_id": _ref("job_id", job_id, 96),
            "event_type": _ref("event_type", event_type, 64),
            "routing_key": _ref("routing_key", routing_key, 128),
            "idempotency_key": _ref("idempotency_key", idempotency_key, 192),
            "schema_version": schema_version,
            "available_at": _stamp(available_at),
        }
        if type(schema_version) is not int or schema_version <= 0:
            raise ValueError("ledger schema_version must be positive")
        with self._engine.begin() as connection:
            result = connection.execute(
                pg_insert(_OUTBOX).values(values).on_conflict_do_nothing().returning(_OUTBOX.c.event_id)
            )
            return result.scalar_one_or_none() is not None

    def claim_outbox_event(self, now: datetime, worker_ref: str, lease: timedelta) -> OutboxClaim | None:
        """Claim one due event before publishing it to a broker."""
        now = _stamp(now)
        _ref("worker_ref", worker_ref, 128)
        if lease <= timedelta(0):
            raise ValueError("ledger lease must be positive")
        with self._engine.begin() as connection:
            connection.execute(
                update(_OUTBOX)
                .where(_OUTBOX.c.status == "claimed", _OUTBOX.c.lease_until <= now)
                .values(status="queued", lease_until=None, claim_id=None, claimed_by=None, updated_at=now)
            )
            row = connection.execute(
                select(_OUTBOX)
                .where(_OUTBOX.c.status.in_(("queued", "failed")), _OUTBOX.c.available_at <= now)
                .order_by(_OUTBOX.c.available_at, _OUTBOX.c.event_id)
                .limit(1)
                .with_for_update(skip_locked=True)
            ).first()
            if row is None:
                return None
            claim_id = _opaque("outbox-claim")
            connection.execute(
                update(_OUTBOX)
                .where(_OUTBOX.c.event_id == row.event_id)
                .values(
                    status="claimed",
                    lease_until=now + lease,
                    publish_attempts=row.publish_attempts + 1,
                    claim_id=claim_id,
                    claimed_by=worker_ref,
                    updated_at=now,
                )
            )
            return OutboxClaim(row.event_id, row.job_id, claim_id)

    def mark_outbox_published(self, event_id: str, claim_id: str, *, now: datetime | None = None) -> bool:
        """Close a claimed event after broker confirmation."""
        stamp = _stamp(now)
        event_id = _ref("event_id", event_id, 96)
        claim_id = _ref("claim_id", claim_id, 96)
        with self._engine.begin() as connection:
            return (
                connection.execute(
                    update(_OUTBOX)
                    .where(
                        _OUTBOX.c.event_id == event_id,
                        _OUTBOX.c.claim_id == claim_id,
                        _OUTBOX.c.status == "claimed",
                    )
                    .values(
                        status="published",
                        published_at=stamp,
                        lease_until=None,
                        claim_id=None,
                        claimed_by=None,
                        updated_at=stamp,
                    )
                ).rowcount
                == 1
            )

    def mark_outbox_failed(
        self, event_id: str, claim_id: str, reason_code: str, *, now: datetime | None = None
    ) -> bool:
        """Record a retryable, categorized publish failure."""
        stamp = _stamp(now)
        event_id = _ref("event_id", event_id, 96)
        claim_id = _ref("claim_id", claim_id, 96)
        reason_code = _reason(reason_code)
        with self._engine.begin() as connection:
            return (
                connection.execute(
                    update(_OUTBOX)
                    .where(
                        _OUTBOX.c.event_id == event_id,
                        _OUTBOX.c.claim_id == claim_id,
                        _OUTBOX.c.status == "claimed",
                    )
                    .values(
                        status="failed",
                        last_error_code=reason_code,
                        lease_until=None,
                        claim_id=None,
                        claimed_by=None,
                        available_at=stamp,
                        updated_at=stamp,
                    )
                ).rowcount
                == 1
            )

    def register_inbox_event(self, event_id: str, consumer_name: str, *, received_at: datetime | None = None) -> bool:
        """Register a broker delivery once for a consumer."""
        values = {
            "event_id": _ref("event_id", event_id, 96),
            "consumer_name": _ref("consumer_name", consumer_name, 128),
            "received_at": _stamp(received_at),
        }
        with self._engine.begin() as connection:
            result = connection.execute(
                pg_insert(_INBOX).values(values).on_conflict_do_nothing().returning(_INBOX.c.event_id)
            )
            return result.scalar_one_or_none() is not None

    def mark_inbox_processed(
        self, event_id: str, consumer_name: str, result_code: str, *, now: datetime | None = None
    ) -> bool:
        """Close an unprocessed inbox row exactly once."""
        stamp = _stamp(now)
        event_id = _ref("event_id", event_id, 96)
        consumer_name = _ref("consumer_name", consumer_name, 128)
        result_code = _reason(result_code)
        with self._engine.begin() as connection:
            return (
                connection.execute(
                    update(_INBOX)
                    .where(
                        _INBOX.c.event_id == event_id,
                        _INBOX.c.consumer_name == consumer_name,
                        _INBOX.c.processed_at.is_(None),
                    )
                    .values(processed_at=stamp, result_code=result_code)
                ).rowcount
                == 1
            )
