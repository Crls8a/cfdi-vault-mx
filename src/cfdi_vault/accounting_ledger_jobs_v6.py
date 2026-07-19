"""Internal PostgreSQL repository for durable V6 jobs and claims."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Engine

from cfdi_vault.accounting_ledger_outbox_v6 import LedgerOutboxStoreMixin
from cfdi_vault.accounting_ledger_worker import (
    LedgerClaim,
    LedgerJobStore,
    LedgerParseAggregate,
    LedgerParseJob,
)
from cfdi_vault.queue_safety import validate_reason_code, validate_reference_string

_METADATA = MetaData()
_REASON = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
_COUNTS = frozenset(
    {
        "records",
        "eligible",
        "cancelled",
        "duplicate",
        "conflict",
        "unknown",
        "concepts",
        "taxes",
        "payments",
        "payroll",
        "related",
    }
)
_TERMINAL = ("succeeded", "duplicate", "failed", "uncertain", "dead_letter")
_PARSE_JOB_TYPES = {"cfdi.parse.metadata": "metadata_parse", "cfdi.parse.xml": "xml_parse"}
_JOBS = Table(
    "ledger_jobs",
    _METADATA,
    Column("job_id", String(96)),
    Column("tenant_id", String(64)),
    Column("job_type", String(64)),
    Column("queue_name", String(128)),
    Column("artifact_ref", String(192)),
    Column("idempotency_key", String(192)),
    Column("status", String(24)),
    Column("available_at", DateTime(timezone=True)),
    Column("attempt_count", Integer),
    Column("max_attempts", Integer),
    Column("last_error_code", String(64)),
    Column("aggregate_counts", JSONB),
    Column("created_at", DateTime(timezone=True)),
    Column("updated_at", DateTime(timezone=True)),
    Column("completed_at", DateTime(timezone=True)),
)
_CLAIMS = Table(
    "ledger_job_claims",
    _METADATA,
    Column("claim_id", String(96)),
    Column("job_id", String(96)),
    Column("worker_ref", String(128)),
    Column("attempt", Integer),
    Column("lease_until", DateTime(timezone=True)),
    Column("claimed_at", DateTime(timezone=True)),
    Column("completed_at", DateTime(timezone=True)),
    Column("result_code", String(64)),
)


def _now(value: datetime | None = None) -> datetime:
    stamp = value or datetime.now(timezone.utc)
    if stamp.tzinfo is None:
        raise ValueError("ledger timestamp must be timezone-aware")
    return stamp


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


def _counts(value: Mapping[str, Any] | None) -> dict[str, int]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError("ledger aggregate counts must be a mapping")
    if any(key not in _COUNTS for key in value):
        raise ValueError("ledger aggregate contains an unsupported counter")
    result: dict[str, int] = {}
    for key, count in value.items():
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("ledger aggregate counters must be non-negative integers")
        result[key] = count
    return result


def _aggregate(value: LedgerParseAggregate | Mapping[str, Any]) -> dict[str, int]:
    if isinstance(value, LedgerParseAggregate):
        raw = value.as_dict()
        result: dict[str, int] = {}
        aliases = {
            "records_seen": "records",
            "records_written": "eligible",
            "duplicates": "duplicate",
            "conflicts": "conflict",
            "unknown": "unknown",
            "invalid": "unknown",
            "concepts": "concepts",
            "taxes": "taxes",
            "payments": "payments",
            "payroll": "payroll",
            "related": "related",
        }
        for key, count in raw.items():
            target = aliases[key]
            result[target] = result.get(target, 0) + count
        return _counts(result)
    return _counts(value)


def _opaque(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


@dataclass(frozen=True, slots=True, repr=False)
class JobClaim:
    claim_id: str
    job_id: str
    attempt: int

    def __repr__(self) -> str:
        return f"JobClaim(attempt={self.attempt})"


@dataclass(frozen=True, slots=True, repr=False)
class JobStatus:
    status: str
    attempt_count: int
    max_attempts: int
    aggregate_counts: Mapping[str, int]
    last_error_code: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "attempt_count": self.attempt_count,
            "max_attempts": self.max_attempts,
            "aggregate_counts": dict(self.aggregate_counts),
            "last_error_code": self.last_error_code,
        }

    def __repr__(self) -> str:
        return f"JobStatus({self.as_dict()!r})"


class LedgerJobStoreV6(LedgerOutboxStoreMixin, LedgerJobStore):
    """PostgreSQL-backed implementation of the durable ledger job port."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def create_job(
        self,
        *,
        job_id: str,
        tenant_id: str,
        job_type: str,
        queue_name: str,
        artifact_ref: str | None,
        idempotency_key: str,
        available_at: datetime | None = None,
        max_attempts: int = 3,
        aggregate_counts: Mapping[str, Any] | None = None,
    ) -> bool:
        values = {
            "job_id": _ref("job_id", job_id, 96),
            "tenant_id": _ref("tenant_id", tenant_id, 64),
            "job_type": _ref("job_type", job_type, 64),
            "queue_name": _ref("queue_name", queue_name, 128),
            "artifact_ref": _ref("artifact_ref", artifact_ref, 192) if artifact_ref is not None else None,
            "idempotency_key": _ref("idempotency_key", idempotency_key, 192),
            "available_at": _now(available_at),
            "max_attempts": max_attempts,
            "aggregate_counts": _counts(aggregate_counts),
        }
        if type(max_attempts) is not int or max_attempts <= 0:
            raise ValueError("ledger max_attempts must be positive")
        with self._engine.begin() as connection:
            result = connection.execute(
                pg_insert(_JOBS).values(values).on_conflict_do_nothing().returning(_JOBS.c.job_id)
            )
            return result.scalar_one_or_none() is not None

    def _expire_claims(self, connection: Any, now: datetime) -> None:
        rows = connection.execute(
            select(_CLAIMS.c.claim_id, _CLAIMS.c.job_id)
            .join(_JOBS, _JOBS.c.job_id == _CLAIMS.c.job_id)
            .where(
                _CLAIMS.c.completed_at.is_(None),
                _CLAIMS.c.lease_until <= now,
                _JOBS.c.status.in_(("claimed", "running")),
            )
            .with_for_update(skip_locked=True)
        ).all()
        for row in rows:
            connection.execute(
                update(_CLAIMS)
                .where(_CLAIMS.c.claim_id == row.claim_id, _CLAIMS.c.completed_at.is_(None))
                .values(completed_at=now, result_code="lease_expired")
            )
            connection.execute(
                update(_JOBS)
                .where(_JOBS.c.job_id == row.job_id, _JOBS.c.status.in_(("claimed", "running")))
                .values(status="queued", updated_at=now)
            )

    def _claim_row(self, connection: Any, row: Any, worker_ref: str, now: datetime, lease: timedelta) -> JobClaim:
        attempt = int(row.attempt_count) + 1
        claim_id = _opaque("claim")
        connection.execute(
            _CLAIMS.insert().values(
                claim_id=claim_id,
                job_id=row.job_id,
                worker_ref=worker_ref,
                attempt=attempt,
                lease_until=now + lease,
                claimed_at=now,
            )
        )
        connection.execute(
            update(_JOBS)
            .where(_JOBS.c.job_id == row.job_id)
            .values(status="claimed", attempt_count=attempt, updated_at=now)
        )
        return JobClaim(claim_id, row.job_id, attempt)

    def claim_job(self, now: datetime, worker_ref: str, lease: timedelta) -> JobClaim | None:
        now = _now(now)
        worker_ref = _ref("worker_ref", worker_ref, 128)
        if lease <= timedelta(0):
            raise ValueError("ledger lease must be positive")
        with self._engine.begin() as connection:
            self._expire_claims(connection, now)
            while True:
                row = connection.execute(
                    select(_JOBS)
                    .where(_JOBS.c.status == "queued", _JOBS.c.available_at <= now)
                    .order_by(_JOBS.c.available_at, _JOBS.c.job_id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                ).first()
                if row is None:
                    return None
                if row.attempt_count >= row.max_attempts:
                    connection.execute(
                        update(_JOBS)
                        .where(_JOBS.c.job_id == row.job_id)
                        .values(status="dead_letter", last_error_code="max_attempts", completed_at=now, updated_at=now)
                    )
                    continue
                return self._claim_row(connection, row, worker_ref, now, lease)

    def claim_parse_job(self, job: LedgerParseJob, *, worker_ref: str, now: datetime) -> LedgerClaim:
        now = _now(now)
        worker_ref = _ref("worker_ref", worker_ref, 128)
        with self._engine.begin() as connection:
            self._expire_claims(connection, now)
            row = connection.execute(
                select(_JOBS)
                .where(
                    _JOBS.c.tenant_id == _ref("tenant_id", job.tenant_id, 64),
                    _JOBS.c.queue_name == job.queue.value,
                    _JOBS.c.job_type == _PARSE_JOB_TYPES[job.queue.value],
                    _JOBS.c.artifact_ref == _ref("artifact_ref", job.artifact_ref, 192),
                    _JOBS.c.idempotency_key == _ref("idempotency_key", job.idempotency_key, 192),
                )
                .with_for_update(skip_locked=True)
            ).first()
            if row is None or row.status in _TERMINAL or row.status != "queued" or row.available_at > now:
                return LedgerClaim("unclaimed", False)
            if row.attempt_count >= row.max_attempts:
                connection.execute(
                    update(_JOBS)
                    .where(_JOBS.c.job_id == row.job_id)
                    .values(status="dead_letter", last_error_code="max_attempts", completed_at=now, updated_at=now)
                )
                return LedgerClaim("unclaimed", False)
            claim = self._claim_row(connection, row, worker_ref, now, timedelta(minutes=30))
            return LedgerClaim(claim.claim_id, True)

    def mark_running(self, claim_id: str, *, now: datetime | None = None) -> bool:
        stamp = _now(now)
        claim_id = _ref("claim_id", claim_id, 96)
        with self._engine.begin() as connection:
            job = connection.execute(
                select(_CLAIMS.c.job_id)
                .where(_CLAIMS.c.claim_id == claim_id, _CLAIMS.c.completed_at.is_(None))
                .with_for_update()
            ).scalar_one_or_none()
            if job is None:
                return False
            return (
                connection.execute(
                    update(_JOBS)
                    .where(_JOBS.c.job_id == job, _JOBS.c.status == "claimed")
                    .values(status="running", updated_at=stamp)
                ).rowcount
                == 1
            )

    def _finish(
        self,
        claim_id: str,
        *,
        status: str,
        now: datetime,
        reason: str | None = None,
        counts: dict[str, int] | None = None,
    ) -> bool:
        claim_id = _ref("claim_id", claim_id, 96)
        with self._engine.begin() as connection:
            job_id = connection.execute(
                select(_CLAIMS.c.job_id)
                .where(_CLAIMS.c.claim_id == claim_id, _CLAIMS.c.completed_at.is_(None))
                .with_for_update()
            ).scalar_one_or_none()
            if job_id is None:
                return False
            values: dict[str, Any] = {"status": status, "completed_at": now, "updated_at": now}
            if reason is not None:
                values["last_error_code"] = _reason(reason)
            if counts is not None:
                values["aggregate_counts"] = counts
            changed = connection.execute(
                update(_JOBS).where(_JOBS.c.job_id == job_id, _JOBS.c.status.in_(("claimed", "running"))).values(values)
            ).rowcount
            if changed != 1:
                return False
            connection.execute(
                update(_CLAIMS)
                .where(_CLAIMS.c.claim_id == claim_id, _CLAIMS.c.completed_at.is_(None))
                .values(completed_at=now, result_code=_reason(reason or status))
            )
            return True

    def complete_job(
        self, claim_id: str, aggregate: LedgerParseAggregate | Mapping[str, Any], *, now: datetime | None = None
    ) -> bool:
        return self._finish(claim_id, status="succeeded", now=_now(now), counts=_aggregate(aggregate))

    def complete_parse_job(self, claim_id: str, aggregate: LedgerParseAggregate, *, now: datetime) -> None:
        self.complete_job(claim_id, aggregate, now=now)

    def fail_job(self, claim_id: str, reason_code: str, *, now: datetime | None = None) -> bool:
        return self._finish(claim_id, status="failed", now=_now(now), reason=_reason(reason_code))

    def fail_parse_job(self, claim_id: str, reason_code: str, *, now: datetime) -> None:
        self.fail_job(claim_id, reason_code, now=now)

    def mark_uncertain(self, claim_id: str, reason_code: str, *, now: datetime | None = None) -> bool:
        return self._finish(claim_id, status="uncertain", now=_now(now), reason=_reason(reason_code))

    def get_job_status(self, job_id: str) -> JobStatus | None:
        job_id = _ref("job_id", job_id, 96)
        with self._engine.connect() as connection:
            row = connection.execute(select(_JOBS).where(_JOBS.c.job_id == job_id)).first()
        if row is None:
            return None
        return JobStatus(
            row.status, row.attempt_count, row.max_attempts, row.aggregate_counts or {}, row.last_error_code
        )
