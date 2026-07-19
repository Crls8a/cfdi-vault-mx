"""Durable-claim boundary for accounting-ledger parse jobs.

The queue already carries only an opaque artifact reference.  This module
adds the missing worker boundary without pretending that process-local state
is durable: callers must inject a repository whose claim and result methods
commit to PostgreSQL (or another durable store).  The V6 outbox/ledger-job
schema is intentionally not part of this unit.

The parser callback runs only after ``claim_parse_job`` returns, so no
database transaction can remain open during external storage or parsing I/O.
Only aggregate counters and fixed reason codes cross the public result
boundary; rows, identifiers, amounts, and parser messages are excluded.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_safety import validate_reason_code, validate_reference_string

_PARSE_QUEUES = frozenset({QueueName.CFDI_PARSE_METADATA, QueueName.CFDI_PARSE_XML})
_COUNT_FIELDS = frozenset(
    {
        "records_seen",
        "records_written",
        "duplicates",
        "conflicts",
        "unknown",
        "invalid",
        "concepts",
        "taxes",
        "payments",
        "payroll",
        "related",
    }
)


@dataclass(frozen=True, repr=False)
class LedgerParseJob:
    """Reference-only parse work hydrated by the durable repository."""

    tenant_id: str
    artifact_ref: str
    queue: QueueName
    idempotency_key: str

    def __post_init__(self) -> None:
        if not isinstance(self.queue, QueueName) or self.queue not in _PARSE_QUEUES:
            raise ValueError("ledger job must use a parse queue")
        for name, value in (("tenant_id", self.tenant_id), ("artifact_ref", self.artifact_ref)):
            validate_reference_string(name, value)
        validate_reference_string("idempotency_key", self.idempotency_key)

    def __repr__(self) -> str:
        return f"LedgerParseJob(queue={self.queue.value!r}, references_redacted=True)"

    @classmethod
    def from_message(cls, message: QueueMessage) -> "LedgerParseJob":
        return cls(message.tenant_id, message.job_id, message.queue, message.idempotency_key)


@dataclass(frozen=True, repr=False)
class LedgerClaim:
    """Result of one durable claim transaction."""

    claim_ref: str
    accepted: bool

    def __post_init__(self) -> None:
        if not isinstance(self.accepted, bool):
            raise TypeError("ledger claim accepted must be a boolean")
        validate_reference_string("claim_ref", self.claim_ref)

    def __repr__(self) -> str:
        return f"LedgerClaim(accepted={self.accepted!r})"


@dataclass(frozen=True)
class LedgerParseAggregate:
    """Fixed aggregate counters; no fiscal values or row data are allowed."""

    records_seen: int = 0
    records_written: int = 0
    duplicates: int = 0
    conflicts: int = 0
    unknown: int = 0
    invalid: int = 0
    concepts: int = 0
    taxes: int = 0
    payments: int = 0
    payroll: int = 0
    related: int = 0

    def __post_init__(self) -> None:
        for name in _COUNT_FIELDS:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"aggregate count {name} must be a non-negative integer")

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in sorted(_COUNT_FIELDS) if getattr(self, name)}


class LedgerParseError(RuntimeError):
    """Parser failure represented by a fixed, redacted reason code."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = validate_reason_code(reason_code)
        super().__init__(self.reason_code)


class LedgerJobStore(Protocol):
    """Durable claim/result port; implementations must use short transactions."""

    def claim_parse_job(self, job: LedgerParseJob, *, worker_ref: str, now: datetime) -> LedgerClaim:
        """Commit a claim before any parser or storage I/O."""

    def complete_parse_job(
        self,
        claim_ref: str,
        aggregate: LedgerParseAggregate,
        *,
        now: datetime,
    ) -> None:
        """Commit a successful result exactly once."""

    def fail_parse_job(self, claim_ref: str, reason_code: str, *, now: datetime) -> None:
        """Commit a categorized terminal or retryable result exactly once."""


@dataclass(frozen=True, repr=False)
class LedgerWorkerReport:
    """Sanitized outcome suitable for status aggregation."""

    status: str
    aggregate: LedgerParseAggregate = field(default_factory=LedgerParseAggregate)
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"succeeded", "duplicate", "failed"}:
            raise ValueError("unsupported ledger worker status")
        if self.reason_code is not None:
            validate_reason_code(self.reason_code)

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {"status": self.status, "aggregates": self.aggregate.as_dict()}
        if self.reason_code is not None:
            result["reason_code"] = self.reason_code
        return result

    def __repr__(self) -> str:
        return f"LedgerWorkerReport({self.as_dict()!r})"


class LedgerWorker:
    """Run one reference-only parse job around a durable claim port."""

    def __init__(
        self,
        store: LedgerJobStore,
        *,
        worker_ref: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        validate_reference_string("worker_ref", worker_ref)
        self._store = store
        self._worker_ref = worker_ref
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def run_once(
        self,
        message: QueueMessage,
        parser: Callable[[LedgerParseJob], LedgerParseAggregate],
    ) -> LedgerWorkerReport:
        job = LedgerParseJob.from_message(message)
        claim = self._store.claim_parse_job(job, worker_ref=self._worker_ref, now=self._clock())
        if not claim.accepted:
            return LedgerWorkerReport(status="duplicate")
        try:
            aggregate = parser(job)
            if not isinstance(aggregate, LedgerParseAggregate):
                raise LedgerParseError("parse_result_invalid")
        except LedgerParseError as exc:
            self._store.fail_parse_job(claim.claim_ref, exc.reason_code, now=self._clock())
            return LedgerWorkerReport(status="failed", reason_code=exc.reason_code)
        except Exception:
            self._store.fail_parse_job(claim.claim_ref, "parse_failed", now=self._clock())
            return LedgerWorkerReport(status="failed", reason_code="parse_failed")
        self._store.complete_parse_job(claim.claim_ref, aggregate, now=self._clock())
        return LedgerWorkerReport(status="succeeded", aggregate=aggregate)
