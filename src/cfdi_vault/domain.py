"""Domain objects for CFDI recovery and reconciliation."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import StrEnum
import hashlib
import json
from typing import Any
from uuid import uuid4


class RequestType(StrEnum):
    """SAT request content types."""

    METADATA = "metadata"
    CFDI = "cfdi"


class DownloadDirection(StrEnum):
    """Direction of the requested CFDI documents."""

    ISSUED = "issued"
    RECEIVED = "received"
    FOLIO = "folio"


class QueueName(StrEnum):
    """Durable RabbitMQ queue names used by the recovery system."""

    SAT_REQUEST = "sat.request"
    SAT_VERIFY = "sat.verify"
    SAT_DOWNLOAD = "sat.download"
    CFDI_PARSE_METADATA = "cfdi.parse.metadata"
    CFDI_PARSE_XML = "cfdi.parse.xml"
    CFDI_RECONCILE = "cfdi.reconcile"
    CFDI_EXPORT = "cfdi.export"
    DEAD_LETTER = "dead.letter"


class JobStatus(StrEnum):
    """Queue job lifecycle states."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    RETRY_SCHEDULED = "retry_scheduled"
    MANUAL_REVIEW = "manual_review"


class SatRequestState(StrEnum):
    """Normalized SAT request states."""

    ACCEPTED = "accepted"
    IN_PROCESS = "in_process"
    FINISHED = "finished"
    ERROR = "error"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ReconciliationState(StrEnum):
    """UUID-level reconciliation state."""

    DISCOVERED_IN_METADATA = "DISCOVERED_IN_METADATA"
    XML_PENDING = "XML_PENDING"
    XML_REQUESTED = "XML_REQUESTED"
    XML_DOWNLOADED = "XML_DOWNLOADED"
    XML_NOT_AVAILABLE = "XML_NOT_AVAILABLE"
    CANCELLED_METADATA = "CANCELLED_METADATA"
    CANCELLED_CONFIRMED = "CANCELLED_CONFIRMED"
    STATE_CHECK_PENDING = "STATE_CHECK_PENDING"
    STATE_CHECKED = "STATE_CHECKED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    FAILED_PERMANENT = "FAILED_PERMANENT"


class CfdiStatusOutcome(StrEnum):
    """Normalized CFDI status consultation outcomes."""

    ACTIVE = "active"
    CANCELLED = "cancelled"
    NOT_FOUND = "not_found"
    UNAUTHORIZED = "unauthorized"
    RETRYABLE = "retryable"
    PERMANENT = "permanent"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DateTimePeriod:
    """Closed datetime range used for SAT request planning."""

    start: datetime
    end: datetime

    def __post_init__(self) -> None:
        if self.end < self.start:
            raise ValueError("period end must be greater than or equal to start")

    def as_dict(self) -> dict[str, str]:
        return {"start": self.start.isoformat(), "end": self.end.isoformat()}


@dataclass(frozen=True)
class DownloadQuery:
    """Normalized criteria for one SAT metadata or CFDI request."""

    tenant_id: str
    requester_rfc: str
    direction: DownloadDirection
    request_type: RequestType
    period: DateTimePeriod | None = None
    issuer_rfc: str | None = None
    receiver_rfcs: tuple[str, ...] = ()
    uuid: str | None = None
    document_status: str | None = None
    document_type: str | None = None
    complement: str | None = None
    rfc_on_behalf: str | None = None
    recovery_variant_reason: str | None = None

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.tenant_id:
            errors.append("tenant_id is required")
        if not self.requester_rfc:
            errors.append("requester_rfc is required")
        if self.direction == DownloadDirection.FOLIO:
            if not self.uuid:
                errors.append("uuid is required for folio requests")
        elif self.period is None:
            errors.append("period is required for issued or received requests")
        if len(self.receiver_rfcs) > 5:
            errors.append("receiver_rfcs accepts at most 5 RFC values")
        return tuple(errors)

    def criteria_hash(self) -> str:
        """Stable hash used to prevent duplicate SAT requests."""

        payload = {
            "tenant_id": self.tenant_id,
            "requester_rfc": self.requester_rfc.upper(),
            "direction": self.direction.value,
            "request_type": self.request_type.value,
            "period": self.period.as_dict() if self.period else None,
            "issuer_rfc": self.issuer_rfc.upper() if self.issuer_rfc else None,
            "receiver_rfcs": sorted(rfc.upper() for rfc in self.receiver_rfcs),
            "uuid": self.uuid.upper() if self.uuid else None,
            "document_status": self.document_status,
            "document_type": self.document_type,
            "complement": self.complement,
            "rfc_on_behalf": self.rfc_on_behalf.upper() if self.rfc_on_behalf else None,
            "recovery_variant_reason": self.recovery_variant_reason,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class QueueMessage:
    """Reference-only delivery envelope sent through queue adapters."""

    queue: QueueName
    tenant_id: str
    job_id: str = field(default_factory=lambda: str(uuid4()))
    profile_id: str | None = None
    correlation_id: str = field(default_factory=lambda: str(uuid4()))
    attempt: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    message_id: str = field(default_factory=lambda: str(uuid4()))
    idempotency_key: str = ""
    envelope_version: int = 1
    not_before: datetime | None = None

    def __post_init__(self) -> None:
        if isinstance(self.envelope_version, bool) or not isinstance(self.envelope_version, int):
            raise TypeError("queue envelope_version must be an integer")
        if self.envelope_version != 1:
            raise ValueError("unsupported queue envelope version")
        if isinstance(self.attempt, bool) or not isinstance(self.attempt, int) or self.attempt < 0:
            raise ValueError("queue attempt must be a non-negative integer")
        for name, value in (
            ("tenant_id", self.tenant_id),
            ("job_id", self.job_id),
            ("message_id", self.message_id),
            ("correlation_id", self.correlation_id),
        ):
            if not isinstance(value, str):
                raise TypeError(f"queue {name} must be a string")
            if not value.strip():
                raise ValueError(f"queue {name} cannot be empty")
        if self.profile_id is not None and (not isinstance(self.profile_id, str) or not self.profile_id.strip()):
            raise ValueError("queue profile_id must be a non-empty string or null")
        if not self.idempotency_key:
            object.__setattr__(self, "idempotency_key", self.job_id)
        if not isinstance(self.idempotency_key, str):
            raise TypeError("queue idempotency_key must be a string")
        if not isinstance(self.created_at, datetime) or (
            self.not_before is not None and not isinstance(self.not_before, datetime)
        ):
            raise TypeError("queue timestamps must be datetime values")

    def as_dict(self) -> dict[str, Any]:
        return {
            "queue": self.queue.value,
            "job_id": self.job_id,
            "tenant_id": self.tenant_id,
            "profile_id": self.profile_id,
            "correlation_id": self.correlation_id,
            "message_id": self.message_id,
            "idempotency_key": self.idempotency_key,
            "envelope_version": self.envelope_version,
            "attempt": self.attempt,
            "created_at": self.created_at.isoformat(),
            "not_before": self.not_before.isoformat() if self.not_before else None,
        }

    def retry_after(self, delay_seconds: int, *, now: datetime | None = None) -> "QueueMessage":
        """Create the next delivery while preserving correlation/idempotency."""

        if isinstance(delay_seconds, bool) or not isinstance(delay_seconds, int) or delay_seconds < 0:
            raise ValueError("retry delay_seconds must be a non-negative integer")
        moment = now or datetime.now(timezone.utc)
        return replace(
            self,
            message_id=str(uuid4()),
            attempt=self.attempt + 1,
            not_before=moment + timedelta(seconds=delay_seconds),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "QueueMessage":
        allowed = {
            "queue",
            "job_id",
            "tenant_id",
            "profile_id",
            "correlation_id",
            "message_id",
            "idempotency_key",
            "envelope_version",
            "attempt",
            "created_at",
            "not_before",
        }
        unknown = set(data) - allowed
        missing = allowed - set(data)
        if unknown:
            raise ValueError(f"unsupported queue envelope fields: {sorted(unknown)}")
        if missing:
            raise ValueError(f"missing queue envelope fields: {sorted(missing)}")
        for name in ("queue", "job_id", "tenant_id", "correlation_id", "message_id", "idempotency_key", "created_at"):
            if not isinstance(data[name], str):
                raise TypeError(f"queue {name} must be a string")
        profile_id = data["profile_id"]
        if profile_id is not None and not isinstance(profile_id, str):
            raise TypeError("queue profile_id must be a string or null")
        for name in ("envelope_version", "attempt"):
            if isinstance(data[name], bool) or not isinstance(data[name], int):
                raise TypeError(f"queue {name} must be an integer")
        not_before = data["not_before"]
        if not_before is not None and not isinstance(not_before, str):
            raise TypeError("queue not_before must be an ISO datetime string or null")
        return cls(
            queue=QueueName(data["queue"]),
            job_id=data["job_id"],
            tenant_id=data["tenant_id"],
            profile_id=profile_id,
            correlation_id=data["correlation_id"],
            message_id=data["message_id"],
            idempotency_key=data["idempotency_key"],
            envelope_version=data["envelope_version"],
            attempt=data["attempt"],
            created_at=datetime.fromisoformat(data["created_at"]),
            not_before=datetime.fromisoformat(not_before) if not_before is not None else None,
        )


@dataclass(frozen=True)
class MetadataEntry:
    """Canonical metadata-led inventory row."""

    uuid: str
    issuer_rfc: str
    issuer_name: str
    receiver_rfc: str
    receiver_name: str
    issue_date: datetime
    total: Decimal
    status: str
    effect: str
    source_package_id: str


@dataclass(frozen=True)
class CfdiStatusQuery:
    """Minimum data required by SAT status consultation."""

    uuid: str
    issuer_rfc: str
    receiver_rfc: str
    total: Decimal


@dataclass(frozen=True)
class CfdiStatusResult:
    """Normalized result returned by a CFDI status consultation adapter."""

    uuid: str
    status: str
    checked_at: datetime
    sat_code: str | None = None
    raw_response: dict[str, Any] = field(default_factory=dict)
    outcome: CfdiStatusOutcome = CfdiStatusOutcome.UNKNOWN


@dataclass(frozen=True)
class UserFacingError:
    """Typed error payload for CLI/API callers."""

    code: str
    user_message: str
    developer_message: str
    next_action: str
    retryable: bool
    severity: str = "error"
    sat_code: str | None = None
    request_id: str | None = None
    package_id: str | None = None
    correlation_id: str = field(default_factory=lambda: str(uuid4()))
