"""Domain objects for CFDI recovery and reconciliation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    """Message envelope sent through RabbitMQ or fake queue adapters."""

    queue: QueueName
    tenant_id: str
    rfc: str
    payload: dict[str, Any]
    job_id: str = field(default_factory=lambda: str(uuid4()))
    correlation_id: str = field(default_factory=lambda: str(uuid4()))
    attempt: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "queue": self.queue.value,
            "job_id": self.job_id,
            "tenant_id": self.tenant_id,
            "rfc": self.rfc,
            "correlation_id": self.correlation_id,
            "attempt": self.attempt,
            "payload": self.payload,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "QueueMessage":
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            parsed_created_at = datetime.fromisoformat(created_at)
        else:
            parsed_created_at = datetime.now(timezone.utc)
        return cls(
            queue=QueueName(str(data["queue"])),
            job_id=str(data["job_id"]),
            tenant_id=str(data["tenant_id"]),
            rfc=str(data["rfc"]),
            correlation_id=str(data["correlation_id"]),
            attempt=int(data.get("attempt", 0)),
            payload=dict(data.get("payload") or {}),
            created_at=parsed_created_at,
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
