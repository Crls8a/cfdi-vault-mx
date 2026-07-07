"""Local state for human-gated live SAT metadata requests.

The file managed here lives under the configured local profile storage root,
not in the repository. It intentionally stores the full ``IdSolicitud`` only
for local follow-up verification while every printable field remains redacted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Mapping

from cfdi_vault.domain import DownloadQuery


STATE_SCHEMA_VERSION = 1
STATE_DIR = "state"
STATE_FILE = "live-metadata-requests.json"
STATE_JSON_INDENT = 2
DEFAULT_VERIFY_INITIAL_DELAY = timedelta(minutes=5)
DEFAULT_VERIFY_MAX_AGE = timedelta(hours=72)

REQUEST_ACCEPTED = "REQUEST_ACCEPTED"
VERIFY_SCHEDULED = "VERIFY_SCHEDULED"
VERIFY_IN_PROGRESS = "VERIFY_IN_PROGRESS"
VERIFY_IN_PROGRESS_SAT = "VERIFY_IN_PROGRESS_SAT"
VERIFY_FINISHED = "VERIFY_FINISHED"
VERIFY_NO_DATA = "VERIFY_NO_DATA"
VERIFY_REJECTED = "VERIFY_REJECTED"
VERIFY_EXPIRED = "VERIFY_EXPIRED"
VERIFY_FAILED_RETRYABLE = "VERIFY_FAILED_RETRYABLE"
VERIFY_FAILED_PERMANENT = "VERIFY_FAILED_PERMANENT"
PACKAGE_READY = "PACKAGE_READY"
PACKAGE_DOWNLOAD_SCHEDULED = "PACKAGE_DOWNLOAD_SCHEDULED"
PACKAGE_DOWNLOADED = "PACKAGE_DOWNLOADED"

LEGACY_PENDING_VERIFY_STATUSES = frozenset({"accepted", "submitted"})
PENDING_VERIFY_STATUSES = frozenset(
    {
        REQUEST_ACCEPTED,
        VERIFY_SCHEDULED,
        VERIFY_IN_PROGRESS_SAT,
        VERIFY_FAILED_RETRYABLE,
        *LEGACY_PENDING_VERIFY_STATUSES,
    }
)
TERMINAL_VERIFY_STATUSES = frozenset(
    {
        VERIFY_FINISHED,
        VERIFY_NO_DATA,
        VERIFY_REJECTED,
        VERIFY_EXPIRED,
        VERIFY_FAILED_PERMANENT,
        PACKAGE_READY,
        PACKAGE_DOWNLOAD_SCHEDULED,
        PACKAGE_DOWNLOADED,
    }
)
_IDENTIFIER_RE = re.compile(r"(?i)\b[0-9a-f][0-9a-f-]{14,120}[0-9a-f]\b")


class LiveRequestStateError(ValueError):
    """Raised when local live request state is missing or invalid."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class LiveMetadataRequestRecord:
    """Recoverable local reference to one accepted live metadata request."""

    request_ref: str
    profile_id: str
    direction: str
    kind: str
    operation: str
    fecha_inicial: str
    fecha_final: str
    criteria_hash: str
    id_solicitud: str
    id_solicitud_redacted: str
    sat_code: str
    sat_message: str
    created_at: str
    live: bool
    source_command: str
    permit_id_hash: str
    status: str
    attempt_count: int = 0
    next_check_at: str = ""
    last_checked_at: str = ""
    last_error_kind: str = ""
    last_http_status: int | None = None
    sat_estado_solicitud: str = ""
    sat_codigo_estado: str = ""
    numero_cfdis: int = 0
    package_ids: tuple[str, ...] = ()
    package_refs_redacted: tuple[str, ...] = ()
    updated_at: str = ""
    expires_at: str = ""

    @property
    def terminal_state(self) -> bool:
        return self.status in TERMINAL_VERIFY_STATUSES

    def to_document(self) -> dict[str, object]:
        return {
            "requestRef": self.request_ref,
            "profileId": self.profile_id,
            "direction": self.direction,
            "kind": self.kind,
            "operation": self.operation,
            "fechaInicial": self.fecha_inicial,
            "fechaFinal": self.fecha_final,
            "criteriaHash": self.criteria_hash,
            "idSolicitud": self.id_solicitud,
            "idSolicitudRedacted": self.id_solicitud_redacted,
            "satCode": self.sat_code,
            "satMessage": self.sat_message,
            "createdAt": self.created_at,
            "live": self.live,
            "sourceCommand": self.source_command,
            "permitIdHash": self.permit_id_hash,
            "status": self.status,
            "attemptCount": self.attempt_count,
            "nextCheckAt": self.next_check_at,
            "lastCheckedAt": self.last_checked_at,
            "lastErrorKind": self.last_error_kind,
            "lastHttpStatus": self.last_http_status,
            "satEstadoSolicitud": self.sat_estado_solicitud,
            "satCodigoEstado": self.sat_codigo_estado,
            "numeroCfdis": self.numero_cfdis,
            "packageIds": list(self.package_ids),
            "packageRefsRedacted": list(self.package_refs_redacted),
            "updatedAt": self.updated_at,
            "expiresAt": self.expires_at,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> "LiveMetadataRequestRecord":
        created_at = _required_str(document, "createdAt")
        status = _normalize_status(_required_str(document, "status"))
        updated_at = _optional_str(document, "updatedAt") or created_at
        expires_at = _optional_str(document, "expiresAt") or _format_dt(_parse_dt(created_at) + DEFAULT_VERIFY_MAX_AGE)
        next_check_at = _optional_str(document, "nextCheckAt")
        if not next_check_at and status in PENDING_VERIFY_STATUSES:
            next_check_at = _format_dt(_parse_dt(created_at) + DEFAULT_VERIFY_INITIAL_DELAY)
        return cls(
            request_ref=_required_str(document, "requestRef"),
            profile_id=_required_str(document, "profileId"),
            direction=_required_str(document, "direction"),
            kind=_required_str(document, "kind"),
            operation=_required_str(document, "operation"),
            fecha_inicial=_required_str(document, "fechaInicial"),
            fecha_final=_required_str(document, "fechaFinal"),
            criteria_hash=_required_str(document, "criteriaHash"),
            id_solicitud=_required_str(document, "idSolicitud"),
            id_solicitud_redacted=_required_str(document, "idSolicitudRedacted"),
            sat_code=_required_str(document, "satCode"),
            sat_message=_required_str(document, "satMessage"),
            created_at=created_at,
            live=_required_bool(document, "live"),
            source_command=_required_str(document, "sourceCommand"),
            permit_id_hash=_required_str(document, "permitIdHash"),
            status=status,
            attempt_count=_optional_int(document, "attemptCount", default=0),
            next_check_at=next_check_at,
            last_checked_at=_optional_str(document, "lastCheckedAt"),
            last_error_kind=_optional_str(document, "lastErrorKind"),
            last_http_status=_optional_int_or_none(document, "lastHttpStatus"),
            sat_estado_solicitud=_optional_str(document, "satEstadoSolicitud"),
            sat_codigo_estado=_optional_str(document, "satCodigoEstado"),
            numero_cfdis=_optional_int(document, "numeroCfdis", default=0),
            package_ids=_optional_str_tuple(document, "packageIds"),
            package_refs_redacted=_optional_str_tuple(document, "packageRefsRedacted"),
            updated_at=updated_at,
            expires_at=expires_at,
        )


@dataclass(frozen=True)
class LiveMetadataRequestSummary:
    """Safe aggregate status for the local async verify scheduler."""

    pending_verify_count: int
    due_verify_count: int
    next_due_verification: str
    finished_requests: int
    failed_requests: int
    package_ready_count: int


def live_metadata_state_path(storage_root: str | Path) -> Path:
    """Return the local JSON state file for live metadata requests."""

    return Path(storage_root).expanduser() / STATE_DIR / STATE_FILE


def persist_live_metadata_request(
    *,
    storage_root: str | Path,
    profile_id: str,
    query: DownloadQuery,
    operation: str,
    id_solicitud: str,
    sat_code: str,
    sat_message: str,
    source_command: str,
    permit_ref: str | None,
    status: str = VERIFY_SCHEDULED,
    now: datetime | None = None,
) -> LiveMetadataRequestRecord:
    """Persist one accepted live metadata request without raw SOAP or tokens."""

    created = now or datetime.now(timezone.utc)
    request_id = str(id_solicitud).strip()
    if not request_id:
        raise LiveRequestStateError("id-solicitud-required")
    criteria_hash = query.criteria_hash()
    record = LiveMetadataRequestRecord(
        request_ref=_request_ref(profile_id=profile_id, criteria_hash=criteria_hash, id_solicitud=request_id),
        profile_id=profile_id,
        direction=query.direction.value,
        kind=query.request_type.value,
        operation=operation,
        fecha_inicial=query.period.start.isoformat() if query.period else "",
        fecha_final=query.period.end.isoformat() if query.period else "",
        criteria_hash=criteria_hash,
        id_solicitud=request_id,
        id_solicitud_redacted=redact_identifier(request_id),
        sat_code=str(sat_code or ""),
        sat_message=_safe_message(sat_message),
        created_at=_format_dt(created),
        live=True,
        source_command=source_command,
        permit_id_hash=_hash_optional(permit_ref),
        status=_normalize_status(status),
        attempt_count=0,
        next_check_at=_format_dt(created + DEFAULT_VERIFY_INITIAL_DELAY),
        updated_at=_format_dt(created),
        expires_at=_format_dt(created + DEFAULT_VERIFY_MAX_AGE),
    )
    upsert_live_metadata_request(storage_root=storage_root, record=record)
    return record


def upsert_live_metadata_request(*, storage_root: str | Path, record: LiveMetadataRequestRecord) -> None:
    """Persist one record update by safe request reference."""

    path = live_metadata_state_path(storage_root)
    document = _read_state(path)
    records = [LiveMetadataRequestRecord.from_document(item) for item in document["requests"] if isinstance(item, Mapping)]
    records = [existing for existing in records if existing.request_ref != record.request_ref]
    records.append(record)
    records.sort(key=lambda item: item.created_at, reverse=True)
    _write_state(path, records)


def list_live_metadata_requests(
    storage_root: str | Path,
    *,
    pending_only: bool = False,
) -> tuple[LiveMetadataRequestRecord, ...]:
    """List persisted live metadata requests without printing full identifiers."""

    path = live_metadata_state_path(storage_root)
    document = _read_state(path)
    records = tuple(
        LiveMetadataRequestRecord.from_document(item) for item in document["requests"] if isinstance(item, Mapping)
    )
    if pending_only:
        return tuple(record for record in records if record.status in PENDING_VERIFY_STATUSES)
    return records


def load_live_metadata_request(storage_root: str | Path, request_ref: str) -> LiveMetadataRequestRecord:
    """Load one local request by safe reference."""

    requested = str(request_ref).strip()
    if not requested:
        raise LiveRequestStateError("request-ref-required")
    for record in list_live_metadata_requests(storage_root):
        if record.request_ref == requested:
            return record
    raise LiveRequestStateError("request-state-not-found")


def summarize_live_metadata_requests(
    records: tuple[LiveMetadataRequestRecord, ...],
    *,
    now: datetime | None = None,
) -> LiveMetadataRequestSummary:
    """Return redacted scheduler counts for CLI status output."""

    current = now or datetime.now(timezone.utc)
    pending = tuple(record for record in records if record.status in PENDING_VERIFY_STATUSES)
    due = tuple(record for record in pending if _is_due(record, current))
    scheduled = sorted((record.next_check_at for record in pending if record.next_check_at), key=str)
    failed = tuple(record for record in records if record.status in {VERIFY_FAILED_PERMANENT, VERIFY_REJECTED, VERIFY_EXPIRED})
    finished = tuple(record for record in records if record.status in {VERIFY_FINISHED, PACKAGE_READY})
    package_ready = tuple(record for record in records if record.status == PACKAGE_READY)
    return LiveMetadataRequestSummary(
        pending_verify_count=len(pending),
        due_verify_count=len(due),
        next_due_verification=scheduled[0] if scheduled else "",
        finished_requests=len(finished),
        failed_requests=len(failed),
        package_ready_count=len(package_ready),
    )


def redact_identifier(value: str) -> str:
    """Return a safe short identifier fingerprint for CLI/log output."""

    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 8:
        return "<redacted>"
    return f"{text[:4]}...{text[-4:]}"


def redact_package_ref(value: str) -> str:
    """Return a stable non-reversible package reference for status output."""

    text = str(value or "").strip()
    if not text:
        return ""
    return f"pkg-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]}"


def parse_state_datetime(value: str) -> datetime:
    """Parse a state timestamp and normalize it to aware UTC."""

    return _parse_dt(value)


def format_state_datetime(value: datetime) -> str:
    """Format a timestamp for local state JSON."""

    return _format_dt(value)


def _is_due(record: LiveMetadataRequestRecord, now: datetime) -> bool:
    if not record.next_check_at:
        return False
    return _parse_dt(record.next_check_at) <= _normalize_dt(now)


def _request_ref(*, profile_id: str, criteria_hash: str, id_solicitud: str) -> str:
    digest = hashlib.sha256(f"{profile_id}:{criteria_hash}:{id_solicitud}".encode("utf-8")).hexdigest()
    return f"req-{criteria_hash[:12]}-{digest[:12]}"


def _hash_optional(value: str | None) -> str:
    if not value:
        return ""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16]


def _safe_message(value: str) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    text = _IDENTIFIER_RE.sub(lambda match: redact_identifier(match.group(0)), text)
    return text[:256]


def _read_state(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {"schemaVersion": STATE_SCHEMA_VERSION, "requests": []}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise LiveRequestStateError("request-state-io-error") from exc
    except json.JSONDecodeError as exc:
        raise LiveRequestStateError("request-state-invalid-json") from exc
    if not isinstance(document, Mapping):
        raise LiveRequestStateError("request-state-invalid")
    if document.get("schemaVersion") != STATE_SCHEMA_VERSION:
        raise LiveRequestStateError("request-state-unsupported-version")
    requests = document.get("requests")
    if not isinstance(requests, list):
        raise LiveRequestStateError("request-state-invalid")
    return {"schemaVersion": STATE_SCHEMA_VERSION, "requests": requests}


def _write_state(path: Path, records: list[LiveMetadataRequestRecord]) -> None:
    document = {
        "schemaVersion": STATE_SCHEMA_VERSION,
        "requests": [record.to_document() for record in records],
    }
    tmp_path = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.write_text(
            json.dumps(document, indent=STATE_JSON_INDENT, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp_path, path)
    except OSError as exc:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise LiveRequestStateError("request-state-io-error") from exc


def _format_dt(value: datetime) -> str:
    return _normalize_dt(value).isoformat().replace("+00:00", "Z")


def _parse_dt(value: str) -> datetime:
    if not value:
        raise LiveRequestStateError("request-state-invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LiveRequestStateError("request-state-invalid") from exc
    return _normalize_dt(parsed)


def _normalize_dt(value: datetime) -> datetime:
    normalized = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc)


def _normalize_status(value: str) -> str:
    status = str(value or "").strip()
    if status.lower() in LEGACY_PENDING_VERIFY_STATUSES or status == REQUEST_ACCEPTED:
        return VERIFY_SCHEDULED
    return status or VERIFY_SCHEDULED


def _required_str(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str):
        raise LiveRequestStateError("request-state-invalid")
    return value


def _required_bool(document: Mapping[str, object], key: str) -> bool:
    value = document.get(key)
    if not isinstance(value, bool):
        raise LiveRequestStateError("request-state-invalid")
    return value


def _optional_str(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise LiveRequestStateError("request-state-invalid")
    return value


def _optional_int(document: Mapping[str, object], key: str, *, default: int) -> int:
    value = document.get(key)
    if value is None:
        return default
    if not isinstance(value, int):
        raise LiveRequestStateError("request-state-invalid")
    return value


def _optional_int_or_none(document: Mapping[str, object], key: str) -> int | None:
    value = document.get(key)
    if value is None:
        return None
    if not isinstance(value, int):
        raise LiveRequestStateError("request-state-invalid")
    return value


def _optional_str_tuple(document: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = document.get(key)
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise LiveRequestStateError("request-state-invalid")
    return tuple(value)
