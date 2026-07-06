"""Local state for human-gated live SAT metadata requests.

The file managed here lives under the configured local profile storage root,
not in the repository. It intentionally stores the full ``IdSolicitud`` only
for local follow-up verification while every printable field remains redacted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from cfdi_vault.domain import DownloadQuery


STATE_SCHEMA_VERSION = 1
STATE_DIR = "state"
STATE_FILE = "live-metadata-requests.json"
STATE_JSON_INDENT = 2
PENDING_VERIFY_STATUSES = frozenset({"accepted", "submitted"})
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
        }

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> "LiveMetadataRequestRecord":
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
            created_at=_required_str(document, "createdAt"),
            live=_required_bool(document, "live"),
            source_command=_required_str(document, "sourceCommand"),
            permit_id_hash=_required_str(document, "permitIdHash"),
            status=_required_str(document, "status"),
        )


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
    status: str = "accepted",
    now: datetime | None = None,
) -> LiveMetadataRequestRecord:
    """Persist one accepted live metadata request without raw SOAP or tokens."""

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
        created_at=_format_dt(now or datetime.now(timezone.utc)),
        live=True,
        source_command=source_command,
        permit_id_hash=_hash_optional(permit_ref),
        status=status,
    )
    path = live_metadata_state_path(storage_root)
    document = _read_state(path)
    records = [LiveMetadataRequestRecord.from_document(item) for item in document["requests"] if isinstance(item, Mapping)]
    records = [existing for existing in records if existing.request_ref != record.request_ref]
    records.append(record)
    records.sort(key=lambda item: item.created_at, reverse=True)
    _write_state(path, records)
    return record


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


def redact_identifier(value: str) -> str:
    """Return a safe short identifier fingerprint for CLI/log output."""

    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 8:
        return "<redacted>"
    return f"{text[:4]}...{text[-4:]}"


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
    normalized = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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
