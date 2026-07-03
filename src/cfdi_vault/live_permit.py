"""One-time local permits for guarded live SAT operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
from typing import Mapping

from cfdi_vault.domain import DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.setup_core import SetupError, find_repo_root, resolve_appdata_root, validate_profile_id

ALLOWED_SCOPES = frozenset({"transport_probe", "metadata_live_smoke"})
PERMIT_INDENT = 2
MAX_EXPIRES_MINUTES = 15
MAX_RANGE_DAYS = 1
MAX_ATTEMPTS = 1
PERMIT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


class LivePermitError(ValueError):
    """Raised when a live execution permit is missing, invalid, or consumed."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class LivePermitRequest:
    scope: str
    profile_id: str
    kind: str
    direction: str
    date_from: str
    date_to: str
    reason: str
    expires_minutes: int = MAX_EXPIRES_MINUTES
    issued_by: str = "carlos-local"


@dataclass(frozen=True)
class LiveExecutionPermit:
    """Auditable one-time authorization for one scoped live operation."""

    permit_id: str
    scope: str
    profile_id: str
    kind: str
    direction: str
    date_from: str
    date_to: str
    max_range_days: int
    max_attempts: int
    allow_real_sat: bool
    allow_real_credentials: bool
    created_at: datetime
    expires_at: datetime
    issued_by: str
    reason: str
    consumed: bool
    consumed_at: datetime | None
    redaction_required: bool
    repo_root_hash: str
    path: Path | None = None

    def to_document(self) -> dict[str, object]:
        return {
            "permitId": self.permit_id,
            "scope": self.scope,
            "profileId": self.profile_id,
            "kind": self.kind,
            "direction": self.direction,
            "dateFrom": self.date_from,
            "dateTo": self.date_to,
            "maxRangeDays": self.max_range_days,
            "maxAttempts": self.max_attempts,
            "allowRealSat": self.allow_real_sat,
            "allowRealCredentials": self.allow_real_credentials,
            "createdAt": _format_dt(self.created_at),
            "expiresAt": _format_dt(self.expires_at),
            "issuedBy": self.issued_by,
            "reason": self.reason,
            "consumed": self.consumed,
            "consumedAt": _format_dt(self.consumed_at) if self.consumed_at else None,
            "redactionRequired": self.redaction_required,
            "repoRootHash": self.repo_root_hash,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, object], *, path: Path | None = None) -> LiveExecutionPermit:
        return cls(
            permit_id=_required_str(document, "permitId"),
            scope=_required_str(document, "scope"),
            profile_id=_required_str(document, "profileId"),
            kind=_required_str(document, "kind"),
            direction=_required_str(document, "direction"),
            date_from=_required_str(document, "dateFrom"),
            date_to=_required_str(document, "dateTo"),
            max_range_days=_required_int(document, "maxRangeDays"),
            max_attempts=_required_int(document, "maxAttempts"),
            allow_real_sat=_required_bool(document, "allowRealSat"),
            allow_real_credentials=_required_bool(document, "allowRealCredentials"),
            created_at=_parse_dt(_required_str(document, "createdAt")),
            expires_at=_parse_dt(_required_str(document, "expiresAt")),
            issued_by=_required_str(document, "issuedBy"),
            reason=_required_str(document, "reason"),
            consumed=_required_bool(document, "consumed"),
            consumed_at=_optional_dt(document.get("consumedAt")),
            redaction_required=_required_bool(document, "redactionRequired"),
            repo_root_hash=_required_str(document, "repoRootHash"),
            path=path,
        )


def permit_root(*, env: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    """Return the local AppData permit folder; never a repository path in production."""

    return resolve_appdata_root(env=env, home=home) / "permits"


def resolve_live_permit_reference(permit_ref: str | Path, *, env: Mapping[str, str] | None = None) -> Path:
    """Resolve a permit id or explicit path to the AppData permit document path."""

    raw = str(permit_ref).strip()
    if not raw:
        raise LivePermitError("permit-required")
    if PERMIT_ID_PATTERN.fullmatch(raw) and not raw.lower().endswith(".json"):
        return permit_root(env=env) / f"live-permit-{raw}.json"
    return Path(raw).expanduser()


def current_repo_identity(repo_root: Path | None = None) -> str:
    """Return the current commit id, falling back to a stable path hash outside git."""

    root = _repo_root(repo_root)
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    resolved = str(root.resolve()).replace("\\", "/")
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()


def create_live_execution_permit(
    request: LivePermitRequest,
    *,
    env: Mapping[str, str] | None = None,
    now: datetime | None = None,
    repo_root: Path | None = None,
) -> LiveExecutionPermit:
    """Create one scoped permit document under local AppData."""

    safe_request = _validated_request(request)
    created_at = _utc_now(now)
    root = permit_root(env=env)
    _ensure_permit_root_outside_repo(root, repo_root=repo_root)
    permit_id = secrets.token_urlsafe(12)
    permit = LiveExecutionPermit(
        permit_id=permit_id,
        scope=safe_request.scope,
        profile_id=safe_request.profile_id,
        kind=safe_request.kind,
        direction=safe_request.direction,
        date_from=safe_request.date_from,
        date_to=safe_request.date_to,
        max_range_days=MAX_RANGE_DAYS,
        max_attempts=MAX_ATTEMPTS,
        allow_real_sat=True,
        allow_real_credentials=safe_request.scope == "metadata_live_smoke",
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=safe_request.expires_minutes),
        issued_by=safe_request.issued_by,
        reason=safe_request.reason,
        consumed=False,
        consumed_at=None,
        redaction_required=True,
        repo_root_hash=current_repo_identity(repo_root),
        path=root / f"live-permit-{permit_id}.json",
    )
    assert permit.path is not None
    root.mkdir(parents=True, exist_ok=True)
    _write_permit_document(permit.path, permit)
    return permit


def load_live_execution_permit(
    permit_ref: str | Path,
    *,
    env: Mapping[str, str] | None = None,
) -> LiveExecutionPermit:
    path = _validated_permit_path(resolve_live_permit_reference(permit_ref, env=env), env=env)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise LivePermitError("permit-not-found") from exc
    except json.JSONDecodeError as exc:
        raise LivePermitError("permit-invalid-json") from exc
    return LiveExecutionPermit.from_document(document, path=path)


def validate_and_consume_live_permit(
    permit_ref: str | Path,
    *,
    scope: str,
    profile_id: str,
    kind: str,
    direction: str,
    date_from: str,
    date_to: str,
    env: Mapping[str, str] | None = None,
    now: datetime | None = None,
    repo_root: Path | None = None,
) -> LiveExecutionPermit:
    """Validate exact operation scope and consume the permit before live I/O."""

    permit = load_live_execution_permit(permit_ref, env=env)
    expected = {
        "scope": scope,
        "profile_id": _safe_profile_id(profile_id),
        "kind": kind,
        "direction": direction,
        "date_from": date_from,
        "date_to": date_to,
    }
    actual = {
        "scope": permit.scope,
        "profile_id": permit.profile_id,
        "kind": permit.kind,
        "direction": permit.direction,
        "date_from": permit.date_from,
        "date_to": permit.date_to,
    }
    for key, value in expected.items():
        if actual[key] != value:
            raise LivePermitError(f"permit-{_document_key(key)}-mismatch")

    _validate_document_policy(permit, now=_utc_now(now), repo_root=repo_root)
    consumed = LiveExecutionPermit(
        permit_id=permit.permit_id,
        scope=permit.scope,
        profile_id=permit.profile_id,
        kind=permit.kind,
        direction=permit.direction,
        date_from=permit.date_from,
        date_to=permit.date_to,
        max_range_days=permit.max_range_days,
        max_attempts=permit.max_attempts,
        allow_real_sat=permit.allow_real_sat,
        allow_real_credentials=permit.allow_real_credentials,
        created_at=permit.created_at,
        expires_at=permit.expires_at,
        issued_by=permit.issued_by,
        reason=permit.reason,
        consumed=True,
        consumed_at=_utc_now(now),
        redaction_required=permit.redaction_required,
        repo_root_hash=permit.repo_root_hash,
        path=permit.path,
    )
    assert consumed.path is not None
    _write_permit_document(consumed.path, consumed)
    return consumed


def permit_expectation_from_query(scope: str, profile_id: str, query: DownloadQuery) -> dict[str, str]:
    if query.period is None:
        raise LivePermitError("permit-query-period-required")
    return {
        "scope": scope,
        "profile_id": profile_id,
        "kind": query.request_type.value,
        "direction": query.direction.value,
        "date_from": query.period.start.date().isoformat(),
        "date_to": query.period.end.date().isoformat(),
    }


def transport_probe_permit_expectation(profile_id: str, permit_ref: str | Path, *, env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the exact public transport probe expectation from the permit itself."""

    permit = load_live_execution_permit(permit_ref, env=env)
    return {
        "scope": "transport_probe",
        "profile_id": profile_id,
        "kind": RequestType.METADATA.value,
        "direction": permit.direction,
        "date_from": permit.date_from,
        "date_to": permit.date_to,
    }


def _validated_request(request: LivePermitRequest) -> LivePermitRequest:
    if request.scope not in ALLOWED_SCOPES:
        raise LivePermitError("invalid-scope")
    profile_id = _safe_profile_id(request.profile_id)
    if request.kind != RequestType.METADATA.value:
        raise LivePermitError("metadata-only-required")
    if request.direction not in {DownloadDirection.RECEIVED.value, DownloadDirection.ISSUED.value}:
        raise LivePermitError("invalid-direction")
    _validate_one_day_range(request.date_from, request.date_to)
    if not request.reason.strip():
        raise LivePermitError("reason-required")
    if request.issued_by != "carlos-local":
        raise LivePermitError("invalid-issuer")
    if request.expires_minutes < 1 or request.expires_minutes > MAX_EXPIRES_MINUTES:
        raise LivePermitError("invalid-expiration-window")
    return LivePermitRequest(
        scope=request.scope,
        profile_id=profile_id,
        kind=request.kind,
        direction=request.direction,
        date_from=request.date_from,
        date_to=request.date_to,
        reason=request.reason.strip(),
        expires_minutes=request.expires_minutes,
        issued_by=request.issued_by,
    )


def _validate_document_policy(permit: LiveExecutionPermit, *, now: datetime, repo_root: Path | None) -> None:
    if permit.consumed:
        raise LivePermitError("permit-already-consumed")
    if permit.expires_at <= now:
        raise LivePermitError("permit-expired")
    if permit.max_range_days != MAX_RANGE_DAYS:
        raise LivePermitError("permit-range-policy-invalid")
    if permit.max_attempts != MAX_ATTEMPTS:
        raise LivePermitError("permit-attempt-policy-invalid")
    if permit.kind != RequestType.METADATA.value:
        raise LivePermitError("metadata-only-required")
    _validate_one_day_range(permit.date_from, permit.date_to)
    if permit.allow_real_sat is not True:
        raise LivePermitError("permit-real-sat-not-allowed")
    if permit.scope == "metadata_live_smoke" and permit.allow_real_credentials is not True:
        raise LivePermitError("permit-real-credentials-not-allowed")
    if permit.scope == "transport_probe" and permit.allow_real_credentials is True:
        raise LivePermitError("permit-unneeded-credentials")
    if permit.scope not in ALLOWED_SCOPES:
        raise LivePermitError("invalid-scope")
    if permit.redaction_required is not True:
        raise LivePermitError("permit-redaction-required")
    if permit.repo_root_hash != current_repo_identity(repo_root):
        raise LivePermitError("permit-repo-identity-mismatch")


def _validated_permit_path(path: Path, *, env: Mapping[str, str] | None) -> Path:
    root = permit_root(env=env).resolve()
    resolved = path.expanduser().resolve()
    if not _is_relative_to(resolved, root):
        raise LivePermitError("permit-outside-appdata")
    return resolved


def _ensure_permit_root_outside_repo(root: Path, *, repo_root: Path | None) -> None:
    repo = find_repo_root(_repo_root(repo_root))
    if repo is None:
        return
    try:
        if _is_relative_to(root.resolve(), repo.resolve()):
            raise LivePermitError("permit-root-inside-repo")
    except FileNotFoundError:
        if _is_relative_to(root.absolute(), repo.resolve()):
            raise LivePermitError("permit-root-inside-repo")


def _repo_root(repo_root: Path | None) -> Path:
    return (repo_root or Path.cwd()).resolve()


def _write_permit_document(path: Path, permit: LiveExecutionPermit) -> None:
    path.write_text(json.dumps(permit.to_document(), indent=PERMIT_INDENT, ensure_ascii=False) + "\n", encoding="utf-8")


def _validate_one_day_range(date_from: str, date_to: str) -> None:
    start = _parse_date(date_from)
    end = _parse_date(date_to)
    if end < start:
        raise LivePermitError("invalid-date-range")
    if (end - start).days + 1 > MAX_RANGE_DAYS:
        raise LivePermitError("range-too-wide")


def _parse_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise LivePermitError("invalid-date") from exc


def _safe_profile_id(value: str) -> str:
    try:
        return validate_profile_id(value)
    except SetupError as exc:
        raise LivePermitError("invalid-profile") from exc


def _utc_now(now: datetime | None = None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _format_dt(value: datetime) -> str:
    return _utc_now(value).isoformat().replace("+00:00", "Z")


def _parse_dt(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except ValueError as exc:
        raise LivePermitError("permit-invalid-datetime") from exc


def _optional_dt(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise LivePermitError("permit-invalid-consumed-at")
    return _parse_dt(value)


def _required_str(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise LivePermitError(f"permit-{key}-invalid")
    return value


def _required_bool(document: Mapping[str, object], key: str) -> bool:
    value = document.get(key)
    if not isinstance(value, bool):
        raise LivePermitError(f"permit-{key}-invalid")
    return value


def _required_int(document: Mapping[str, object], key: str) -> int:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise LivePermitError(f"permit-{key}-invalid")
    return value


def _document_key(key: str) -> str:
    return {
        "profile_id": "profileId",
        "date_from": "dateFrom",
        "date_to": "dateTo",
    }.get(key, key)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
