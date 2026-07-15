"""Local bounded grants for one-shot due SAT verification only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

from cfdi_vault.sat_scheduler_lock import LocalFileLock, SchedulerLockError
from cfdi_vault.setup_core import SetupError, validate_profile_id

GRANT_SCOPE = "sat_due_verify_one"
GRANT_SCHEMA_VERSION = 1
MAX_GRANT_LIFETIME = timedelta(hours=24)
MAX_INVOCATIONS = 288
MAX_ATTEMPTS_PER_REQUEST = 12
GRANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


class SchedulerGrantError(ValueError):
    """Raised when a scheduler grant is missing, invalid, or exhausted."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class SchedulerGrant:
    """Bounded authority for due verification, never broader SAT work."""

    grant_id: str
    profile_id: str
    repo_scope: str
    created_at: datetime
    expires_at: datetime
    max_invocations: int
    consumed_invocations: int
    path: Path
    scope: str = GRANT_SCOPE
    max_attempts_per_request: int = MAX_ATTEMPTS_PER_REQUEST
    allow_create_request: bool = False
    allow_download: bool = False
    allow_xml: bool = False
    allow_pdf: bool = False
    redaction_required: bool = True

    def to_document(self) -> dict[str, object]:
        """Return the non-secret persisted grant document."""

        return {
            "schemaVersion": GRANT_SCHEMA_VERSION,
            "grantId": self.grant_id,
            "scope": self.scope,
            "profileId": self.profile_id,
            "repoScope": self.repo_scope,
            "createdAt": _format_dt(self.created_at),
            "expiresAt": _format_dt(self.expires_at),
            "maxInvocations": self.max_invocations,
            "consumedInvocations": self.consumed_invocations,
            "maxAttemptsPerRequest": self.max_attempts_per_request,
            "allowCreateRequest": self.allow_create_request,
            "allowDownload": self.allow_download,
            "allowXml": self.allow_xml,
            "allowPdf": self.allow_pdf,
            "redactionRequired": self.redaction_required,
        }


def scheduler_grant_root(storage_root: str | Path) -> Path:
    """Return the local scheduler grant folder inside profile storage."""

    return Path(storage_root).expanduser() / "state" / "scheduler-grants"


def create_scheduler_grant(
    *,
    storage_root: str | Path,
    profile_id: str,
    repo_root: str | Path,
    max_invocations: int,
    expires_in: timedelta,
    now: datetime | None = None,
) -> SchedulerGrant:
    """Create one bounded local grant without enabling live CLI execution."""

    safe_profile = _profile_id(profile_id)
    if not 1 <= max_invocations <= MAX_INVOCATIONS:
        raise SchedulerGrantError("scheduler-grant-invocations-invalid")
    if expires_in <= timedelta(0) or expires_in > MAX_GRANT_LIFETIME:
        raise SchedulerGrantError("scheduler-grant-expiry-invalid")
    created = _utc_now(now)
    grant_id = secrets.token_urlsafe(12)
    root = scheduler_grant_root(storage_root)
    path = root / f"scheduler-grant-{grant_id}.json"
    grant = SchedulerGrant(
        grant_id=grant_id,
        profile_id=safe_profile,
        repo_scope=_repo_scope(repo_root),
        created_at=created,
        expires_at=created + expires_in,
        max_invocations=max_invocations,
        consumed_invocations=0,
        path=path,
    )
    root.mkdir(parents=True, exist_ok=True)
    _write_exclusive(path, grant.to_document())
    return grant


def load_scheduler_grant(storage_root: str | Path, grant_ref: str | Path) -> SchedulerGrant:
    """Load one grant constrained to the configured local grant root."""

    path = _grant_path(storage_root, grant_ref)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SchedulerGrantError("scheduler-grant-not-found") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise SchedulerGrantError("scheduler-grant-invalid") from exc
    if not isinstance(document, Mapping) or document.get("schemaVersion") != GRANT_SCHEMA_VERSION:
        raise SchedulerGrantError("scheduler-grant-invalid")
    try:
        return SchedulerGrant(
            grant_id=_required_str(document, "grantId"),
            scope=_required_str(document, "scope"),
            profile_id=_required_str(document, "profileId"),
            repo_scope=_required_str(document, "repoScope"),
            created_at=_parse_dt(_required_str(document, "createdAt")),
            expires_at=_parse_dt(_required_str(document, "expiresAt")),
            max_invocations=_required_int(document, "maxInvocations"),
            consumed_invocations=_required_int(document, "consumedInvocations"),
            max_attempts_per_request=_required_int(document, "maxAttemptsPerRequest"),
            allow_create_request=_required_bool(document, "allowCreateRequest"),
            allow_download=_required_bool(document, "allowDownload"),
            allow_xml=_required_bool(document, "allowXml"),
            allow_pdf=_required_bool(document, "allowPdf"),
            redaction_required=_required_bool(document, "redactionRequired"),
            path=path,
        )
    except (TypeError, ValueError) as exc:
        if isinstance(exc, SchedulerGrantError):
            raise
        raise SchedulerGrantError("scheduler-grant-invalid") from exc


def claim_scheduler_grant(
    *,
    storage_root: str | Path,
    grant_ref: str | Path,
    profile_id: str,
    repo_root: str | Path,
    now: datetime | None = None,
) -> SchedulerGrant:
    """Atomically consume one invocation after validating exact authority."""

    path = _grant_path(storage_root, grant_ref)
    try:
        with LocalFileLock(path.with_suffix(".claim.lock"), now=now):
            grant = load_scheduler_grant(storage_root, grant_ref)
            _validate_grant(grant, profile_id=profile_id, repo_root=repo_root, now=_utc_now(now))
            claimed = replace(grant, consumed_invocations=grant.consumed_invocations + 1)
            _write_atomic(path, claimed.to_document())
            return claimed
    except SchedulerLockError as exc:
        raise SchedulerGrantError("scheduler-grant-claim-busy") from exc


def _validate_grant(
    grant: SchedulerGrant,
    *,
    profile_id: str,
    repo_root: str | Path,
    now: datetime,
) -> None:
    if grant.scope != GRANT_SCOPE:
        raise SchedulerGrantError("scheduler-grant-scope-mismatch")
    if grant.profile_id != _profile_id(profile_id):
        raise SchedulerGrantError("scheduler-grant-profile-mismatch")
    if grant.repo_scope != _repo_scope(repo_root):
        raise SchedulerGrantError("scheduler-grant-repo-mismatch")
    if grant.created_at > now or grant.created_at >= grant.expires_at:
        raise SchedulerGrantError("scheduler-grant-window-invalid")
    if grant.expires_at - grant.created_at > MAX_GRANT_LIFETIME:
        raise SchedulerGrantError("scheduler-grant-lifetime-invalid")
    if grant.expires_at <= now:
        raise SchedulerGrantError("scheduler-grant-expired")
    if grant.max_invocations < 1 or grant.max_invocations > MAX_INVOCATIONS:
        raise SchedulerGrantError("scheduler-grant-policy-invalid")
    if grant.consumed_invocations < 0 or grant.consumed_invocations > grant.max_invocations:
        raise SchedulerGrantError("scheduler-grant-policy-invalid")
    if grant.consumed_invocations == grant.max_invocations:
        raise SchedulerGrantError("scheduler-grant-exhausted")
    if grant.max_attempts_per_request != MAX_ATTEMPTS_PER_REQUEST:
        raise SchedulerGrantError("scheduler-grant-policy-invalid")
    if any((grant.allow_create_request, grant.allow_download, grant.allow_xml, grant.allow_pdf)):
        raise SchedulerGrantError("scheduler-grant-authority-invalid")
    if grant.redaction_required is not True:
        raise SchedulerGrantError("scheduler-grant-authority-invalid")


def _grant_path(storage_root: str | Path, grant_ref: str | Path) -> Path:
    raw = str(grant_ref).strip()
    if not raw:
        raise SchedulerGrantError("scheduler-grant-required")
    root = scheduler_grant_root(storage_root).resolve()
    path = root / f"scheduler-grant-{raw}.json" if GRANT_ID_PATTERN.fullmatch(raw) else Path(raw).expanduser()
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise SchedulerGrantError("scheduler-grant-outside-storage")
    return resolved


def _repo_scope(repo_root: str | Path) -> str:
    normalized = str(Path(repo_root).expanduser().resolve()).replace("\\", "/").casefold()
    return f"repo-{hashlib.sha256(normalized.encode('utf-8')).hexdigest()[:24]}"


def _profile_id(value: str) -> str:
    try:
        return validate_profile_id(value)
    except SetupError as exc:
        raise SchedulerGrantError("scheduler-grant-profile-invalid") from exc


def _write_exclusive(path: Path, document: Mapping[str, object]) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError as exc:
        raise SchedulerGrantError("scheduler-grant-write-failed") from exc


def _write_atomic(path: Path, document: Mapping[str, object]) -> None:
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}")
    try:
        temp.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temp, path)
    except OSError as exc:
        temp.unlink(missing_ok=True)
        raise SchedulerGrantError("scheduler-grant-write-failed") from exc


def _required_str(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise SchedulerGrantError("scheduler-grant-invalid")
    return value


def _required_int(document: Mapping[str, object], key: str) -> int:
    value = document.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise SchedulerGrantError("scheduler-grant-invalid")
    return value


def _required_bool(document: Mapping[str, object], key: str) -> bool:
    value = document.get(key)
    if not isinstance(value, bool):
        raise SchedulerGrantError("scheduler-grant-invalid")
    return value


def _parse_dt(value: str) -> datetime:
    try:
        return _utc_now(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError as exc:
        raise SchedulerGrantError("scheduler-grant-invalid") from exc


def _format_dt(value: datetime) -> str:
    return _utc_now(value).isoformat().replace("+00:00", "Z")


def _utc_now(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    aware = current if current.tzinfo is not None else current.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc)
