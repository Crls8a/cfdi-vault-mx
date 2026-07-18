"""Explicit importer for private JSON state created before PostgreSQL V3."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from cfdi_vault.recovery_db import SatCampaignRecord, SatCampaignWindowRecord, SatGrantRecord, SatRequestRecord

_MAX_BYTES = 4 * 1024 * 1024
_WINDOW_STATUS = {
    "planned": "planned", "outstanding": "reserved", "recovery_linked": "reserved",
    "submitted": "metadata", "completed": "complete", "no_data": "no_data",
    "failed": "failed", "threshold_blocked": "manual_review",
}
_REQUEST_STATUS = {
    "pending": "waiting_verify", "submitted": "submitted", "waiting_verify": "waiting_verify",
    "verify_scheduled": "waiting_verify", "packages_ready": "package", "completed": "package",
    "package": "package", "no_data": "no_data", "failed": "failed", "expired": "expired",
    "pending_after_budget": "service_window_exceeded", "download_uncertain": "uncertain",
    "download_failed": "failed", "verify_failed": "failed",
    "zip_downloaded_pending_processing": "package",
    "uncertain": "uncertain", "service_window_exceeded": "service_window_exceeded",
}
_VERIFY_RESULTS = {
    "pending", "package", "no_data", "error", "expired",
    "duplicate_active_request", "sat_too_many_results",
    "service_window_exceeded", "download_uncertain",
}
_VERIFY_CATEGORIES = _VERIFY_RESULTS
_VERIFY_CODES = {
    "5000", "5003", "5004", "5005", "lease_expired",
    "submit_lease_manual_review", "download_lease_manual_review",
    "download_uncertain", "verify_retryable", "verify_failed",
    "verify_uncertain", "sat_expired", "duplicate_active_request",
}
_LEGACY_CATEGORY_MAP = {
    "timeout": "pending", "verify_retryable": "pending",
    "verify_failed": "error", "verify_uncertain": "error",
}


class LegacyJsonImportError(ValueError):
    """A legacy document cannot be imported without manual review."""

    def __init__(self, reason: str, *, manual_review: bool = True) -> None:
        self.reason = reason
        self.manual_review = manual_review
        super().__init__(reason)


@dataclass(frozen=True)
class LegacyImportResult:
    """Sanitized aggregate result of one import transaction."""

    campaign_ref: str
    windows_imported: int
    requests_imported: int
    attempts_imported: int
    packages_imported: int
    grants_imported: int = 0
    legacy_json: bool = True


def _read_legacy_json(path: str | Path) -> dict[str, Any]:
    """Read one bounded JSON object without echoing its private values."""
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise LegacyJsonImportError("legacy-json-path-invalid")
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise LegacyJsonImportError("legacy-json-unreadable") from exc
    if len(raw) > _MAX_BYTES:
        raise LegacyJsonImportError("legacy-json-too-large")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except LegacyJsonImportError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LegacyJsonImportError("legacy-json-invalid") from exc
    if not isinstance(value, dict):
        raise LegacyJsonImportError("legacy-json-invalid")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LegacyJsonImportError("legacy-json-duplicate-key")
        result[key] = value
    return result


def _legacy_window_status(value: str) -> str:
    return _WINDOW_STATUS.get(value, "manual_review")


def _parse_date(value: Any, field: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise LegacyJsonImportError(f"legacy-{field}-invalid") from exc


def _parse_datetime(value: Any, field: str, *, default: datetime | None = None) -> datetime:
    if value is None:
        if default is not None:
            return default
        raise LegacyJsonImportError(f"legacy-{field}-missing")
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise LegacyJsonImportError(f"legacy-{field}-invalid") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _criteria_hash(value: Any, fallback: str) -> str:
    text = str(value or "")
    if len(text) == 64 and all(char in "0123456789abcdefABCDEF" for char in text):
        return text.lower()
    return hashlib.sha256(fallback.encode("utf-8")).hexdigest()


def _document_digest(value: dict[str, Any]) -> str:
    payload = dict(value)
    supplied = payload.pop("manifestSha256", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if supplied is not None:
        if (not isinstance(supplied, str) or len(supplied) != 64 or
                any(char not in "0123456789abcdefABCDEF" for char in supplied) or
                supplied.lower() != digest):
            raise LegacyJsonImportError("legacy-manifest-digest-conflict")
    return digest


def _parse_int(value: Any, field: str, default: int = 0) -> int:
    if isinstance(value, bool) or isinstance(value, float):
        raise LegacyJsonImportError(f"legacy-{field}-invalid")
    try:
        return default if value is None else int(value)
    except (TypeError, ValueError) as exc:
        raise LegacyJsonImportError(f"legacy-{field}-invalid") from exc


def import_legacy_json(
    session_factory: Any,
    *,
    manifest_path: str | Path | None = None,
    recovery_state_path: str | Path | None = None,
    grant_paths: tuple[str | Path, ...] = (),
    tenant_id: str,
    commit_ref: str,
    now: datetime | None = None,
) -> LegacyImportResult:
    """Import private JSON once; never contacts SAT or deletes source files."""
    paths = [path for path in (manifest_path, recovery_state_path, *grant_paths) if path is not None]
    if not paths:
        raise LegacyJsonImportError("legacy-json-missing")
    documents = [_read_legacy_json(path) for path in paths]
    manifest = documents[0]
    campaign_ref = str(manifest.get("campaignRef") or "")
    if not campaign_ref:
        raise LegacyJsonImportError("legacy-campaign-missing")
    profile_ref = str(manifest.get("profileId") or "legacy-json")
    digest = _document_digest(manifest)
    stamp = now or datetime.now(timezone.utc)
    if not isinstance(manifest.get("items"), list):
        raise LegacyJsonImportError("legacy-items-missing")
    items = manifest["items"]
    recoveries: list[dict[str, Any]] = []
    for document in documents[1:]:
        values = document.get("recoveries", [])
        if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
            raise LegacyJsonImportError("legacy-recoveries-invalid")
        recoveries.extend(values)
    try:
        with session_factory() as session:
            campaign = session.scalar(select(SatCampaignRecord).where(SatCampaignRecord.campaign_ref == campaign_ref))
            if campaign is None:
                campaign = SatCampaignRecord(
                    campaign_ref=campaign_ref, tenant_id=tenant_id, profile_ref=profile_ref,
                    manifest_sha256=digest, commit_ref=commit_ref, phase="metadata-proof",
                    status="planned", max_open_operations=2, budget=max(1, len(items)),
                    created_at=stamp, updated_at=stamp,
                )
                session.add(campaign)
                session.flush()
            elif (campaign.tenant_id, campaign.profile_ref, campaign.manifest_sha256, campaign.commit_ref) != (
                tenant_id, profile_ref, digest, commit_ref
            ):
                raise LegacyJsonImportError("legacy-import-conflict")
            windows = _import_windows(session, campaign, items, stamp)
            grants = _import_grants(session, campaign, documents[1:], stamp)
            requests, attempts, packages = _import_recoveries(session, campaign, windows, recoveries, tenant_id, stamp)
            session.commit()
            return LegacyImportResult(campaign_ref, windows, requests, attempts, packages, grants)
    except SQLAlchemyError as exc:
        raise LegacyJsonImportError("legacy-db-constraint") from exc


def _import_grants(session: Any, campaign: SatCampaignRecord, documents: list[dict[str, Any]], stamp: datetime) -> int:
    imported = 0
    for document in documents:
        raw_grant = document.get("grant")
        if "grant" in document and raw_grant is not None and not isinstance(raw_grant, dict):
            raise LegacyJsonImportError("legacy-grant-invalid")
        value = raw_grant if isinstance(raw_grant, dict) else document
        if not isinstance(value, dict) or not value.get("grantRef"):
            continue
        grant_ref = str(value["grantRef"])
        existing = session.scalar(select(SatGrantRecord).where(SatGrantRecord.grant_ref == grant_ref))
        phase = str(value.get("phase", "metadata-proof"))
        expires_at = _parse_datetime(value.get("expiresAt"), "grant-expires", default=stamp)
        budget = max(1, _parse_int(value.get("budget", 1), "grant-budget", 1))
        if phase not in {"metadata-proof", "cfdi-proof", "continue"}:
            raise LegacyJsonImportError("legacy-grant-invalid")
        if existing is not None:
            if (existing.campaign_id, existing.phase, existing.commit_ref,
                    existing.manifest_sha256, existing.profile_ref, existing.expires_at,
                    existing.budget) != (campaign.id, phase, campaign.commit_ref,
                    campaign.manifest_sha256, campaign.profile_ref, expires_at, budget):
                raise LegacyJsonImportError("legacy-import-conflict")
            continue
        session.add(SatGrantRecord(
            campaign_id=campaign.id, grant_ref=grant_ref, phase=phase,
            manifest_sha256=campaign.manifest_sha256, commit_ref=campaign.commit_ref,
            profile_ref=campaign.profile_ref, reason="legacy_json", budget=budget,
            expires_at=expires_at, created_at=stamp,
        ))
        imported += 1
    return imported


def _import_windows(session: Any, campaign: SatCampaignRecord, items: list[Any], stamp: datetime) -> int:
    from cfdi_vault.sat_legacy_import_windows import import_windows
    return import_windows(
        session, campaign, items, stamp, error_cls=LegacyJsonImportError,
        parse_date=_parse_date, parse_int=_parse_int, status_map=_WINDOW_STATUS,
    )


def _import_recoveries(session: Any, campaign: SatCampaignRecord, windows: int, recoveries: list[dict[str, Any]], tenant_id: str, stamp: datetime) -> tuple[int, int, int]:
    requests = attempts = packages = 0
    window_rows = session.scalars(select(SatCampaignWindowRecord).where(SatCampaignWindowRecord.campaign_id == campaign.id)).all()
    by_ref = {row.work_ref: row for row in window_rows}
    for raw_recovery in recoveries:
        recovery = _normalize_recovery(raw_recovery)
        request_id = str(recovery.get("idSolicitud") or "")
        window = _resolve_window(by_ref, window_rows, recovery)
        if not request_id or window is None:
            raise LegacyJsonImportError("legacy-recovery-invalid")
        requested_at = _parse_datetime(recovery.get("createdAt"), "requested-at", default=stamp)
        deadline = _parse_datetime(recovery.get("serviceWindowExpiresAt") or recovery.get("deadlineAt"), "deadline")
        next_check = recovery.get("nextCheckAt")
        next_at = _parse_datetime(next_check, "next-check") if next_check else None
        existing = session.scalar(select(SatRequestRecord).where(SatRequestRecord.id_solicitud == request_id))
        direction = str(recovery.get("direction", window.direction))
        request_type = str(recovery.get("kind", "Metadata"))
        if direction != window.direction:
            raise LegacyJsonImportError("legacy-recovery-window-conflict")
        if recovery.get("fechaInicial") and _parse_date(recovery["fechaInicial"], "window-start") != window.start_date:
            raise LegacyJsonImportError("legacy-recovery-window-conflict")
        if recovery.get("fechaFinal") and _parse_date(recovery["fechaFinal"], "window-end") != window.end_date:
            raise LegacyJsonImportError("legacy-recovery-window-conflict")
        criteria_hash = _criteria_hash(recovery.get("criteriaHash"), request_id)
        recovery_ref = str(recovery.get("recoveryRef")) if recovery.get("recoveryRef") else None
        mapped_status = _REQUEST_STATUS.get(str(recovery.get("status", "pending")), "uncertain")
        if existing is not None:
            if (existing.campaign_id != campaign.id or existing.tenant_id != tenant_id or
                    existing.window_id != window.id or existing.work_ref != window.work_ref or
                    existing.criteria_hash != criteria_hash or existing.direction != direction or
                    existing.request_type != request_type or existing.requested_at != requested_at or
                    existing.next_check_at != next_at or
                    existing.service_window_expires_at != deadline or
                    existing.recovery_ref != recovery_ref):
                raise LegacyJsonImportError("legacy-import-conflict")
            if ("status" in recovery and
                    existing.sat_state != str(recovery.get("status"))):
                raise LegacyJsonImportError("legacy-import-conflict")
            if ("verifyAttempts" in recovery and
                    existing.verify_attempts != _parse_int(recovery.get("verifyAttempts"), "verify-attempts", 0)):
                raise LegacyJsonImportError("legacy-import-conflict")
            request = existing
        else:
            request = SatRequestRecord(
                tenant_id=tenant_id, id_solicitud=request_id,
                criteria_hash=criteria_hash, direction=direction, request_type=request_type,
                sat_state=str(recovery.get("status", "pending")), requested_at=requested_at,
                campaign_id=campaign.id, window_id=window.id, work_ref=window.work_ref,
                recovery_ref=recovery_ref,
                next_check_at=next_at, service_window_expires_at=deadline,
                status=mapped_status,
                response_summary={"legacy_json": True, "source": "legacy_json"},
            )
            session.add(request)
            session.flush()
            requests += 1
        attempts += _import_history(session, request, campaign.id, recovery.get("verifyHistory", []), stamp)
        artifacts = recovery.get("artifacts", [])
        if not isinstance(artifacts, list):
            raise LegacyJsonImportError("legacy-artifacts-invalid")
        artifact_by_package: dict[str, dict[str, Any]] = {}
        for artifact in artifacts:
            if not isinstance(artifact, dict) or not artifact.get("packageRef"):
                raise LegacyJsonImportError("legacy-artifact-invalid")
            package_ref = str(artifact["packageRef"])
            if package_ref in artifact_by_package:
                raise LegacyJsonImportError("legacy-artifact-duplicate")
            artifact_by_package[package_ref] = artifact
        packages += _import_packages(
            session, request, campaign.id, recovery.get("packages", []), stamp,
            artifact_by_package=artifact_by_package,
        )
    return requests, attempts, packages


def _normalize_recovery(value: dict[str, Any]) -> dict[str, Any]:
    nested = value.get("recovery")
    legacy_ref = nested if isinstance(nested, str) else None
    if not isinstance(nested, dict):
        nested = {}
    merged = dict(nested)
    merged.update(value)
    merged.pop("recovery", None)
    merged["recoveryRef"] = nested.get("recoveryRef") or value.get("recoveryRef") or legacy_ref
    merged["workRef"] = value.get("workRef") or nested.get("workRef")
    merged["packages"] = value.get("packages", nested.get("packages", []))
    merged["verifyHistory"] = value.get("verifyHistory", nested.get("verifyHistory", []))
    merged["artifacts"] = value.get("artifacts", nested.get("artifacts", []))
    return merged


def _resolve_window(by_ref: dict[str, SatCampaignWindowRecord], rows: list[SatCampaignWindowRecord], recovery: dict[str, Any]) -> SatCampaignWindowRecord | None:
    work_ref = recovery.get("workRef")
    if work_ref:
        if str(work_ref) in by_ref:
            return by_ref[str(work_ref)]
        raise LegacyJsonImportError("legacy-window-unresolved")
    recovery_ref = recovery.get("recoveryRef")
    if recovery_ref:
        candidates = [row for row in rows if row.recovery_ref == str(recovery_ref)]
        if len(candidates) != 1:
            raise LegacyJsonImportError("legacy-window-unresolved")
        return candidates[0]
    candidates = []
    if not candidates and recovery.get("fechaInicial") and recovery.get("fechaFinal"):
        start = _parse_date(recovery["fechaInicial"], "window-start")
        end = _parse_date(recovery["fechaFinal"], "window-end")
        candidates = [row for row in rows if row.direction == str(recovery.get("direction", row.direction))
                      and row.start_date == start and row.end_date == end]
    if len(candidates) != 1:
        raise LegacyJsonImportError("legacy-window-unresolved")
    return candidates[0]


def _import_history(session: Any, request: SatRequestRecord, campaign_id: int, values: Any, stamp: datetime) -> int:
    from cfdi_vault.sat_legacy_import_history import import_history
    return import_history(
        session, request, campaign_id, values, stamp, error_cls=LegacyJsonImportError,
        parse_datetime=_parse_datetime, parse_int=_parse_int,
        category_map=_LEGACY_CATEGORY_MAP, categories=_VERIFY_RESULTS, codes=_VERIFY_CODES,
    )


def _import_packages(
    session: Any, request: SatRequestRecord, campaign_id: int, values: Any, stamp: datetime,
    *, artifact_by_package: dict[str, dict[str, Any]],
) -> int:
    from cfdi_vault.sat_legacy_import_packages import import_packages
    return import_packages(
        session, request, campaign_id, values, stamp,
        error_cls=LegacyJsonImportError, parse_int=_parse_int,
        artifact_by_package=artifact_by_package,
    )
