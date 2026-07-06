"""One-shot SAT verification scheduler for persisted metadata requests."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
from typing import Protocol

from cfdi_vault.domain import SatRequestState
from cfdi_vault.ports import SatVerificationPort
from cfdi_vault.sat_contract import SatOutcomeAction, SatVerificationResult
from cfdi_vault.sat_live_request_state import (
    PACKAGE_READY,
    PENDING_VERIFY_STATUSES,
    VERIFY_EXPIRED,
    VERIFY_FAILED_PERMANENT,
    VERIFY_FAILED_RETRYABLE,
    VERIFY_IN_PROGRESS,
    VERIFY_IN_PROGRESS_SAT,
    VERIFY_NO_DATA,
    VERIFY_REJECTED,
    LiveMetadataRequestRecord,
    format_state_datetime,
    list_live_metadata_requests,
    parse_state_datetime,
    redact_package_ref,
    summarize_live_metadata_requests,
    upsert_live_metadata_request,
)


_NO_DATA_CODES = frozenset({"301", "302", "5003", "5004", "no_data"})
_RETRYABLE_HTTP_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})


class Clock(Protocol):
    def __call__(self) -> datetime:
        """Return the current time."""


@dataclass(frozen=True)
class VerifyBackoffPolicy:
    """Configurable one-shot verification backoff policy."""

    max_attempts: int = 12
    max_age: timedelta = timedelta(hours=72)
    initial_delay: timedelta = timedelta(minutes=5)
    second_delay: timedelta = timedelta(minutes=15)
    third_delay: timedelta = timedelta(minutes=30)
    fourth_delay: timedelta = timedelta(hours=1)
    later_min_delay: timedelta = timedelta(hours=2)
    later_max_delay: timedelta = timedelta(hours=4)

    def next_delay(self, completed_attempts: int, request_ref: str) -> timedelta:
        """Return the delay after the given number of completed attempts."""

        if completed_attempts <= 0:
            return self.initial_delay
        if completed_attempts == 1:
            return self.second_delay
        if completed_attempts == 2:
            return self.third_delay
        if completed_attempts == 3:
            return self.fourth_delay
        jitter_window = max(int((self.later_max_delay - self.later_min_delay).total_seconds()), 0)
        if jitter_window == 0:
            return self.later_min_delay
        digest = hashlib.sha256(f"{request_ref}:{completed_attempts}".encode("utf-8")).hexdigest()
        jitter_seconds = int(digest[:8], 16) % (jitter_window + 1)
        return self.later_min_delay + timedelta(seconds=jitter_seconds)


@dataclass(frozen=True)
class VerifyDueItem:
    """Safe per-request result for one verify-due run."""

    request_ref: str
    status: str
    next_check_at: str
    attempt_count: int
    last_error_kind: str = ""
    package_count: int = 0


@dataclass(frozen=True)
class VerifyDueReport:
    """Safe aggregate result for one one-shot verify worker run."""

    profile_id: str
    dry_run: bool
    due_count: int
    selected_count: int
    processed_count: int
    pending_verify_count: int
    next_due_verification: str
    package_ready_count: int
    failed_requests: int
    items: tuple[VerifyDueItem, ...]


def run_verify_due(
    *,
    storage_root: str,
    profile_id: str,
    verifier: SatVerificationPort,
    limit: int = 1,
    dry_run: bool = False,
    now: datetime | None = None,
    policy: VerifyBackoffPolicy | None = None,
) -> VerifyDueReport:
    """Run at most one bounded batch of due SAT verifications and return."""

    current = _normalize_dt(now or datetime.now(timezone.utc))
    active_policy = policy or VerifyBackoffPolicy()
    records = tuple(record for record in list_live_metadata_requests(storage_root) if record.profile_id == profile_id)
    due_records = _due_records(records, current)
    selected = due_records[:limit]
    if dry_run:
        summary = summarize_live_metadata_requests(records, now=current)
        return VerifyDueReport(
            profile_id=profile_id,
            dry_run=True,
            due_count=len(due_records),
            selected_count=len(selected),
            processed_count=0,
            pending_verify_count=summary.pending_verify_count,
            next_due_verification=summary.next_due_verification,
            package_ready_count=summary.package_ready_count,
            failed_requests=summary.failed_requests,
            items=tuple(_item_from_record(record) for record in selected),
        )

    processed: list[VerifyDueItem] = []
    for record in selected:
        updated = _verify_one(
            storage_root=storage_root,
            record=record,
            verifier=verifier,
            now=current,
            policy=active_policy,
        )
        processed.append(_item_from_record(updated))

    refreshed = tuple(record for record in list_live_metadata_requests(storage_root) if record.profile_id == profile_id)
    summary = summarize_live_metadata_requests(refreshed, now=current)
    return VerifyDueReport(
        profile_id=profile_id,
        dry_run=False,
        due_count=len(due_records),
        selected_count=len(selected),
        processed_count=len(processed),
        pending_verify_count=summary.pending_verify_count,
        next_due_verification=summary.next_due_verification,
        package_ready_count=summary.package_ready_count,
        failed_requests=summary.failed_requests,
        items=tuple(processed),
    )


def _verify_one(
    *,
    storage_root: str,
    record: LiveMetadataRequestRecord,
    verifier: SatVerificationPort,
    now: datetime,
    policy: VerifyBackoffPolicy,
) -> LiveMetadataRequestRecord:
    if _is_expired(record, now, policy):
        return _store(
            storage_root,
            replace(
                record,
                status=VERIFY_EXPIRED,
                next_check_at="",
                last_checked_at=format_state_datetime(now),
                last_error_kind="expired_request",
                updated_at=format_state_datetime(now),
            ),
        )
    if record.attempt_count >= policy.max_attempts:
        return _store(
            storage_root,
            replace(
                record,
                status=VERIFY_FAILED_PERMANENT,
                next_check_at="",
                last_checked_at=format_state_datetime(now),
                last_error_kind="max_attempts_reached",
                updated_at=format_state_datetime(now),
            ),
        )

    in_progress = replace(
        record,
        status=VERIFY_IN_PROGRESS,
        last_checked_at=format_state_datetime(now),
        updated_at=format_state_datetime(now),
    )
    upsert_live_metadata_request(storage_root=storage_root, record=in_progress)
    try:
        result = verifier.verify_request(record.id_solicitud)
    except Exception as exc:  # noqa: BLE001 - boundary converts transport failures into scheduler state.
        return _retry_or_permanent(
            storage_root=storage_root,
            record=in_progress,
            now=now,
            policy=policy,
            error_kind=_error_kind(exc),
            http_status=_http_status(exc),
        )
    return _record_result(storage_root=storage_root, record=in_progress, result=result, now=now, policy=policy)


def _record_result(
    *,
    storage_root: str,
    record: LiveMetadataRequestRecord,
    result: SatVerificationResult,
    now: datetime,
    policy: VerifyBackoffPolicy,
) -> LiveMetadataRequestRecord:
    attempt_count = record.attempt_count + 1
    common = replace(
        record,
        attempt_count=attempt_count,
        last_checked_at=format_state_datetime(now),
        last_error_kind="",
        last_http_status=None,
        sat_estado_solicitud=result.state.value,
        sat_codigo_estado=result.sat_code,
        numero_cfdis=len(result.package_ids),
        updated_at=format_state_datetime(now),
    )

    if result.action == SatOutcomeAction.FINISHED:
        return _store(
            storage_root,
            replace(
                common,
                status=PACKAGE_READY,
                next_check_at="",
                package_refs_redacted=tuple(redact_package_ref(package_id) for package_id in result.package_ids),
            ),
        )
    if _is_no_data(result):
        return _store(storage_root, replace(common, status=VERIFY_NO_DATA, next_check_at=""))
    if result.action == SatOutcomeAction.EXPIRED or result.state == SatRequestState.EXPIRED:
        return _store(storage_root, replace(common, status=VERIFY_EXPIRED, next_check_at="", last_error_kind="expired_request"))
    if result.state == SatRequestState.REJECTED:
        return _store(storage_root, replace(common, status=VERIFY_REJECTED, next_check_at="", last_error_kind="rejected"))
    if result.action == SatOutcomeAction.UNAUTHORIZED:
        return _store(storage_root, replace(common, status=VERIFY_FAILED_PERMANENT, next_check_at="", last_error_kind="unauthorized"))
    if result.action == SatOutcomeAction.PERMANENT_FAILURE:
        return _store(storage_root, replace(common, status=VERIFY_FAILED_PERMANENT, next_check_at="", last_error_kind="permanent_failure"))
    if result.action in {SatOutcomeAction.ACCEPTED, SatOutcomeAction.IN_PROGRESS, SatOutcomeAction.RETRY, SatOutcomeAction.DUPLICATE}:
        if attempt_count >= policy.max_attempts:
            return _store(
                storage_root,
                replace(common, status=VERIFY_FAILED_PERMANENT, next_check_at="", last_error_kind="max_attempts_reached"),
            )
        next_check_at = _next_check_at(common, now, policy)
        status = VERIFY_IN_PROGRESS_SAT if result.action in {SatOutcomeAction.ACCEPTED, SatOutcomeAction.IN_PROGRESS} else VERIFY_FAILED_RETRYABLE
        return _store(storage_root, replace(common, status=status, next_check_at=next_check_at))

    return _store(storage_root, replace(common, status=VERIFY_FAILED_RETRYABLE, next_check_at=_next_check_at(common, now, policy)))


def _retry_or_permanent(
    *,
    storage_root: str,
    record: LiveMetadataRequestRecord,
    now: datetime,
    policy: VerifyBackoffPolicy,
    error_kind: str,
    http_status: int | None,
) -> LiveMetadataRequestRecord:
    attempt_count = record.attempt_count + 1
    status = VERIFY_FAILED_PERMANENT if attempt_count >= policy.max_attempts else VERIFY_FAILED_RETRYABLE
    next_check_at = "" if status == VERIFY_FAILED_PERMANENT else _next_check_at(record, now, policy, completed_attempts=attempt_count)
    if status == VERIFY_FAILED_PERMANENT and error_kind == "transport_timeout":
        error_kind = "max_attempts_reached"
    return _store(
        storage_root,
        replace(
            record,
            status=status,
            attempt_count=attempt_count,
            next_check_at=next_check_at,
            last_checked_at=format_state_datetime(now),
            last_error_kind=error_kind,
            last_http_status=http_status,
            updated_at=format_state_datetime(now),
        ),
    )


def _next_check_at(
    record: LiveMetadataRequestRecord,
    now: datetime,
    policy: VerifyBackoffPolicy,
    *,
    completed_attempts: int | None = None,
) -> str:
    attempts = record.attempt_count if completed_attempts is None else completed_attempts
    next_at = now + policy.next_delay(attempts, record.request_ref)
    expires_at = parse_state_datetime(record.expires_at) if record.expires_at else parse_state_datetime(record.created_at) + policy.max_age
    if next_at > expires_at:
        next_at = expires_at
    return format_state_datetime(next_at)


def _due_records(records: tuple[LiveMetadataRequestRecord, ...], now: datetime) -> tuple[LiveMetadataRequestRecord, ...]:
    due = [record for record in records if record.status in PENDING_VERIFY_STATUSES and record.next_check_at and parse_state_datetime(record.next_check_at) <= now]
    due.sort(key=lambda record: (record.next_check_at, record.created_at, record.request_ref))
    return tuple(due)


def _is_expired(record: LiveMetadataRequestRecord, now: datetime, policy: VerifyBackoffPolicy) -> bool:
    expires_at = parse_state_datetime(record.expires_at) if record.expires_at else parse_state_datetime(record.created_at) + policy.max_age
    return now >= expires_at


def _is_no_data(result: SatVerificationResult) -> bool:
    return str(result.sat_code).strip().lower() in _NO_DATA_CODES


def _store(storage_root: str, record: LiveMetadataRequestRecord) -> LiveMetadataRequestRecord:
    upsert_live_metadata_request(storage_root=storage_root, record=record)
    return record


def _item_from_record(record: LiveMetadataRequestRecord) -> VerifyDueItem:
    return VerifyDueItem(
        request_ref=record.request_ref,
        status=record.status,
        next_check_at=record.next_check_at,
        attempt_count=record.attempt_count,
        last_error_kind=record.last_error_kind,
        package_count=record.numero_cfdis,
    )


def _error_kind(exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return "transport_timeout"
    return "transport_error"


def _http_status(exc: Exception) -> int | None:
    status = getattr(exc, "status_code", None) or getattr(exc, "http_status", None)
    if isinstance(status, int) and status in _RETRYABLE_HTTP_STATUS_CODES:
        return status
    return status if isinstance(status, int) else None


def _normalize_dt(value: datetime) -> datetime:
    normalized = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc)
