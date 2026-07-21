"""One-shot PostgreSQL-backed SAT VERIFY runner.

The runner owns due-claim orchestration only.  It never submits a request,
downloads a package, opens credentials, or contacts SAT unless the injected
verification adapter is called after a durable database claim.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol
from uuid import uuid4

from cfdi_vault.domain import DownloadQuery
from cfdi_vault.ports import SatRequestPort, SatVerificationPort
from cfdi_vault.recovery_db import SatClaimRecord
from cfdi_vault.sat_campaign_repository import RepositoryBusy, SatCampaignRepository
from cfdi_vault.sat_contract import (
    SatOutcomeAction,
    SatRequestResult,
    SatVerificationError,
    SatVerificationResult,
)

VERIFY_DELAYS = (
    timedelta(minutes=5),
    timedelta(minutes=15),
    timedelta(minutes=30),
    timedelta(hours=1),
    timedelta(hours=2),
    timedelta(hours=4),
    timedelta(hours=8),
)
_SAFE_CODE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


class Clock(Protocol):
    """Return the current timezone-aware UTC time."""

    def __call__(self) -> datetime:
        """Return now."""


@dataclass(frozen=True)
class SatRunnerReport:
    """Sanitized aggregate outcome for one bounded runner invocation."""

    claimed_count: int
    contacted_count: int
    categories: dict[str, int]
    package_count: int
    next_due_at: datetime | None
    submitted_count: int = 0
    submission_categories: dict[str, int] | None = None
    busy: bool = False
    error: str | None = None

    def as_safe_dict(self) -> dict[str, object]:
        """Serialize the aggregate without request or package identifiers."""

        next_check_at = self.next_due_at.isoformat() if self.next_due_at else None
        if self.busy:
            status = "busy"
        elif self.error:
            status = "error"
        elif self.submitted_count or self.contacted_count or self.categories or self.submission_categories:
            status = "processed"
        else:
            status = "no_due_operations"

        return {
            "status": status,
            "claimed_count": self.claimed_count,
            "contacted_count": self.contacted_count,
            "categories": dict(self.categories),
            "package_count": self.package_count,
            "next_due_at": next_check_at,
            # The CLI contract calls this field next_check_at.  Keep the
            # internal next_due_at name above for callers using the report
            # model, but expose both names in the sanitized boundary.
            "next_check_at": next_check_at,
            "submitted_count": self.submitted_count,
            "submission_categories": dict(self.submission_categories or {}),
            "busy": self.busy,
            "error": self.error,
        }


def next_local_check(scheduled_at: datetime, completed_attempts: int) -> datetime:
    """Return the deterministic local schedule after a VERIFY attempt.

    ``completed_attempts=0`` represents the first contact at five minutes;
    subsequent intervals are 15m, 30m, 1h, 2h, 4h, then 8h forever.
    """

    attempt = max(0, int(completed_attempts))
    index = min(attempt, len(VERIFY_DELAYS) - 1)
    return _utc(scheduled_at) + VERIFY_DELAYS[index]


class SatCampaignRunner:
    """Claim and verify due requests using PostgreSQL as durable truth."""

    def __init__(
        self,
        repository: SatCampaignRepository,
        verifier_factory: Callable[[str], SatVerificationPort],
        *,
        downloader_factory: Callable[[str], object] | None = None,
        artifact_coordinator: object | None = None,
        submitter_factory: Callable[[DownloadQuery], SatRequestPort] | None = None,
        query_factory: Callable[[object], DownloadQuery] | None = None,
        grant_ref: str | None = None,
        package_kind: str = "metadata_zip",
        campaign_ref: str | None = None,
        clock: Clock | None = None,
        worker_ref: str | None = None,
    ) -> None:
        self._repository = repository
        self._verifier_factory = verifier_factory
        self._downloader_factory = downloader_factory
        self._artifact_coordinator = artifact_coordinator
        self._submitter_factory = submitter_factory
        self._query_factory = query_factory
        self._grant_ref = grant_ref
        self._package_kind = package_kind
        self._campaign_ref = campaign_ref
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._worker_ref = worker_ref or f"sat-monitor-{uuid4().hex[:16]}"

    def run(self, *, now: datetime | None = None, limit: int = 2,
            lease_seconds: int = 300) -> SatRunnerReport:
        """Process only due requests and return without waiting or retrying.

        The adapter factory is evaluated only after each request has a durable
        VERIFY claim.  Adapter failures are categorized and never create a
        replacement SAT request.
        """

        current = _utc(now or self._clock())
        # A worker that can receive a package must have an external artifact
        # store and a durable parsing handoff *before* any SAT-facing method
        # is reached.  Discovering this after VERIFY would quarantine a
        # perfectly valid package as ``download_uncertain`` and leave the
        # campaign without a safe way to process it.
        self._require_artifact_runtime()
        submitted_count, submission_categories = self._submit_windows(current, limit=min(limit, 2))
        try:
            claims = self._repository.claim_due_operations(
                current, worker_ref=self._worker_ref, limit=min(limit, 2),
                lease_seconds=lease_seconds,
                require_grant=True,
            )
        except RepositoryBusy:
            return SatRunnerReport(
                0, 0, {}, 0, None,
                submitted_count=submitted_count,
                submission_categories=submission_categories,
                busy=True,
            )
        categories: Counter[str] = Counter()
        contacted = 0
        package_count = 0
        for claim in claims:
            category, result, result_code, next_check, count = self._verify_claim(
                claim, current,
            )
            categories[category] += 1
            contacted += 1
            package_count += count
        next_due = self._next_due(current)
        return SatRunnerReport(
            claimed_count=len(claims), contacted_count=contacted,
            categories=dict(categories), package_count=package_count,
            next_due_at=next_due,
            submitted_count=submitted_count,
            submission_categories=submission_categories,
        )

    def _submit_windows(self, current: datetime, *, limit: int) -> tuple[int, dict[str, int]]:
        """Submit planned windows only after a durable grant-bound claim."""

        if self._submitter_factory is None or self._query_factory is None or not self._campaign_ref:
            return 0, {}
        count_open = getattr(self._repository, "count_open_operations", None)
        if callable(count_open):
            open_operations = max(0, int(count_open(self._campaign_ref)))
            limit = min(limit, max(0, 2 - open_operations))
            if limit == 0:
                return 0, {}
        counts: Counter[str] = Counter()
        submitted = 0
        if self._package_kind == "cfdi_zip":
            windows = self._repository.list_submission_windows(
                self._campaign_ref, limit=limit, eligible_only=True,
            )
        else:
            windows = self._repository.list_submission_windows(self._campaign_ref, limit=limit)
        for window in windows:
            claim = None
            try:
                claim = self._repository.claim_operation(
                    campaign_ref=self._campaign_ref,
                    window_ref=window.work_ref,
                    operation_kind="submit",
                    idempotency_key=f"submit:{window.work_ref}",
                    worker_ref=self._worker_ref,
                    now=current,
                    lease_until=current + timedelta(minutes=10),
                    grant_ref=self._grant_ref,
                    require_grant=True,
                )
                if hasattr(claim, "worker_ref") and claim.worker_ref != self._worker_ref:
                    counts["busy"] += 1
                    continue
                query = self._query_factory(window)
                if not isinstance(query, DownloadQuery):
                    raise TypeError("submission query is invalid")
                adapter = self._submitter_factory(query)
                value = adapter.submit_request(query)
                if not isinstance(value, SatRequestResult):
                    raise ValueError("submission adapter returned no result")
                rejected = _submission_rejection(value)
                if rejected is not None:
                    self._repository.record_submission_failure(
                        claim_ref=claim.claim_ref,
                        result_code=rejected,
                        result="error",
                        now=current,
                    )
                    counts[rejected] += 1
                    continue
                if not isinstance(value.request_id, str) or not value.request_id.strip():
                    raise ValueError("submission adapter returned no request")
                self._repository.record_submission(
                    claim_ref=claim.claim_ref,
                    campaign_ref=self._campaign_ref,
                    work_ref=window.work_ref,
                    tenant_id=self._repository.tenant_id_for_campaign(self._campaign_ref),
                    id_solicitud=value.request_id,
                    criteria_hash=query.criteria_hash(),
                    direction=query.direction.value,
                    request_type=query.request_type.value,
                    requested_at=current,
                    next_check_at=current + VERIFY_DELAYS[0],
                    service_window_expires_at=current + timedelta(hours=48),
                    grant_ref=self._grant_ref,
                    now=current,
                )
                submitted += 1
                counts["accepted"] += 1
            except RepositoryBusy:
                counts["busy"] += 1
                break
            except Exception as error:
                if _is_fatal_error(error):
                    raise
                # A timeout/connection reset can happen after SAT accepted
                # the request.  Quarantine the claim instead of allowing a
                # later run to submit a duplicate request.
                uncertain = bool(getattr(error, "effect_unknown", False)) or isinstance(error, TimeoutError)
                category = "uncertain" if uncertain else "error"
                counts[category] += 1
                if claim is not None:
                    self._repository.record_submission_failure(
                        claim_ref=claim.claim_ref,
                        result_code="submission_failed",
                        result="uncertain" if uncertain else "error",
                        now=current,
                    )
        return submitted, dict(counts)

    def _require_artifact_runtime(self) -> None:
        """Reject an incompletely wired package lane before SAT contact."""

        # A submit-only fake or an offline status run does not have a package
        # lane.  Productive worker factories always provide a downloader.
        if self._downloader_factory is None:
            return
        coordinator = self._artifact_coordinator
        if coordinator is None or not callable(getattr(coordinator, "store_package", None)):
            raise RuntimeError("artifact-runtime-required")
        ensure_ready = getattr(coordinator, "ensure_ready", None)
        if callable(ensure_ready):
            try:
                ensure_ready(require_handoff=True)
            except Exception as error:
                reason = getattr(error, "reason", None)
                raise RuntimeError(
                    reason if isinstance(reason, str) and reason else "artifact-runtime-unavailable"
                ) from None


    def _verify_claim(self, claim: SatClaimRecord, current: datetime) -> tuple[
        str, str, str | None, datetime | None, int
    ]:
        if claim.request_id is None:
            raise RuntimeError("verify claim is missing request")
        request = self._repository.get_request(claim.request_id)
        if request is None:
            raise RuntimeError("verify request is missing")
        scheduled_at = _utc(request.next_check_at or claim.claimed_at)
        request_id = request.id_solicitud
        category = "error"
        result = "error"
        result_code: str | None = "verify_adapter_error"
        sat_next: datetime | None = None
        package_count = 0
        contacted_at = _utc(self._clock())
        try:
            verifier = self._verifier_factory(request_id)
            contacted_at = _utc(self._clock())
            value = verifier.verify_request(request_id)
            if not isinstance(value, SatVerificationResult):
                raise TypeError("verification adapter returned an unsupported result")
            if value.request_id and value.request_id != request_id:
                result_code = "request_identity_conflict"
            else:
                category, result, result_code, sat_next, package_count = _classify_result(value)
                if category == "package":
                    try:
                        if self._downloader_factory is None or self._artifact_coordinator is None:
                            raise RuntimeError("artifact-runtime-required")
                        package_count = self._download_packages(request, value.package_ids, current)
                    except _DownloadClaimNotOwned:
                        category = result = "download_uncertain"
                        result_code = "download_claim_in_progress"
                        package_count = 0
                    except Exception as error:
                        if _is_fatal_error(error):
                            raise
                        category = result = "download_uncertain"
                        result_code = "download_uncertain"
                        package_count = 0
        except SatVerificationError as error:
            category, result, result_code, sat_next = _classify_error(error)
        except TimeoutError:
            category = result = "pending"
            result_code = "verify_timeout"
        except Exception as error:
            if _is_fatal_error(error):
                raise
            category = result = "error"
            result_code = "verify_adapter_error"
        if category == "pending":
            next_check = _merge_next_check(
                # Base the minimum interval on the actual contact, not the
                # stale due timestamp.  A delayed one-shot wake must never
                # make the next SAT call immediately due.
                next_local_check(current, request.verify_attempts + 1),
                sat_next, request.service_window_expires_at,
            )
            if next_check is None:
                category = result = "service_window_exceeded"
                result_code = "service_window_exceeded"
        else:
            next_check = None
        self._repository.record_verify_attempt(
            claim_ref=claim.claim_ref, category=category, result=result,
            scheduled_at=scheduled_at, contacted_at=contacted_at,
            next_check_at=next_check, now=current, result_code=_safe_code(result_code),
        )
        return category, result, result_code, next_check, package_count

    def _download_packages(self, request: object, package_ids: tuple[str, ...], current: datetime) -> int:
        if self._artifact_coordinator is None:
            # Do not contact SAT for a package unless durable external
            # storage and the opaque parsing handoff are configured.  The
            # verify result remains auditable as an uncertain download and
            # cannot be retried automatically by a later run.
            raise RuntimeError("artifact-coordinator-required")
        downloaded = 0
        for ordinal, package_id in enumerate(package_ids, start=1):
            request_id = getattr(request, "id", None)
            sat_request_id = getattr(request, "id_solicitud", None)
            work_ref = getattr(request, "work_ref", None)
            campaign_ref = self._campaign_ref
            if not isinstance(request_id, int) or not isinstance(sat_request_id, str) or not isinstance(work_ref, str):
                raise RuntimeError("download request identity unavailable")
            claim = self._repository.claim_operation(
                campaign_ref=campaign_ref or self._campaign_for_request(request_id),
                window_ref=work_ref,
                request_id=request_id,
                operation_kind="download",
                idempotency_key=f"download:{package_id}",
                worker_ref=self._worker_ref,
                now=current,
                lease_until=current + timedelta(minutes=10),
                grant_ref=getattr(request, "grant_ref", None),
                require_grant=getattr(request, "grant_ref", None) is not None,
            )
            if hasattr(claim, "worker_ref") and claim.worker_ref != self._worker_ref:
                raise _DownloadClaimNotOwned
            try:
                downloader = self._downloader_factory(package_id)
                value = downloader.download_package(package_id)
                content = getattr(value, "content", None)
                if not isinstance(content, (bytes, bytearray)):
                    raise RuntimeError("download adapter returned no content")
                self._artifact_coordinator.store_package(
                    campaign_ref=campaign_ref or self._campaign_for_request(request_id),
                    work_ref=work_ref,
                    request_id=request_id,
                    package_ref=package_id,
                    ordinal=ordinal,
                    kind=self._package_kind,
                    chunks=(bytes(content),),
                    max_bytes=512 * 1024 * 1024,
                    claim_ref=claim.claim_ref,
                    now=current,
                )
                downloaded += 1
            except Exception:
                self._repository.record_download_uncertain(claim_ref=claim.claim_ref, now=current)
                raise
        return downloaded

    def _campaign_for_request(self, request_id: int) -> str:
        campaign_ref = self._repository.get_campaign_ref_for_request(request_id)
        if campaign_ref is None:
            raise RuntimeError("request campaign unavailable")
        return campaign_ref

    def _next_due(self, now: datetime) -> datetime | None:
        del now
        if not self._campaign_ref:
            return None
        status = self._repository.get_campaign_status(self._campaign_ref)
        value = status.get("next_check_at") if status else None
        if isinstance(value, datetime):
            return _utc(value)
        if isinstance(value, str) and value:
            try:
                return _utc(datetime.fromisoformat(value))
            except ValueError:
                return None
        return None


def _classify_result(value: SatVerificationResult) -> tuple[str, str, str | None, datetime | None, int]:
    code = str(value.sat_code or "").strip()
    if code == "5004":
        return "no_data", "no_data", code, None, 0
    if code == "5003":
        return "sat_too_many_results", "sat_too_many_results", code, None, 0
    if code == "5005":
        return "duplicate_active_request", "duplicate_active_request", code, None, 0
    if value.action == SatOutcomeAction.EXPIRED or _state(value) == "expired":
        return "expired", "expired", code or "expired", None, 0
    if code == "5000":
        count = len(value.package_ids)
        if count:
            return "package", "package", code, value.next_check_at, count
        return "pending", "pending", code, value.next_check_at, 0
    return "error", "error", code or "verify_error", None, 0


def _classify_error(error: SatVerificationError) -> tuple[str, str, str, datetime | None]:
    code = str(error.code).strip()
    if code == "5004":
        return "no_data", "no_data", code, None
    if code == "5003":
        return "sat_too_many_results", "sat_too_many_results", code, None
    if code == "5005":
        return "duplicate_active_request", "duplicate_active_request", code, None
    if code == "5000":
        return "pending", "pending", code, None
    if code in {"5007", "expired", "request_expired"}:
        return "expired", "expired", code, None
    if error.retryable or code in {"408", "429", "500", "502", "503", "504", "timeout"}:
        return "pending", "pending", _safe_code(code) or "verify_retryable", None
    return "error", "error", _safe_code(code) or "verify_error", None


def _submission_rejection(value: SatRequestResult) -> str | None:
    """Categorize a non-accepted submit result before request persistence."""

    code = str(value.sat_code or "").strip().casefold()
    action = value.action
    if code == "5003":
        return "sat_too_many_results"
    if code == "5004":
        return "no_data"
    if code == "5005" or code in {"duplicate", "duplicate_active_request"}:
        return "duplicate_active_request"
    if action is SatOutcomeAction.DUPLICATE:
        return "duplicate_active_request"
    if action is not SatOutcomeAction.ACCEPTED:
        return "sat_rejected"
    return None


def _merge_next_check(local: datetime, sat: datetime | None,
                      deadline: datetime | None) -> datetime | None:
    candidate = max(_utc(local), _utc(sat)) if sat else _utc(local)
    if deadline is not None and candidate >= _utc(deadline):
        return None
    return candidate


def _safe_code(value: str | None) -> str | None:
    text = str(value or "").strip()
    return text if _SAFE_CODE.fullmatch(text) else "adapter_error"


def _state(value: SatVerificationResult) -> str:
    state = value.state
    return str(getattr(state, "value", state)).strip().lower()


class _DownloadClaimNotOwned(RuntimeError):
    """Another worker already owns the package download claim."""


def _is_fatal_error(error: BaseException) -> bool:
    """Stop a campaign for preflight, identity, or configuration failures."""

    if bool(getattr(error, "fatal_sat", False)):
        return True
    if type(error).__name__ == "SatLiveWorkerRuntimeError":
        return True
    return str(error) in {
        "download request identity unavailable",
        "request campaign unavailable",
        "verification adapter returned an unsupported result",
    }


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
