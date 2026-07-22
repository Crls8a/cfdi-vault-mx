"""Internal PostgreSQL repository for durable SAT campaign state.

Owns short transactions and sanitized claims; never contacts SAT or stores
transport responses or artifact payloads.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import and_, exists, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased

from cfdi_vault.recovery_db import (
    SatArtifactRecord,
    SatCampaignRecord,
    SatCampaignWindowRecord,
    SatClaimRecord,
    SatMetadataImportRecord,
    SatMonitorRunRecord,
    SatPackageRecord,
    SatRequestRecord,
    SatVerifyAttemptRecord,
)
from cfdi_vault.sat_campaign_repository_campaign import SatCampaignRepositoryCampaignMixin
from cfdi_vault.sat_campaign_repository_constants import (
    REQUEST_STATUS,
    VERIFY_RESULTS,
    ClaimAlreadyCompleted,
    RepositoryBusy,
)
from cfdi_vault.sat_campaign_repository_helpers import SatCampaignRepositoryHelpers
from cfdi_vault.sat_campaign_repository_status import SatCampaignStatusMixin


class SatCampaignRepository(SatCampaignRepositoryCampaignMixin, SatCampaignStatusMixin, SatCampaignRepositoryHelpers):
    """Persist campaign state in independent SQLAlchemy transactions; no network calls."""
    def __init__(self, session_factory: Any) -> None:
        self._session_factory = session_factory

    def get_request(self, request_id: int) -> SatRequestRecord | None:
        """Return one request snapshot for an already persisted claim.

        The returned record is detached when the short read transaction closes;
        callers must treat it as a snapshot and never mutate it directly.
        """

        with self._session_factory() as session:
            return session.get(SatRequestRecord, request_id)

    def get_next_due_at(self, *, now: datetime | None = None) -> datetime | None:
        """Return the earliest durable VERIFY schedule, if one exists.

        ``now`` is accepted so callers can use one clock snapshot for the
        wait decision and the subsequent claim. PostgreSQL remains the source
        of truth; this read never marks work as due or contacts SAT.
        """

        del now
        with self._session_factory() as session:
            effective_due = func.least(
                SatRequestRecord.next_check_at, SatRequestRecord.service_window_expires_at,
            )
            return session.scalar(select(func.min(effective_due)).where(
                SatRequestRecord.status.in_(("submitted", "waiting_verify")),
                or_(
                    SatRequestRecord.next_check_at.is_not(None),
                    SatRequestRecord.service_window_expires_at.is_not(None),
                ),
            ))

    def record_monitor_run(
        self, *, started_at: datetime, finished_at: datetime, wake_reason: str,
        due_count: int, contacted_count: int, package_count: int = 0,
        no_data_count: int = 0, error_count: int = 0,
        terminal_category: str | None = None, duration_ms: int,
        watchdog_wake: bool = False, now: datetime | None = None,
    ) -> SatMonitorRunRecord:
        """Append one sanitized monitor-cycle aggregate in a short transaction."""

        if finished_at < started_at:
            raise ValueError("monitor run finished before it started")
        if wake_reason not in {"startup", "schedule_changed", "watchdog", "reconnect", "manual", "unknown"}:
            raise ValueError("monitor wake reason is invalid")
        counts = (due_count, contacted_count, package_count, no_data_count, error_count, duration_ms)
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError("monitor run counts are invalid")
        if terminal_category is not None and (
            not terminal_category or len(terminal_category) > 32
            or not all(char.islower() or char.isdigit() or char in ".-_" for char in terminal_category)
            or not terminal_category[0].islower()
        ):
            raise ValueError("monitor terminal category is invalid")
        stamp = now or finished_at
        with self._session_factory() as session:
            record = SatMonitorRunRecord(
                run_ref=f"monitor-run-{uuid4().hex}", started_at=started_at,
                finished_at=finished_at, wake_reason=wake_reason, due_count=due_count,
                contacted_count=contacted_count, package_count=package_count,
                no_data_count=no_data_count, error_count=error_count,
                terminal_category=terminal_category, duration_ms=duration_ms,
                watchdog_wake=bool(watchdog_wake), created_at=stamp,
            )
            session.add(record)
            session.commit()
            return record

    def get_monitor_status(self) -> dict[str, object]:
        """Return only aggregate monitor history; never expose transport data."""

        with self._session_factory() as session:
            totals = session.execute(select(
                func.count(SatMonitorRunRecord.id),
                func.coalesce(func.sum(SatMonitorRunRecord.due_count), 0),
                func.coalesce(func.sum(SatMonitorRunRecord.contacted_count), 0),
                func.coalesce(func.sum(SatMonitorRunRecord.package_count), 0),
                func.coalesce(func.sum(SatMonitorRunRecord.no_data_count), 0),
                func.coalesce(func.sum(SatMonitorRunRecord.error_count), 0),
            )).one()
            latest = session.scalar(select(SatMonitorRunRecord).order_by(
                SatMonitorRunRecord.started_at.desc(), SatMonitorRunRecord.id.desc(),
            ).limit(1))
            return {
                "total_runs": int(totals[0] or 0), "due_count": int(totals[1] or 0),
                "contacted_count": int(totals[2] or 0), "package_count": int(totals[3] or 0),
                "no_data_count": int(totals[4] or 0), "error_count": int(totals[5] or 0),
                "last_wake_reason": latest.wake_reason if latest else None,
                "last_terminal_category": latest.terminal_category if latest else None,
                "last_watchdog_wake": latest.watchdog_wake if latest else None,
            }

    def get_claim(self, claim_ref: str) -> SatClaimRecord | None:
        """Return one detached claim snapshot for an already durable claim."""

        with self._session_factory() as session:
            return session.scalar(select(SatClaimRecord).where(SatClaimRecord.claim_ref == claim_ref))

    def get_campaign_ref_for_request(self, request_id: int) -> str | None:
        with self._session_factory() as session:
            request = session.get(SatRequestRecord, request_id)
            if request is None:
                return None
            campaign = session.get(SatCampaignRecord, request.campaign_id)
            return campaign.campaign_ref if campaign is not None else None

    def tenant_id_for_campaign(self, campaign_ref: str) -> str:
        """Return the tenant bound to a campaign for internal request lineage."""

        with self._session_factory() as session:
            return self._campaign(session, campaign_ref).tenant_id

    def get_request_for_work(
        self, campaign_ref: str, work_ref: str, *, request_type: str = "metadata",
    ) -> SatRequestRecord | None:
        """Return the durable request linked to one campaign window."""

        with self._session_factory() as session:
            campaign = self._campaign(session, campaign_ref)
            return session.scalar(select(SatRequestRecord).where(
                SatRequestRecord.campaign_id == campaign.id,
                SatRequestRecord.work_ref == work_ref,
                SatRequestRecord.request_type == request_type,
            ))

    def count_open_operations(self, campaign_ref: str) -> int:
        """Count durable SAT operations that still occupy campaign capacity.

        Submitted requests remain open until SAT returns a terminal result. An
        unbound submit claim is also counted because its external effect may
        still be in flight. This prevents a later one-shot wake from opening
        replacement requests after the original request's submit claim has
        already been completed.
        """

        open_request_statuses = (
            "outstanding", "recovery_linked", "submitted", "waiting_verify",
            "package", "uncertain",
        )
        with self._session_factory() as session:
            campaign = self._campaign(session, campaign_ref)
            request_count = session.scalar(select(func.count(SatRequestRecord.id)).where(
                SatRequestRecord.campaign_id == campaign.id,
                SatRequestRecord.status.in_(open_request_statuses),
            ))
            unbound_claim_count = session.scalar(select(func.count(SatClaimRecord.id)).where(
                SatClaimRecord.campaign_id == campaign.id,
                SatClaimRecord.operation_kind == "submit",
                SatClaimRecord.request_id.is_(None),
                SatClaimRecord.active.is_(True),
            ))
            return int(request_count or 0) + int(unbound_claim_count or 0)

    def list_submission_windows(
        self, campaign_ref: str, *, limit: int = 2, eligible_only: bool = False,
    ) -> tuple[SatCampaignWindowRecord, ...]:
        """Return the next windows that have no persisted SAT request.

        The read is intentionally short and only selects windows in the
        campaign's planned/reserved state for a new Metadata request.  The
        CFDI lane may additionally select a ``metadata`` window after the
        worker has persisted eligible Metadata evidence.  A caller must still
        reserve a submit claim before invoking an external adapter.
        """

        with self._session_factory() as session:
            campaign = self._campaign(session, campaign_ref)
            requests = select(SatRequestRecord.window_id).where(
                SatRequestRecord.campaign_id == campaign.id,
            )
            conditions = [
                    SatCampaignWindowRecord.campaign_id == campaign.id,
                    SatCampaignWindowRecord.status.in_(("planned", "reserved")),
                    ~SatCampaignWindowRecord.id.in_(requests),
            ]
            if eligible_only:
                # Metadata submission has already created a request for this
                # window.  CFDI follow-up must exclude only an existing CFDI
                # request, while retaining the original planned/reserved
                # compatibility path used by synthetic campaign setup.
                cfdi_requests = select(SatRequestRecord.id).where(
                    SatRequestRecord.campaign_id == campaign.id,
                    SatRequestRecord.window_id == SatCampaignWindowRecord.id,
                    func.lower(SatRequestRecord.request_type) == "cfdi",
                )
                conditions[1] = or_(
                    conditions[1], SatCampaignWindowRecord.status == "metadata",
                )
                conditions[2] = ~exists(cfdi_requests)
                latest_import = aliased(SatMetadataImportRecord)
                eligible_import = select(SatMetadataImportRecord.id).join(
                    SatArtifactRecord, SatArtifactRecord.id == SatMetadataImportRecord.artifact_id,
                ).where(
                    SatMetadataImportRecord.campaign_id == campaign.id,
                    SatMetadataImportRecord.window_id == SatCampaignWindowRecord.id,
                    SatMetadataImportRecord.encoding == "utf-8-sig",
                    SatMetadataImportRecord.delimiter == "~",
                    SatMetadataImportRecord.header_compatible.is_(True),
                    SatMetadataImportRecord.record_count > 0,
                    SatMetadataImportRecord.eligible_count > 0,
                    SatArtifactRecord.window_id == SatMetadataImportRecord.window_id,
                    SatArtifactRecord.kind.in_(("metadata_zip", "metadata_txt")),
                    SatArtifactRecord.validation_status.in_(("valid", "processed")),
                    ~exists(select(latest_import.id).where(
                        latest_import.campaign_id == SatMetadataImportRecord.campaign_id,
                        latest_import.window_id == SatMetadataImportRecord.window_id,
                        or_(
                            latest_import.created_at > SatMetadataImportRecord.created_at,
                            and_(
                                latest_import.created_at == SatMetadataImportRecord.created_at,
                                latest_import.id > SatMetadataImportRecord.id,
                            ),
                        ),
                    )),
                )
                conditions.append(exists(eligible_import))
            rows = session.scalars(select(SatCampaignWindowRecord).where(
                    *conditions,
                ).order_by(
                    SatCampaignWindowRecord.start_date,
                    SatCampaignWindowRecord.id,
                ).limit(min(max(limit, 0), 2))
            ).all()
            return tuple(rows)

    def record_submission_failure(
        self, *, claim_ref: str, result_code: str, now: datetime | None = None,
        result: str = "error",
    ) -> None:
        """Close a submit claim after a categorized adapter failure."""

        if result not in {"error", "uncertain"}:
            raise ValueError("unsupported submission result")
        stamp = now or datetime.now(timezone.utc)
        with self._session_factory() as session:
            claim = self._claim(session, claim_ref)
            if claim.operation_kind != "submit":
                raise ValueError("claim is not a submission")
            if claim.active:
                self._finish_claim(claim, stamp, result, result_code)
                window = session.get(SatCampaignWindowRecord, claim.window_id)
                if window is not None:
                    window.status = "manual_review"
                campaign = session.get(SatCampaignRecord, claim.campaign_id)
                if campaign is not None:
                    campaign.updated_at = stamp
                session.commit()
    def claim_operation(self, *, campaign_ref: str, idempotency_key: str, operation_kind: str,
                        worker_ref: str, now: datetime, lease_until: datetime,
                        window_ref: str | None = None, request_id: int | None = None,
                        grant_ref: str | None = None, require_grant: bool = False) -> SatClaimRecord:
        with self._session_factory() as session:
            self._close_expired_claims(session, now)
            # Persist lease expiry/quarantine before any later validation can raise.
            session.commit()
            if lease_until <= now:
                raise ValueError("claim lease must be in the future")
            campaign = self._campaign(session, campaign_ref)
            window = self._window(session, campaign.id, window_ref) if window_ref else None
            grant = None
            if grant_ref is not None:
                grant = self._grant(session, campaign.id, grant_ref, now)
                if grant.phase not in {"metadata-proof", "cfdi-proof", "continue"}:
                    raise ValueError("claim grant phase is invalid")
            elif require_grant and operation_kind in {"submit", "verify", "download"}:
                raise ValueError("external claim requires grant")
            if operation_kind == "submit" and request_id is not None:
                raise ValueError("submit claim cannot have a request")
            if operation_kind != "submit" and request_id is None:
                raise ValueError("non-submit claim requires a request")
            if request_id is not None:
                request = session.scalar(select(SatRequestRecord).where(
                    SatRequestRecord.id == request_id, SatRequestRecord.campaign_id == campaign.id,
                ))
                if request is None:
                    raise ValueError("request does not belong to campaign")
                if window is None and request.window_id is not None:
                    raise ValueError("request window is required")
                if window is not None and request.window_id != window.id:
                    raise ValueError("request does not belong to window")
            existing = session.scalar(select(SatClaimRecord).where(
                SatClaimRecord.campaign_id == campaign.id,
                SatClaimRecord.idempotency_key == idempotency_key,
            ))
            if existing:
                expected_grant_ref = grant.grant_ref if grant is not None else None
                if (existing.operation_kind, existing.window_id, existing.request_id,
                        existing.grant_ref) != (
                    operation_kind, window.id if window else None, request_id,
                    expected_grant_ref,
                ):
                    raise ValueError("claim identity conflict")
                if (not existing.active or existing.completed_at is not None or
                        existing.lease_until <= now or existing.result in ("uncertain", "lease_expired")):
                    raise ClaimAlreadyCompleted("claim is terminal or expired")
                return existing
            if operation_kind == "submit":
                quarantined = session.scalar(select(SatClaimRecord).where(
                    SatClaimRecord.campaign_id == campaign.id,
                    SatClaimRecord.window_id == (window.id if window else None),
                    SatClaimRecord.operation_kind == "submit",
                    SatClaimRecord.result == "uncertain",
                ))
                if quarantined is not None:
                    raise RepositoryBusy("submit claim requires manual review")
            if operation_kind == "download":
                quarantined = session.scalar(select(SatClaimRecord).where(
                    SatClaimRecord.campaign_id == campaign.id,
                    SatClaimRecord.window_id == (window.id if window else None),
                    SatClaimRecord.request_id == request_id,
                    SatClaimRecord.operation_kind == "download",
                    SatClaimRecord.result == "uncertain",
                ))
                if quarantined is not None:
                    raise ClaimAlreadyCompleted("download requires manual review")
            slots = set(session.scalars(select(SatClaimRecord.operation_slot).where(
                SatClaimRecord.campaign_id == campaign.id, SatClaimRecord.active.is_(True),
            ).with_for_update()).all())
            slot = next((value for value in (1, 2) if value not in slots), None)
            if slot is None:
                raise RepositoryBusy("campaign operation slots are full")
            claim = SatClaimRecord(claim_ref=f"claim-{uuid4().hex}", campaign_id=campaign.id,
                window_id=window.id if window else None, request_id=request_id,
                grant_ref=grant.grant_ref if grant is not None else None,
                operation_kind=operation_kind, idempotency_key=idempotency_key,
                operation_slot=slot, worker_ref=worker_ref, claimed_at=now,
                lease_until=lease_until, active=True)
            session.add(claim)
            try:
                session.commit()
            except IntegrityError as error:
                session.rollback()
                # A slot conflict must not roll back the lease cleanup that
                # made the slot available.  Persist it in a fresh transaction
                # before reporting contention to the caller.
                with self._session_factory() as cleanup_session:
                    self._close_expired_claims(cleanup_session, now)
                    cleanup_session.commit()
                raise RepositoryBusy("campaign operation slots are full") from error
            return claim
    def claim_due_operations(self, now: datetime, *, worker_ref: str = "sat-monitor",
                             limit: int = 2, lease_seconds: int = 300,
                             require_grant: bool = False) -> tuple[SatClaimRecord, ...]:
        limit = min(limit, 2)
        if limit < 1:
            return ()
        if lease_seconds <= 0:
            raise ValueError("lease must be positive")
        with self._session_factory() as session:
            self._close_expired_claims(session, now)
            session.execute(update(SatRequestRecord).where(
                SatRequestRecord.status.in_(("submitted", "waiting_verify")),
                SatRequestRecord.service_window_expires_at.is_not(None),
                SatRequestRecord.service_window_expires_at <= now,
            ).values(status="service_window_exceeded", sat_state="service_window_exceeded", next_check_at=None))
            active = select(SatClaimRecord.id).where(
                SatClaimRecord.request_id == SatRequestRecord.id,
                SatClaimRecord.active.is_(True),
            )
            request_stmt = select(SatRequestRecord).where(
                SatRequestRecord.status.in_(("submitted", "waiting_verify")),
                (SatRequestRecord.grant_ref.is_not(None) if require_grant else True),
                SatRequestRecord.next_check_at.is_not(None),
                SatRequestRecord.next_check_at <= now,
                (SatRequestRecord.service_window_expires_at.is_(None) |
                 (SatRequestRecord.service_window_expires_at > now)),
                ~active.exists(),
            ).order_by(SatRequestRecord.next_check_at, SatRequestRecord.id).with_for_update(skip_locked=True).limit(
                max(limit * 2, limit)
            )
            requests = session.scalars(request_stmt).all()
            claims: list[SatClaimRecord] = []
            claimed_slots: dict[int, set[int]] = {}
            for request in requests:
                if len(claims) >= limit:
                    break
                campaign = session.get(SatCampaignRecord, request.campaign_id)
                if campaign is None:
                    continue
                if request.grant_ref is not None:
                    try:
                        self._grant(session, campaign.id, request.grant_ref, now)
                    except ValueError:
                        continue
                elif require_grant:
                    # Campaign runners must never contact SAT for a request
                    # that was not bound to the exact human authorization.
                    # Legacy requests remain queryable but require explicit
                    # migration/authorization before they can be resumed.
                    continue
                self._close_expired_claims(session, now, campaign.id)
                slots = set(session.scalars(select(SatClaimRecord.operation_slot).where(
                    SatClaimRecord.campaign_id == campaign.id, SatClaimRecord.active.is_(True),
                ).with_for_update()).all())
                slots.update(claimed_slots.get(campaign.id, set()))
                slot = next((value for value in (1, 2) if value not in slots), None)
                if slot is None:
                    continue
                claim = SatClaimRecord(claim_ref=f"claim-{uuid4().hex}", campaign_id=campaign.id,
                    window_id=request.window_id, request_id=request.id, operation_kind="verify",
                    grant_ref=request.grant_ref,
                    idempotency_key=self._verify_idempotency_key(
                        session, campaign.id, request.id, request.verify_attempts + 1
                    ),
                    operation_slot=slot, worker_ref=worker_ref, claimed_at=now,
                    lease_until=now + timedelta(seconds=lease_seconds), active=True)
                session.add(claim)
                claims.append(claim)
                claimed_slots.setdefault(campaign.id, set()).add(slot)
            try:
                session.commit()
            except IntegrityError as error:
                session.rollback()
                with self._session_factory() as cleanup_session:
                    self._close_expired_claims(cleanup_session, now)
                    cleanup_session.commit()
                raise RepositoryBusy("campaign operation slots are full") from error
            return tuple(claims)
    def record_submission(self, *, claim_ref: str, campaign_ref: str, work_ref: str,
                          tenant_id: str, id_solicitud: str, criteria_hash: str,
                          direction: str, request_type: str, requested_at: datetime,
                          next_check_at: datetime, service_window_expires_at: datetime,
                          grant_ref: str | None = None,
                          now: datetime | None = None) -> SatRequestRecord:
        now = now or requested_at
        with self._session_factory() as session:
            claim = self._claim(session, claim_ref)
            campaign = self._campaign(session, campaign_ref)
            window = self._window(session, campaign.id, work_ref)
            if grant_ref is not None:
                grant = self._grant(session, campaign.id, grant_ref, now)
                if claim.grant_ref not in (None, grant.grant_ref):
                    raise ValueError("submission claim grant mismatch")
                claim.grant_ref = grant.grant_ref
            effective_grant_ref = grant_ref or claim.grant_ref
            if campaign.tenant_id != tenant_id:
                raise ValueError("submission tenant mismatch")
            if requested_at > next_check_at:
                raise ValueError("next check precedes submission")
            if next_check_at > service_window_expires_at:
                raise ValueError("next check exceeds service window")
            if service_window_expires_at > requested_at + timedelta(hours=48):
                raise ValueError("service window exceeds 48 hours")
            if (not claim.active or claim.operation_kind != "submit" or
                    claim.campaign_id != campaign.id or claim.window_id != window.id or
                    claim.lease_until <= now):
                raise ValueError("submission claim mismatch")
            existing = session.scalar(select(SatRequestRecord).where(SatRequestRecord.id_solicitud == id_solicitud))
            if existing:
                if (existing.campaign_id, existing.tenant_id, existing.window_id,
                    existing.work_ref, existing.criteria_hash, existing.direction,
                    existing.request_type, existing.requested_at, existing.next_check_at,
                    existing.service_window_expires_at, existing.grant_ref) != (
                    campaign.id, tenant_id, window.id, work_ref, criteria_hash, direction, request_type
                    , requested_at, next_check_at, service_window_expires_at, effective_grant_ref
                ):
                    raise ValueError("request identity conflict")
                if claim.request_id not in (None, existing.id):
                    raise ValueError("submission claim already bound")
                claim.request_id = existing.id
                if effective_grant_ref is not None:
                    existing.grant_ref = effective_grant_ref
                window.status = "metadata" if request_type.casefold() == "metadata" else "cfdi"
                campaign.phase = "metadata-proof" if request_type.casefold() == "metadata" else "cfdi-proof"
                campaign.status = "running"
                campaign.updated_at = now
                self._finish_claim(claim, now, "pending")
                session.commit()
                return existing
            if claim.request_id is not None:
                raise ValueError("submission claim already bound")
            request = SatRequestRecord(tenant_id=tenant_id, id_solicitud=id_solicitud,
                criteria_hash=criteria_hash, direction=direction, request_type=request_type,
                sat_state="pending", requested_at=requested_at, campaign_id=campaign.id,
                window_id=window.id, work_ref=work_ref, grant_ref=effective_grant_ref,
                next_check_at=next_check_at,
                service_window_expires_at=service_window_expires_at, status="submitted")
            session.add(request)
            session.flush()
            window.status = "metadata" if request_type.casefold() == "metadata" else "cfdi"
            campaign.phase = "metadata-proof" if request_type.casefold() == "metadata" else "cfdi-proof"
            campaign.status = "running"
            campaign.updated_at = now
            claim.request_id = request.id
            self._finish_claim(claim, now, "pending")
            session.commit()
            return request
    def record_verify_attempt(self, *, claim_ref: str, category: str, result: str,
                             scheduled_at: datetime, contacted_at: datetime | None,
                             next_check_at: datetime | None, now: datetime | None = None,
                             result_code: str | None = None) -> SatVerifyAttemptRecord:
        now = now or datetime.now(timezone.utc)
        if result not in VERIFY_RESULTS or category not in VERIFY_RESULTS:
            raise ValueError("unsupported verify result")
        if result == "pending" and next_check_at is None:
            raise ValueError("pending verify requires next check")
        with self._session_factory() as session:
            claim = self._claim(session, claim_ref)
            existing = session.scalar(select(SatVerifyAttemptRecord).where(SatVerifyAttemptRecord.claim_ref == claim_ref))
            if existing:
                if (existing.category, existing.result, existing.next_check_at,
                        existing.scheduled_at, existing.contacted_at, existing.result_code) != (
                        category, result, next_check_at, scheduled_at, contacted_at, result_code):
                    raise ValueError("verify attempt identity conflict")
                return existing
            if not claim.active or claim.operation_kind != "verify" or claim.request_id is None:
                raise ValueError("verify claim is not active")
            if claim.lease_until <= now:
                raise ValueError("claim lease expired")
            request = session.get(SatRequestRecord, claim.request_id)
            if request is None or request.campaign_id != claim.campaign_id:
                raise ValueError("verify request mismatch")
            if (next_check_at is not None and request.service_window_expires_at is not None and
                    next_check_at > request.service_window_expires_at):
                raise ValueError("next check exceeds service window")
            attempt = request.verify_attempts + 1
            record = SatVerifyAttemptRecord(campaign_id=claim.campaign_id, request_id=request.id,
                claim_id=claim.id, attempt=attempt, scheduled_at=scheduled_at,
                contacted_at=contacted_at, category=category, result=result,
                result_code=result_code, next_check_at=next_check_at, claim_ref=claim_ref,
                created_at=now)
            session.add(record)
            session.flush()
            request.verify_attempts = attempt
            request.last_verified_at = contacted_at or now
            request.next_check_at = next_check_at
            request.status = REQUEST_STATUS[result]
            request.sat_state = result
            window = session.get(SatCampaignWindowRecord, request.window_id) if request.window_id else None
            if window is not None:
                if result == "no_data":
                    window.status = "no_data"
                elif result == "expired":
                    window.status = "failed"
                elif result in {"error", "duplicate_active_request", "sat_too_many_results", "service_window_exceeded"}:
                    window.status = "manual_review"
                else:
                    window.status = "metadata" if request.request_type.casefold() == "metadata" else "cfdi"
            campaign = session.get(SatCampaignRecord, request.campaign_id)
            if campaign is not None:
                campaign.updated_at = now
            self._finish_claim(claim, now, "uncertain" if result == "download_uncertain" else result, result_code)
            session.commit()
            return record
    def record_package(self, *, claim_ref: str, id_paquete: str, id_solicitud: str,
                       status: str, now: datetime | None = None, ordinal: int | None = None,
                       artifact_id: int | None = None, download_state: str | None = None) -> SatPackageRecord:
        now = now or datetime.now(timezone.utc)
        with self._session_factory() as session:
            claim = self._claim(session, claim_ref)
            if (not claim.active or claim.operation_kind != "download" or
                    claim.request_id is None or claim.lease_until <= now):
                raise ValueError("download claim mismatch")
            request = session.get(SatRequestRecord, claim.request_id)
            if request is None or request.campaign_id != claim.campaign_id or request.id_solicitud != id_solicitud:
                raise ValueError("package request mismatch")
            if claim.result == "uncertain":
                raise ClaimAlreadyCompleted("download requires manual review")
            if artifact_id is None:
                raise ValueError("package artifact is required")
            artifact = session.scalar(select(SatArtifactRecord).where(
                SatArtifactRecord.id == artifact_id, SatArtifactRecord.campaign_id == claim.campaign_id,
            ))
            if artifact is None or artifact.window_id != claim.window_id:
                raise ValueError("package artifact mismatch")
            if artifact.kind not in {"metadata_zip", "cfdi_zip"}:
                raise ValueError("package artifact kind mismatch")
            state = download_state or {
                "downloaded": "downloaded", "download_uncertain": "download_uncertain",
                "download_failed": "download_failed", "uncertain": "download_uncertain",
            }.get(status, "pending")
            existing = session.scalar(select(SatPackageRecord).where(SatPackageRecord.id_paquete == id_paquete))
            if existing:
                if (existing.tenant_id, existing.campaign_id, existing.id_solicitud,
                        existing.status, existing.artifact_id, existing.ordinal,
                        existing.download_state) != (
                    request.tenant_id, claim.campaign_id, id_solicitud, status,
                    artifact_id, ordinal, state
                ):
                    raise ValueError("package identity conflict")
                self._finish_claim(claim, now, "package")
                session.commit()
                return existing
            package = SatPackageRecord(tenant_id=request.tenant_id, id_paquete=id_paquete,
                id_solicitud=id_solicitud, status=status, attempts=0, created_at=now,
                updated_at=now, campaign_id=claim.campaign_id, window_id=claim.window_id,
                artifact_id=artifact_id, claim_id=claim.id, ordinal=ordinal,
                download_state=state, validation_status="unvalidated")
            session.add(package)
            window = session.get(SatCampaignWindowRecord, claim.window_id) if claim.window_id else None
            if window is not None:
                window.status = "metadata" if request.request_type.casefold() == "metadata" else "cfdi"
            campaign = session.get(SatCampaignRecord, claim.campaign_id)
            if campaign is not None:
                campaign.updated_at = now
            self._finish_claim(claim, now, "uncertain" if status in ("download_uncertain", "uncertain") else "package")
            session.commit()
            return package
    def record_download_uncertain(self, *, claim_ref: str, now: datetime | None = None,
                                  result_code: str = "download_uncertain") -> None:
        """Close a download claim after an external write or DB failure.

        The claim becomes manual-review-only; callers must never retry the
        package automatically after the external effect is uncertain.
        """

        stamp = now or datetime.now(timezone.utc)
        with self._session_factory() as session:
            claim = self._claim(session, claim_ref)
            if claim.operation_kind != "download":
                raise ValueError("claim is not a download")
            if claim.active:
                self._finish_claim(claim, stamp, "uncertain", result_code)
                session.commit()
    def record_artifact(self, *, campaign_ref: str, artifact_ref: str, kind: str,
                        storage_key: str, sha256: str, size_bytes: int,
                        validation_status: str, counts: Mapping[str, object] | None = None,
                        window_ref: str | None = None, now: datetime | None = None) -> SatArtifactRecord:
        now = now or datetime.now(timezone.utc)
        normalized_counts = self._artifact_metadata(
            kind=kind, storage_key=storage_key, sha256=sha256, size_bytes=size_bytes,
            validation_status=validation_status, counts=counts,
        )
        with self._session_factory() as session:
            campaign = self._campaign(session, campaign_ref)
            window = self._window(session, campaign.id, window_ref) if window_ref else None
            existing = session.scalar(select(SatArtifactRecord).where(SatArtifactRecord.artifact_ref == artifact_ref))
            if existing:
                if (existing.campaign_id, existing.window_id, existing.artifact_scope,
                    existing.kind, existing.storage_key, existing.sha256, existing.size_bytes,
                    existing.validation_status, existing.counts) != (
                    campaign.id, window.id if window else None, "window" if window else "campaign",
                    kind, storage_key, sha256, size_bytes, validation_status, normalized_counts
                ):
                    raise ValueError("artifact identity conflict")
                return existing
            content = session.scalar(select(SatArtifactRecord).where(
                SatArtifactRecord.campaign_id == campaign.id,
                SatArtifactRecord.kind == kind, SatArtifactRecord.sha256 == sha256,
            ))
            if content:
                if (content.window_id, content.artifact_scope, content.storage_key,
                    content.size_bytes, content.validation_status, content.counts) != (
                    window.id if window else None, "window" if window else "campaign", storage_key,
                    size_bytes, validation_status, normalized_counts
                ):
                    raise ValueError("artifact content conflict")
                return content
            artifact = SatArtifactRecord(campaign_id=campaign.id, window_id=window.id if window else None,
                artifact_scope="window" if window else "campaign", artifact_ref=artifact_ref,
                kind=kind, storage_key=storage_key, sha256=sha256, size_bytes=size_bytes,
                validation_status=validation_status, counts=normalized_counts, created_at=now)
            session.add(artifact)
            session.commit()
            return artifact

    def record_artifact_with_durable_handoff(
        self,
        *,
        campaign_ref: str,
        artifact_ref: str,
        kind: str,
        storage_key: str,
        sha256: str,
        size_bytes: int,
        validation_status: str,
        tenant_id: str,
        handoff: Any,
        counts: Mapping[str, object] | None = None,
        window_ref: str | None = None,
        now: datetime | None = None,
    ) -> SatArtifactRecord:
        """Commit artifact metadata and its durable parse handoff together.

        ``handoff.persist_on_connection`` only writes ledger rows; the caller
        must invoke ``publish_after_commit`` after this method returns. Any
        failure before commit rolls back both the artifact and handoff rows.
        """

        stamp = now or datetime.now(timezone.utc)
        normalized_counts = self._artifact_metadata(
            kind=kind,
            storage_key=storage_key,
            sha256=sha256,
            size_bytes=size_bytes,
            validation_status=validation_status,
            counts=counts,
        )
        with self._session_factory() as session:
            campaign = self._campaign(session, campaign_ref)
            window = self._window(session, campaign.id, window_ref) if window_ref else None
            existing = session.scalar(
                select(SatArtifactRecord).where(SatArtifactRecord.artifact_ref == artifact_ref)
            )
            if existing:
                if (
                    existing.campaign_id,
                    existing.window_id,
                    existing.artifact_scope,
                    existing.kind,
                    existing.storage_key,
                    existing.sha256,
                    existing.size_bytes,
                    existing.validation_status,
                    existing.counts,
                ) != (
                    campaign.id,
                    window.id if window else None,
                    "window" if window else "campaign",
                    kind,
                    storage_key,
                    sha256,
                    size_bytes,
                    validation_status,
                    normalized_counts,
                ):
                    raise ValueError("artifact identity conflict")
                artifact = existing
            else:
                content = session.scalar(
                    select(SatArtifactRecord).where(
                        SatArtifactRecord.campaign_id == campaign.id,
                        SatArtifactRecord.kind == kind,
                        SatArtifactRecord.sha256 == sha256,
                    )
                )
                if content:
                    if (
                        content.window_id,
                        content.artifact_scope,
                        content.storage_key,
                        content.size_bytes,
                        content.validation_status,
                        content.counts,
                    ) != (
                        window.id if window else None,
                        "window" if window else "campaign",
                        storage_key,
                        size_bytes,
                        validation_status,
                        normalized_counts,
                    ):
                        raise ValueError("artifact content conflict")
                    artifact = content
                else:
                    artifact = SatArtifactRecord(
                        campaign_id=campaign.id,
                        window_id=window.id if window else None,
                        artifact_scope="window" if window else "campaign",
                        artifact_ref=artifact_ref,
                        kind=kind,
                        storage_key=storage_key,
                        sha256=sha256,
                        size_bytes=size_bytes,
                        validation_status=validation_status,
                        counts=normalized_counts,
                        created_at=stamp,
                    )
                    session.add(artifact)
                    session.flush()
            handoff.persist_on_connection(
                session.connection(),
                tenant_id=tenant_id,
                artifact_ref=artifact.artifact_ref,
                kind=kind,
                now=stamp,
            )
            session.commit()
            return artifact
