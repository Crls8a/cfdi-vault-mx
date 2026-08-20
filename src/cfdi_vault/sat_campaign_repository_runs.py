"""Durable campaign-run queue persistence (ADR 0005).

PostgreSQL owns the work item.  The ``sat.campaign.run`` broker message is a
wake hint that carries no run data, so every method here is safe to call after
a lost, duplicated, or coalesced hint: the row is always re-read and re-claimed
from the database.

Nothing in this module contacts SAT, opens credentials, or retries a run.  An
expired lease becomes ``abandoned``; a new attempt requires a new human request.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from cfdi_vault.recovery_db import SatCampaignRecord, SatCampaignRunRecord

ACTIVE_RUN_STATUS = ("queued", "claimed", "running")
TERMINAL_RUN_STATUS = ("succeeded", "failed", "abandoned")
REQUESTED_VIA = frozenset({"panel", "cli"})
LEASE_EXPIRED_RESULT_CODE = "lease-expired"


class SatCampaignRunQueueMixin:
    """Enqueue, claim, and close bounded campaign runs in short transactions."""

    def enqueue_campaign_run(
        self, *, campaign_ref: str, grant_ref: str, profile_ref: str, commit_ref: str,
        requested_via: str, lease_seconds: int, now: datetime | None = None,
    ) -> SatCampaignRunRecord:
        """Queue one run, or return the run that is already active for the grant.

        The partial unique index over ``(campaign_id, grant_ref)`` is what makes
        a double-clicked panel button, a retried HTTP request, and a crashed
        publisher all resolve to the same ``run_ref`` instead of authorizing a
        second live SAT sequence.

        ``queued`` rows receive their own lease at enqueue time, not only at
        claim time: without it, a run nobody ever started (because the host
        consumer was never launched) would stay queued forever and never become
        visible as ``abandoned``.
        """

        if requested_via not in REQUESTED_VIA:
            raise ValueError("campaign run requested_via is invalid")
        if type(lease_seconds) is not int or isinstance(lease_seconds, bool) or lease_seconds <= 0:
            raise ValueError("campaign run lease must be positive")
        stamp = _utc(now)
        with self._session_factory() as session:
            campaign = self._campaign(session, campaign_ref)
            if campaign.profile_ref != profile_ref:
                raise ValueError("campaign profile mismatch")
            if campaign.commit_ref != commit_ref:
                raise ValueError("campaign commit mismatch")
            existing = self._active_run(session, campaign.id, grant_ref)
            if existing is not None:
                return existing
            record = SatCampaignRunRecord(
                run_ref=f"run-{uuid4().hex}", campaign_id=campaign.id, grant_ref=grant_ref,
                profile_ref=profile_ref, commit_ref=commit_ref, status="queued",
                requested_via=requested_via, requested_at=stamp,
                lease_until=stamp + timedelta(seconds=lease_seconds),
            )
            session.add(record)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                # Another panel request won the partial unique index between the
                # read above and this insert.  Return the run that exists rather
                # than reporting a failure the operator cannot act on.
                concurrent = self._active_run(session, campaign.id, grant_ref)
                if concurrent is None:
                    raise
                return concurrent
            return record

    def claim_next_campaign_run(
        self, *, worker_ref: str, lease_seconds: int, now: datetime | None = None,
    ) -> SatCampaignRunRecord | None:
        """Claim the oldest queued run with ``FOR UPDATE SKIP LOCKED``.

        Only ``queued`` rows are claimed.  Reclaiming an expired ``claimed`` or
        ``running`` row is deliberately *not* folded into this query: the prior
        holder may have already contacted SAT, so an expired lease is closed as
        ``abandoned`` by :meth:`abandon_expired_campaign_runs` and never silently
        handed to a second worker.
        """

        if not isinstance(worker_ref, str) or not worker_ref.strip():
            raise ValueError("campaign run worker_ref is required")
        if type(lease_seconds) is not int or isinstance(lease_seconds, bool) or lease_seconds <= 0:
            raise ValueError("campaign run lease must be positive")
        stamp = _utc(now)
        with self._session_factory() as session:
            record = session.scalar(
                select(SatCampaignRunRecord)
                .where(SatCampaignRunRecord.status == "queued")
                .order_by(SatCampaignRunRecord.requested_at, SatCampaignRunRecord.run_ref)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if record is None:
                return None
            record.status = "claimed"
            record.claimed_at = stamp
            record.lease_until = stamp + timedelta(seconds=lease_seconds)
            record.worker_ref = worker_ref
            session.commit()
            return record

    def mark_campaign_run_running(
        self, run_ref: str, *, lease_seconds: int, now: datetime | None = None,
    ) -> SatCampaignRunRecord:
        """Move a claimed run to ``running`` and extend its lease.

        This is the last durable write before the live SAT sequence starts, so a
        crash mid-run leaves an observable ``running`` row that the reaper can
        abandon instead of a row that still looks claimable.
        """

        if type(lease_seconds) is not int or isinstance(lease_seconds, bool) or lease_seconds <= 0:
            raise ValueError("campaign run lease must be positive")
        stamp = _utc(now)
        with self._session_factory() as session:
            record = self._run(session, run_ref)
            if record.status != "claimed":
                raise ValueError("campaign run is not claimed")
            record.status = "running"
            record.lease_until = stamp + timedelta(seconds=lease_seconds)
            session.commit()
            return record

    def record_campaign_run_result(
        self, run_ref: str, *, status: str, result_code: str | None = None,
        contacted_count: int = 0, submitted_count: int = 0, package_count: int = 0,
        now: datetime | None = None,
    ) -> SatCampaignRunRecord:
        """Close one run with its sanitized aggregate outcome."""

        if status not in {"succeeded", "failed"}:
            raise ValueError("campaign run terminal status is invalid")
        counts = (contacted_count, submitted_count, package_count)
        if any(type(value) is not int or isinstance(value, bool) or value < 0 for value in counts):
            raise ValueError("campaign run counts are invalid")
        stamp = _utc(now)
        with self._session_factory() as session:
            record = self._run(session, run_ref)
            if record.status in TERMINAL_RUN_STATUS:
                raise ValueError("campaign run is already terminal")
            record.status = status
            record.result_code = _result_code(result_code)
            record.contacted_count = contacted_count
            record.submitted_count = submitted_count
            record.package_count = package_count
            record.finished_at = stamp
            session.commit()
            return record

    def abandon_expired_campaign_runs(
        self, now: datetime | None = None, *, result_code: str = LEASE_EXPIRED_RESULT_CODE,
    ) -> int:
        """Close every non-terminal run whose lease has already expired.

        This is the only automatic transition in the campaign-run lifecycle, and
        it deliberately ends in a terminal state rather than re-queueing: a live
        SAT run must never be restarted by infrastructure (ADR 0004/0005).
        """

        stamp = _utc(now)
        code = _result_code(result_code)
        with self._session_factory() as session:
            result = session.execute(
                update(SatCampaignRunRecord)
                .where(
                    SatCampaignRunRecord.status.in_(ACTIVE_RUN_STATUS),
                    SatCampaignRunRecord.lease_until.is_not(None),
                    SatCampaignRunRecord.lease_until < stamp,
                )
                .values(status="abandoned", result_code=code, finished_at=stamp)
            )
            session.commit()
            return int(result.rowcount or 0)

    def get_last_campaign_run(self, campaign_ref: str) -> dict[str, object] | None:
        """Return the newest run for one campaign as a sanitized projection.

        The projection carries no grant, worker, or profile reference: it exists
        so a run that failed before any VERIFY attempt is still visible in
        ``campaign status``, which previously showed nothing at all.
        """

        with self._session_factory() as session:
            campaign = self._campaign(session, campaign_ref)
            record = session.scalar(
                select(SatCampaignRunRecord)
                .where(SatCampaignRunRecord.campaign_id == campaign.id)
                .order_by(
                    SatCampaignRunRecord.requested_at.desc(), SatCampaignRunRecord.run_ref.desc(),
                )
                .limit(1)
            )
            if record is None:
                return None
            return {
                "run_ref": record.run_ref,
                "status": record.status,
                "result_code": record.result_code,
                "requested_at": record.requested_at.isoformat(),
                "finished_at": record.finished_at.isoformat() if record.finished_at else None,
            }

    def get_campaign_run(self, run_ref: str) -> SatCampaignRunRecord | None:
        """Return one detached run snapshot for an already durable run."""

        with self._session_factory() as session:
            return session.get(SatCampaignRunRecord, run_ref)

    def campaign_ref_for_run(self, run_ref: str) -> str | None:
        """Resolve the campaign reference a claimed run belongs to."""

        with self._session_factory() as session:
            record = session.get(SatCampaignRunRecord, run_ref)
            if record is None:
                return None
            campaign = session.get(SatCampaignRecord, record.campaign_id)
            return campaign.campaign_ref if campaign is not None else None

    @staticmethod
    def _active_run(session: object, campaign_id: int, grant_ref: str) -> SatCampaignRunRecord | None:
        return session.scalar(select(SatCampaignRunRecord).where(
            SatCampaignRunRecord.campaign_id == campaign_id,
            SatCampaignRunRecord.grant_ref == grant_ref,
            SatCampaignRunRecord.status.in_(ACTIVE_RUN_STATUS),
        ))

    @staticmethod
    def _run(session: object, run_ref: str) -> SatCampaignRunRecord:
        record = session.scalar(
            select(SatCampaignRunRecord)
            .where(SatCampaignRunRecord.run_ref == run_ref)
            .with_for_update()
        )
        if record is None:
            raise ValueError("campaign run not found")
        return record


def _result_code(value: str | None) -> str | None:
    """Keep result codes inside the database CHECK the ledger tables also use."""

    if value is None:
        return None
    if (
        not isinstance(value, str) or not 1 <= len(value) <= 64
        or not value[0].islower() or not value[0].isascii()
        or not all(char.isascii() and (char.islower() or char.isdigit() or char in "._-") for char in value)
    ):
        raise ValueError("campaign run result code is invalid")
    return value


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if not isinstance(value, datetime):
        raise TypeError("campaign run timestamp must be a datetime")
    if value.tzinfo is None:
        raise ValueError("campaign run timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)
