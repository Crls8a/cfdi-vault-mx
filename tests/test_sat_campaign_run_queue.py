"""Durable campaign-run queue behaviour (ADR 0005).

These exercise real PostgreSQL because the guarantees under test are database
guarantees: a partial unique index for idempotency, ``FOR UPDATE SKIP LOCKED``
for claiming, and a terminal-immutability trigger.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cfdi_vault.db import create_engine_from_url, create_session_factory
from cfdi_vault.recovery_db import Tenant
from cfdi_vault.sat_campaign_repository import SatCampaignRepository

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
MANIFEST = "a" * 64
LEASE = 900


@pytest.fixture
def run_repository(reset_postgres_database: str) -> SatCampaignRepository:
    engine = create_engine_from_url(reset_postgres_database)
    factory = create_session_factory(engine)
    with factory() as session:
        session.add(Tenant(id="run-tenant", name="Synthetic", rfc="SYNTHETIC", created_at=NOW))
        session.commit()
    repository = SatCampaignRepository(factory)
    repository.create_campaign(
        campaign_ref="campaign-run-queue", tenant_id="run-tenant", profile_ref="profile-run",
        manifest_sha256=MANIFEST, commit_ref="commit-run", phase="metadata-proof",
        status="planned", budget=28, now=NOW,
    )
    try:
        yield repository
    finally:
        engine.dispose()


def _enqueue(
    repository: SatCampaignRepository, grant_ref: str = "grant-run", *,
    now: datetime = NOW, lease_seconds: int = LEASE,
) -> object:
    return repository.enqueue_campaign_run(
        campaign_ref="campaign-run-queue", grant_ref=grant_ref, profile_ref="profile-run",
        commit_ref="commit-run", requested_via="panel", lease_seconds=lease_seconds, now=now,
    )


@pytest.mark.integration
def test_enqueue_returns_the_same_run_ref_while_a_run_is_still_active(
    run_repository: SatCampaignRepository,
) -> None:
    """A double-clicked panel button must never authorize a second live run."""

    first = _enqueue(run_repository)
    second = _enqueue(run_repository, now=NOW + timedelta(seconds=1))

    assert first.run_ref == second.run_ref
    assert second.status == "queued"
    assert second.requested_at == first.requested_at


@pytest.mark.integration
def test_enqueue_creates_a_new_run_only_after_the_previous_one_is_terminal(
    run_repository: SatCampaignRepository,
) -> None:
    first = _enqueue(run_repository)
    run_repository.record_campaign_run_result(
        first.run_ref, status="succeeded", result_code="processed", now=NOW + timedelta(minutes=1),
    )

    second = _enqueue(run_repository, now=NOW + timedelta(minutes=2))

    assert second.run_ref != first.run_ref
    assert second.status == "queued"


@pytest.mark.integration
def test_enqueue_separates_runs_for_different_grants(
    run_repository: SatCampaignRepository,
) -> None:
    first = _enqueue(run_repository, "grant-run-a")
    second = _enqueue(run_repository, "grant-run-b")

    assert first.run_ref != second.run_ref


@pytest.mark.integration
def test_enqueue_rejects_a_profile_or_commit_that_does_not_own_the_campaign(
    run_repository: SatCampaignRepository,
) -> None:
    with pytest.raises(ValueError, match="profile mismatch"):
        run_repository.enqueue_campaign_run(
            campaign_ref="campaign-run-queue", grant_ref="grant-run", profile_ref="other-profile",
            commit_ref="commit-run", requested_via="panel", lease_seconds=LEASE, now=NOW,
        )
    with pytest.raises(ValueError, match="commit mismatch"):
        run_repository.enqueue_campaign_run(
            campaign_ref="campaign-run-queue", grant_ref="grant-run", profile_ref="profile-run",
            commit_ref="other-commit", requested_via="panel", lease_seconds=LEASE, now=NOW,
        )


@pytest.mark.integration
def test_enqueue_rejects_an_unknown_request_origin(
    run_repository: SatCampaignRepository,
) -> None:
    with pytest.raises(ValueError, match="requested_via"):
        run_repository.enqueue_campaign_run(
            campaign_ref="campaign-run-queue", grant_ref="grant-run", profile_ref="profile-run",
            commit_ref="commit-run", requested_via="scheduler", lease_seconds=LEASE, now=NOW,
        )


@pytest.mark.integration
def test_claim_takes_the_oldest_queued_run_and_leases_it(
    run_repository: SatCampaignRepository,
) -> None:
    older = _enqueue(run_repository, "grant-run-a", now=NOW)
    _enqueue(run_repository, "grant-run-b", now=NOW + timedelta(minutes=5))

    claimed = run_repository.claim_next_campaign_run(
        worker_ref="worker-a", lease_seconds=LEASE, now=NOW + timedelta(minutes=6),
    )

    assert claimed is not None
    assert claimed.run_ref == older.run_ref
    assert claimed.status == "claimed"
    assert claimed.worker_ref == "worker-a"
    assert claimed.claimed_at == NOW + timedelta(minutes=6)
    assert claimed.lease_until == NOW + timedelta(minutes=6, seconds=LEASE)


@pytest.mark.integration
def test_claim_returns_none_when_no_run_is_queued(
    run_repository: SatCampaignRepository,
) -> None:
    assert run_repository.claim_next_campaign_run(worker_ref="worker-a", lease_seconds=LEASE) is None


@pytest.mark.integration
def test_a_claimed_run_is_never_handed_to_a_second_worker(
    run_repository: SatCampaignRepository,
) -> None:
    """Two consumers must not both execute one live SAT sequence."""

    record = _enqueue(run_repository)

    first = run_repository.claim_next_campaign_run(worker_ref="worker-a", lease_seconds=LEASE, now=NOW)
    second = run_repository.claim_next_campaign_run(worker_ref="worker-b", lease_seconds=LEASE, now=NOW)

    assert first is not None and first.run_ref == record.run_ref
    assert second is None


@pytest.mark.integration
def test_concurrent_claims_skip_the_locked_row_instead_of_blocking(
    run_repository: SatCampaignRepository, reset_postgres_database: str,
) -> None:
    """``SKIP LOCKED`` must let a second consumer proceed to the next run."""

    _enqueue(run_repository, "grant-run-a", now=NOW)
    _enqueue(run_repository, "grant-run-b", now=NOW + timedelta(minutes=1))

    other_engine = create_engine_from_url(reset_postgres_database)
    try:
        other = SatCampaignRepository(create_session_factory(other_engine))
        with run_repository._session_factory() as holding_session:
            from sqlalchemy import select

            from cfdi_vault.recovery_db import SatCampaignRunRecord

            locked_ref = holding_session.scalar(
                select(SatCampaignRunRecord.run_ref)
                .where(SatCampaignRunRecord.status == "queued")
                .order_by(SatCampaignRunRecord.requested_at)
                .limit(1)
                .with_for_update()
            )
            assert locked_ref is not None
            # The second consumer must not block on the row the first holds.
            claimed = other.claim_next_campaign_run(
                worker_ref="worker-b", lease_seconds=LEASE, now=NOW + timedelta(minutes=2),
            )
            claimed_ref = claimed.run_ref if claimed is not None else None
            holding_session.rollback()
    finally:
        other_engine.dispose()

    assert claimed_ref is not None
    assert claimed_ref != locked_ref


@pytest.mark.integration
def test_expired_runs_are_abandoned_and_fresh_ones_are_left_alone(
    run_repository: SatCampaignRepository,
) -> None:
    """A queued run holds its own lease so an unstarted consumer stays visible."""

    stale = _enqueue(run_repository, "grant-run-a", now=NOW, lease_seconds=60)
    fresh = _enqueue(run_repository, "grant-run-b", now=NOW, lease_seconds=3600)

    abandoned = run_repository.abandon_expired_campaign_runs(NOW + timedelta(minutes=5))

    assert abandoned == 1
    closed = run_repository.get_campaign_run(stale.run_ref)
    assert closed.status == "abandoned"
    assert closed.result_code == "lease-expired"
    assert closed.finished_at == NOW + timedelta(minutes=5)
    assert run_repository.get_campaign_run(fresh.run_ref).status == "queued"


@pytest.mark.integration
def test_the_reaper_never_touches_a_run_that_already_finished(
    run_repository: SatCampaignRepository,
) -> None:
    record = _enqueue(run_repository, lease_seconds=60)
    run_repository.record_campaign_run_result(
        record.run_ref, status="succeeded", result_code="processed", now=NOW + timedelta(seconds=10),
    )

    assert run_repository.abandon_expired_campaign_runs(NOW + timedelta(minutes=5)) == 0
    assert run_repository.get_campaign_run(record.run_ref).status == "succeeded"


@pytest.mark.integration
def test_an_abandoned_run_is_terminal_and_is_never_re_queued(
    run_repository: SatCampaignRepository,
) -> None:
    """Infrastructure must never restart a live SAT run by itself."""

    record = _enqueue(run_repository, lease_seconds=60)
    run_repository.abandon_expired_campaign_runs(NOW + timedelta(minutes=5))

    assert run_repository.claim_next_campaign_run(
        worker_ref="worker-a", lease_seconds=LEASE, now=NOW + timedelta(minutes=6),
    ) is None
    with pytest.raises(ValueError, match="already terminal"):
        run_repository.record_campaign_run_result(
            record.run_ref, status="succeeded", now=NOW + timedelta(minutes=6),
        )


@pytest.mark.integration
def test_recording_a_result_stores_only_sanitized_aggregates(
    run_repository: SatCampaignRepository,
) -> None:
    record = _enqueue(run_repository)
    run_repository.claim_next_campaign_run(worker_ref="worker-a", lease_seconds=LEASE, now=NOW)
    run_repository.mark_campaign_run_running(record.run_ref, lease_seconds=LEASE, now=NOW)

    closed = run_repository.record_campaign_run_result(
        record.run_ref, status="succeeded", result_code="processed",
        contacted_count=2, submitted_count=1, package_count=3, now=NOW + timedelta(minutes=4),
    )

    assert (closed.status, closed.result_code) == ("succeeded", "processed")
    assert (closed.contacted_count, closed.submitted_count, closed.package_count) == (2, 1, 3)
    assert closed.finished_at == NOW + timedelta(minutes=4)


@pytest.mark.integration
def test_result_codes_outside_the_database_check_are_rejected_before_the_write(
    run_repository: SatCampaignRepository,
) -> None:
    record = _enqueue(run_repository)
    with pytest.raises(ValueError, match="result code"):
        run_repository.record_campaign_run_result(
            record.run_ref, status="failed", result_code="Runner Exploded!", now=NOW,
        )


@pytest.mark.integration
def test_last_campaign_run_projects_the_newest_run_without_grant_or_worker_data(
    run_repository: SatCampaignRepository,
) -> None:
    """A run that failed before any VERIFY attempt must still be visible."""

    assert run_repository.get_last_campaign_run("campaign-run-queue") is None

    first = _enqueue(run_repository, "grant-run-a", now=NOW)
    run_repository.record_campaign_run_result(
        first.run_ref, status="succeeded", result_code="processed", now=NOW + timedelta(minutes=1),
    )
    second = _enqueue(run_repository, "grant-run-b", now=NOW + timedelta(minutes=2))
    run_repository.record_campaign_run_result(
        second.run_ref, status="failed", result_code="commit-ref-mismatch",
        now=NOW + timedelta(minutes=3),
    )

    projection = run_repository.get_last_campaign_run("campaign-run-queue")

    assert projection == {
        "run_ref": second.run_ref,
        "status": "failed",
        "result_code": "commit-ref-mismatch",
        "requested_at": (NOW + timedelta(minutes=2)).isoformat(),
        "finished_at": (NOW + timedelta(minutes=3)).isoformat(),
    }
    assert "grant_ref" not in projection and "worker_ref" not in projection


@pytest.mark.integration
def test_campaign_ref_for_run_hydrates_the_campaign_the_consumer_must_execute(
    run_repository: SatCampaignRepository,
) -> None:
    record = _enqueue(run_repository)

    assert run_repository.campaign_ref_for_run(record.run_ref) == "campaign-run-queue"
    assert run_repository.campaign_ref_for_run("run-does-not-exist") is None
