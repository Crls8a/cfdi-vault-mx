from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from hashlib import sha256

import pytest

from cfdi_vault.db import create_engine_from_url, create_session_factory
from cfdi_vault.recovery_db import SatMetadataImportRecord, Tenant
from cfdi_vault.sat_campaign_repository import RepositoryBusy, SatCampaignRepository

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
MANIFEST = "a" * 64


@pytest.fixture
def sat_repository(reset_postgres_database: str) -> SatCampaignRepository:
    engine = create_engine_from_url(reset_postgres_database)
    factory = create_session_factory(engine)
    with factory() as session:
        session.add(Tenant(id="repo-tenant", name="Synthetic", rfc="SYNTHETIC", created_at=NOW))
        session.commit()
    repository = SatCampaignRepository(factory)
    try:
        yield repository
    finally:
        engine.dispose()


def _campaign(repo: SatCampaignRepository) -> object:
    return repo.create_campaign(
        campaign_ref="campaign-repository",
        tenant_id="repo-tenant",
        profile_ref="profile-ref",
        manifest_sha256=MANIFEST,
        commit_ref="commit-ref",
        phase="metadata-proof",
        status="planned",
        budget=28,
        now=NOW,
    )


@pytest.mark.integration
def test_campaign_window_grant_and_sanitized_status(sat_repository: SatCampaignRepository) -> None:
    campaign = _campaign(sat_repository)
    window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-repository",
        direction="received",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 14),
        now=NOW,
    )
    grant = sat_repository.create_grant(
        campaign_ref=campaign.campaign_ref,
        grant_ref="grant-repository",
        phase="metadata-proof",
        reason="synthetic test",
        budget=2,
        expires_at=NOW + timedelta(days=14),
        now=NOW,
    )
    status = sat_repository.get_campaign_status(campaign.campaign_ref)

    assert window.work_ref == "work-repository"
    assert grant.grant_ref == "grant-repository"
    assert status["campaign_ref"] == "campaign-repository"
    assert status["windows"] == {"reserved": 1}
    assert "tenant_id" not in status and "profile_ref" not in status


@pytest.mark.integration
def test_count_open_operations_includes_submitted_requests_and_unbound_claims(
    sat_repository: SatCampaignRepository,
) -> None:
    campaign = _campaign(sat_repository)
    window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-open-count",
        direction="received",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 14),
        now=NOW,
    )
    assert sat_repository.count_open_operations(campaign.campaign_ref) == 0
    claim = sat_repository.claim_operation(
        campaign_ref=campaign.campaign_ref,
        window_ref=window.work_ref,
        operation_kind="submit",
        idempotency_key="submit:work-open-count",
        worker_ref="worker-a",
        now=NOW,
        lease_until=NOW + timedelta(minutes=5),
    )
    assert sat_repository.count_open_operations(campaign.campaign_ref) == 1
    sat_repository.record_submission(
        claim_ref=claim.claim_ref,
        campaign_ref=campaign.campaign_ref,
        work_ref=window.work_ref,
        tenant_id="repo-tenant",
        id_solicitud="synthetic-open-count",
        criteria_hash=MANIFEST,
        direction="received",
        request_type="Metadata",
        requested_at=NOW,
        next_check_at=NOW + timedelta(minutes=5),
        service_window_expires_at=NOW + timedelta(hours=48),
    )
    assert sat_repository.count_open_operations(campaign.campaign_ref) == 1


@pytest.mark.integration
def test_claim_submission_verify_history_is_idempotent(sat_repository: SatCampaignRepository) -> None:
    campaign = _campaign(sat_repository)
    window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-verify",
        direction="received",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 14),
        now=NOW,
    )
    submit_claim = sat_repository.claim_operation(
        campaign_ref=campaign.campaign_ref,
        window_ref=window.work_ref,
        operation_kind="submit",
        idempotency_key="submit:work-verify",
        worker_ref="worker-a",
        now=NOW,
        lease_until=NOW + timedelta(minutes=5),
    )
    with pytest.raises(ValueError, match="next check exceeds service window"):
        sat_repository.record_submission(
            claim_ref=submit_claim.claim_ref,
            campaign_ref=campaign.campaign_ref,
            work_ref=window.work_ref,
            tenant_id="repo-tenant",
            id_solicitud="synthetic-request-too-late",
            criteria_hash=MANIFEST,
            direction="received",
            request_type="Metadata",
            requested_at=NOW,
            next_check_at=NOW + timedelta(hours=49),
            service_window_expires_at=NOW + timedelta(hours=48),
        )
    request = sat_repository.record_submission(
        claim_ref=submit_claim.claim_ref,
        campaign_ref=campaign.campaign_ref,
        work_ref=window.work_ref,
        tenant_id="repo-tenant",
        id_solicitud="synthetic-request",
        criteria_hash=MANIFEST,
        direction="received",
        request_type="Metadata",
        requested_at=NOW,
        next_check_at=NOW,
        service_window_expires_at=NOW + timedelta(hours=48),
    )
    verify_claim = sat_repository.claim_due_operations(
        NOW, worker_ref="worker-a", lease_seconds=300
    )[0]
    with pytest.raises(ValueError, match="next check exceeds service window"):
        sat_repository.record_verify_attempt(
            claim_ref=verify_claim.claim_ref,
            category="pending",
            result="pending",
            scheduled_at=NOW,
            contacted_at=NOW,
            next_check_at=NOW + timedelta(hours=49),
            now=NOW,
        )
    attempt = sat_repository.record_verify_attempt(
        claim_ref=verify_claim.claim_ref,
        category="pending",
        result="pending",
        scheduled_at=NOW,
        contacted_at=NOW,
        next_check_at=NOW + timedelta(minutes=15),
        now=NOW,
    )
    duplicate = sat_repository.record_verify_attempt(
        claim_ref=verify_claim.claim_ref,
        category="pending",
        result="pending",
        scheduled_at=NOW,
        contacted_at=NOW,
        next_check_at=NOW + timedelta(minutes=15),
        now=NOW + timedelta(seconds=1),
    )

    assert request.id_solicitud == "synthetic-request"
    assert attempt.attempt == 1
    assert duplicate.id == attempt.id


@pytest.mark.integration
def test_submission_replay_cannot_replace_grant_provenance(
    sat_repository: SatCampaignRepository,
) -> None:
    """A request replay with another grant must fail closed."""

    campaign = _campaign(sat_repository)
    window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-grant-replay",
        direction="received",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 14),
        now=NOW,
    )
    for grant_ref in ("grant-original", "grant-replay"):
        sat_repository.create_grant(
            campaign_ref=campaign.campaign_ref,
            grant_ref=grant_ref,
            phase="metadata-proof",
            reason="synthetic",
            budget=2,
            expires_at=NOW + timedelta(days=14),
            now=NOW,
        )
    first_claim = sat_repository.claim_operation(
        campaign_ref=campaign.campaign_ref,
        window_ref=window.work_ref,
        operation_kind="submit",
        idempotency_key="submit:grant-original",
        worker_ref="worker-a",
        now=NOW,
        lease_until=NOW + timedelta(minutes=5),
        grant_ref="grant-original",
        require_grant=True,
    )
    request = sat_repository.record_submission(
        claim_ref=first_claim.claim_ref,
        campaign_ref=campaign.campaign_ref,
        work_ref=window.work_ref,
        tenant_id="repo-tenant",
        id_solicitud="request-grant-replay",
        criteria_hash=MANIFEST,
        direction="received",
        request_type="Metadata",
        requested_at=NOW,
        next_check_at=NOW,
        service_window_expires_at=NOW + timedelta(hours=48),
        grant_ref="grant-original",
    )
    replay_claim = sat_repository.claim_operation(
        campaign_ref=campaign.campaign_ref,
        window_ref=window.work_ref,
        operation_kind="submit",
        idempotency_key="submit:grant-replay",
        worker_ref="worker-b",
        now=NOW,
        lease_until=NOW + timedelta(minutes=5),
        grant_ref="grant-replay",
        require_grant=True,
    )

    with pytest.raises(ValueError, match="request identity conflict"):
        sat_repository.record_submission(
            claim_ref=replay_claim.claim_ref,
            campaign_ref=campaign.campaign_ref,
            work_ref=window.work_ref,
            tenant_id="repo-tenant",
            id_solicitud="request-grant-replay",
            criteria_hash=MANIFEST,
            direction="received",
            request_type="Metadata",
            requested_at=NOW,
            next_check_at=NOW,
            service_window_expires_at=NOW + timedelta(hours=48),
            grant_ref="grant-replay",
        )

    persisted = sat_repository.get_request(request.id)
    assert persisted is not None
    assert persisted.grant_ref == "grant-original"


@pytest.mark.integration
def test_campaign_runner_can_require_grant_for_due_requests(
    sat_repository: SatCampaignRepository,
) -> None:
    campaign = _campaign(sat_repository)
    window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-ungranted",
        direction="received",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 14),
        now=NOW,
    )
    submit_claim = sat_repository.claim_operation(
        campaign_ref=campaign.campaign_ref,
        window_ref=window.work_ref,
        operation_kind="submit",
        idempotency_key="submit:work-ungranted",
        worker_ref="worker-a",
        now=NOW,
        lease_until=NOW + timedelta(minutes=5),
    )
    sat_repository.record_submission(
        claim_ref=submit_claim.claim_ref,
        campaign_ref=campaign.campaign_ref,
        work_ref=window.work_ref,
        tenant_id="repo-tenant",
        id_solicitud="synthetic-ungranted-request",
        criteria_hash=MANIFEST,
        direction="received",
        request_type="Metadata",
        requested_at=NOW,
        next_check_at=NOW,
        service_window_expires_at=NOW + timedelta(hours=48),
    )

    assert sat_repository.claim_due_operations(
        NOW, worker_ref="worker-a", require_grant=True,
    ) == ()
    # The compatibility path remains available to the explicit legacy
    # repository API, but the campaign runner never uses it.
    assert len(sat_repository.claim_due_operations(NOW, worker_ref="worker-a")) == 1


@pytest.mark.integration
def test_cfdi_eligibility_uses_only_latest_metadata_import(
    sat_repository: SatCampaignRepository,
) -> None:
    campaign = _campaign(sat_repository)
    window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-latest-import",
        direction="received",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 14),
        now=NOW,
    )

    def add_import(artifact_ref: str, *, eligible_count: int, created_at: datetime) -> None:
        artifact = sat_repository.record_artifact(
            campaign_ref=campaign.campaign_ref,
            window_ref=window.work_ref,
            artifact_ref=artifact_ref,
            kind="metadata_txt",
            storage_key=f"sat-metadata/{artifact_ref}.txt",
            sha256=sha256(artifact_ref.encode()).hexdigest(),
            size_bytes=128,
            validation_status="processed",
            now=created_at,
        )
        with sat_repository._session_factory() as session:  # noqa: SLF001
            session.add(SatMetadataImportRecord(
                campaign_id=campaign.id,
                window_id=window.id,
                artifact_id=artifact.id,
                encoding="utf-8-sig",
                delimiter="~",
                header_compatible=True,
                record_count=eligible_count or 1,
                eligible_count=eligible_count,
                cancelled_count=0 if eligible_count else 1,
                duplicate_count=0,
                conflict_count=0,
                unknown_count=0,
                created_at=created_at,
            ))
            session.commit()

    add_import("artifact-first", eligible_count=1, created_at=NOW)
    assert sat_repository.has_eligible_metadata_import(campaign.campaign_ref) is True
    eligible_windows = sat_repository.list_submission_windows(
        campaign.campaign_ref, eligible_only=True,
    )
    assert tuple(item.work_ref for item in eligible_windows) == (window.work_ref,)

    add_import("artifact-latest", eligible_count=0, created_at=NOW + timedelta(minutes=1))
    assert sat_repository.list_submission_windows(
        campaign.campaign_ref, eligible_only=True,
    ) == ()
    assert sat_repository.has_eligible_metadata_import(campaign.campaign_ref) is False


@pytest.mark.integration
def test_metadata_verified_window_is_selectable_for_cfdi_follow_up(
    sat_repository: SatCampaignRepository,
) -> None:
    """A completed Metadata request must not hide its eligible CFDI lane."""

    campaign = _campaign(sat_repository)
    window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-verified-metadata",
        direction="received",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 14),
        now=NOW,
    )
    submit_claim = sat_repository.claim_operation(
        campaign_ref=campaign.campaign_ref,
        window_ref=window.work_ref,
        operation_kind="submit",
        idempotency_key="submit:verified-metadata",
        worker_ref="worker-a",
        now=NOW,
        lease_until=NOW + timedelta(minutes=5),
    )
    sat_repository.record_submission(
        claim_ref=submit_claim.claim_ref,
        campaign_ref=campaign.campaign_ref,
        work_ref=window.work_ref,
        tenant_id="repo-tenant",
        id_solicitud="metadata-verified-request",
        criteria_hash=MANIFEST,
        direction="received",
        request_type="Metadata",
        requested_at=NOW,
        next_check_at=NOW,
        service_window_expires_at=NOW + timedelta(hours=48),
    )
    verify_claim = sat_repository.claim_due_operations(NOW, worker_ref="worker-a")[0]
    sat_repository.record_verify_attempt(
        claim_ref=verify_claim.claim_ref,
        category="package",
        result="package",
        scheduled_at=NOW,
        contacted_at=NOW,
        next_check_at=None,
        now=NOW,
    )
    artifact = sat_repository.record_artifact(
        campaign_ref=campaign.campaign_ref,
        window_ref=window.work_ref,
        artifact_ref="metadata-verified-artifact",
        kind="metadata_txt",
        storage_key="sat-metadata/verified.txt",
        sha256=sha256(b"verified").hexdigest(),
        size_bytes=128,
        validation_status="processed",
        now=NOW,
    )
    with sat_repository._session_factory() as session:  # noqa: SLF001
        session.add(SatMetadataImportRecord(
            campaign_id=campaign.id,
            window_id=window.id,
            artifact_id=artifact.id,
            encoding="utf-8-sig",
            delimiter="~",
            header_compatible=True,
            record_count=1,
            eligible_count=1,
            cancelled_count=0,
            duplicate_count=0,
            conflict_count=0,
            unknown_count=0,
            created_at=NOW,
        ))
        session.commit()

    eligible = sat_repository.list_submission_windows(
        campaign.campaign_ref, eligible_only=True,
    )

    assert tuple(item.work_ref for item in eligible) == (window.work_ref,)


@pytest.mark.integration
def test_cross_window_metadata_artifact_cannot_authorize_cfdi_window(
    sat_repository: SatCampaignRepository,
) -> None:
    """Metadata evidence must belong to the same campaign window it selects."""

    campaign = _campaign(sat_repository)
    source_window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-source-window",
        direction="received",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 14),
        now=NOW,
    )
    target_window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-target-window",
        direction="received",
        start_date=date(2026, 1, 15),
        end_date=date(2026, 1, 28),
        now=NOW,
    )
    artifact = sat_repository.record_artifact(
        campaign_ref=campaign.campaign_ref,
        window_ref=source_window.work_ref,
        artifact_ref="artifact-source-window",
        kind="metadata_txt",
        storage_key="sat-metadata/source-window.txt",
        sha256=sha256(b"source-window").hexdigest(),
        size_bytes=128,
        validation_status="processed",
        now=NOW,
    )
    # The composite foreign keys permit this historical inconsistency, so the
    # eligibility query must defend its own campaign/window boundary.
    with sat_repository._session_factory() as session:  # noqa: SLF001
        session.add(SatMetadataImportRecord(
            campaign_id=campaign.id,
            window_id=target_window.id,
            artifact_id=artifact.id,
            encoding="utf-8-sig",
            delimiter="~",
            header_compatible=True,
            record_count=1,
            eligible_count=1,
            cancelled_count=0,
            duplicate_count=0,
            conflict_count=0,
            unknown_count=0,
            created_at=NOW,
        ))
        session.commit()

    assert sat_repository.has_eligible_metadata_import(campaign.campaign_ref) is False
    assert sat_repository.list_submission_windows(
        campaign.campaign_ref, eligible_only=True,
    ) == ()


@pytest.mark.integration
def test_package_and_artifact_are_external_references(sat_repository: SatCampaignRepository) -> None:
    campaign = _campaign(sat_repository)
    window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-artifact",
        direction="issued",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 14),
        now=NOW,
    )
    artifact = sat_repository.record_artifact(
        campaign_ref=campaign.campaign_ref,
        window_ref=window.work_ref,
        artifact_ref="artifact-repository",
        kind="metadata_zip",
        storage_key="sat-metadata/campaign-repository/package.zip",
        sha256="b" * 64,
        size_bytes=12,
        validation_status="valid",
        counts={"records": 1},
        now=NOW,
    )

    assert artifact.storage_key.endswith("package.zip")
    with pytest.raises(ValueError, match="non-submit claim requires a request"):
        sat_repository.claim_operation(
            campaign_ref=campaign.campaign_ref,
            window_ref=window.work_ref,
            operation_kind="download",
            idempotency_key="download:without-request",
            worker_ref="worker-a",
            now=NOW,
            lease_until=NOW + timedelta(minutes=5),
        )


@pytest.mark.integration
def test_window_split_must_stay_inside_parent(sat_repository: SatCampaignRepository) -> None:
    campaign = _campaign(sat_repository)
    sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-parent",
        direction="received",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 14),
        now=NOW,
    )

    with pytest.raises(ValueError, match="same-campaign 14-to-7-day child"):
        sat_repository.reserve_window(
            campaign_ref=campaign.campaign_ref,
            work_ref="work-outside-parent",
            direction="received",
            start_date=date(2025, 12, 27),
            end_date=date(2026, 1, 2),
            parent_work_ref="work-parent",
            now=NOW,
        )


@pytest.mark.integration
def test_download_package_claim_is_one_shot(sat_repository: SatCampaignRepository) -> None:
    campaign = _campaign(sat_repository)
    window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref,
        work_ref="work-package",
        direction="received",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 14),
        now=NOW,
    )
    submit = sat_repository.claim_operation(
        campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
        operation_kind="submit", idempotency_key="submit:package", worker_ref="worker-a",
        now=NOW, lease_until=NOW + timedelta(minutes=5),
    )
    request = sat_repository.record_submission(
        claim_ref=submit.claim_ref, campaign_ref=campaign.campaign_ref,
        work_ref=window.work_ref, tenant_id="repo-tenant", id_solicitud="package-request",
        criteria_hash=MANIFEST, direction="received", request_type="Metadata", requested_at=NOW,
        next_check_at=NOW, service_window_expires_at=NOW + timedelta(hours=48),
    )
    artifact = sat_repository.record_artifact(
        campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
        artifact_ref="artifact-package", kind="metadata_zip", storage_key="package.zip",
        sha256="c" * 64, size_bytes=1, validation_status="valid", now=NOW,
    )
    download = sat_repository.claim_operation(
        campaign_ref=campaign.campaign_ref, window_ref=window.work_ref, request_id=request.id,
        operation_kind="download", idempotency_key="download:package", worker_ref="worker-a",
        now=NOW, lease_until=NOW + timedelta(minutes=5),
    )
    package = sat_repository.record_package(
        claim_ref=download.claim_ref, id_paquete="package-id", id_solicitud=request.id_solicitud,
        status="downloaded", artifact_id=artifact.id, now=NOW,
    )

    assert package.download_state == "downloaded"
    with pytest.raises(ValueError, match="download claim mismatch"):
        sat_repository.record_package(
            claim_ref=download.claim_ref, id_paquete="package-id", id_solicitud=request.id_solicitud,
            status="downloaded", artifact_id=artifact.id, now=NOW,
        )


@pytest.mark.integration
def test_expired_claim_releases_slot_for_new_idempotency_key(sat_repository: SatCampaignRepository) -> None:
    campaign = _campaign(sat_repository)
    window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref, work_ref="work-expiry", direction="received",
        start_date=date(2026, 1, 1), end_date=date(2026, 1, 14), now=NOW,
    )
    with pytest.raises(ValueError, match="claim lease must be in the future"):
        sat_repository.claim_operation(
            campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
            operation_kind="submit", idempotency_key="submit:expiry:invalid", worker_ref="worker-a",
            now=NOW, lease_until=NOW,
        )
    first = sat_repository.claim_operation(
        campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
        operation_kind="submit", idempotency_key="submit:expiry:first", worker_ref="worker-a",
        now=NOW, lease_until=NOW + timedelta(minutes=5),
    )
    replay = sat_repository.claim_operation(
        campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
        operation_kind="submit", idempotency_key="submit:expiry:first", worker_ref="worker-b",
        now=NOW + timedelta(minutes=1), lease_until=NOW + timedelta(minutes=11),
    )
    assert replay.claim_ref == first.claim_ref

    with pytest.raises(RepositoryBusy, match="manual review"):
        sat_repository.claim_operation(
            campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
            operation_kind="submit", idempotency_key="submit:expiry:second", worker_ref="worker-a",
            now=NOW + timedelta(minutes=6), lease_until=NOW + timedelta(minutes=11),
        )


@pytest.mark.integration
def test_claim_replay_cannot_change_grant_provenance(
    sat_repository: SatCampaignRepository,
) -> None:
    """Idempotency keys bind the exact grant used by the first claim."""

    campaign = _campaign(sat_repository)
    window = sat_repository.reserve_window(
        campaign_ref=campaign.campaign_ref, work_ref="work-claim-grant",
        direction="received", start_date=date(2026, 1, 1), end_date=date(2026, 1, 14), now=NOW,
    )
    for grant_ref in ("grant-claim-one", "grant-claim-two"):
        sat_repository.create_grant(
            campaign_ref=campaign.campaign_ref, grant_ref=grant_ref,
            phase="metadata-proof", reason="synthetic", budget=2,
            expires_at=NOW + timedelta(days=14), now=NOW,
        )
    first = sat_repository.claim_operation(
        campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
        operation_kind="submit", idempotency_key="submit:claim-grant",
        worker_ref="worker-a", now=NOW, lease_until=NOW + timedelta(minutes=5),
        grant_ref="grant-claim-one", require_grant=True,
    )

    with pytest.raises(ValueError, match="claim identity conflict"):
        sat_repository.claim_operation(
            campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
            operation_kind="submit", idempotency_key="submit:claim-grant",
            worker_ref="worker-b", now=NOW, lease_until=NOW + timedelta(minutes=5),
            grant_ref="grant-claim-two", require_grant=True,
        )

    assert sat_repository.get_claim(first.claim_ref).grant_ref == "grant-claim-one"
