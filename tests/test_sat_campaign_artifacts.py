from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from sqlalchemy import select

from cfdi_vault.db import create_engine_from_url, create_session_factory
from cfdi_vault.recovery_db import SatArtifactRecord, SatClaimRecord, SatPackageRecord, Tenant
from cfdi_vault.sat_campaign_artifacts import CampaignArtifactError, SatCampaignArtifactCoordinator
from cfdi_vault.sat_campaign_repository import SatCampaignRepository

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
MANIFEST = "b" * 64


@pytest.fixture
def artifact_context(reset_postgres_database: str, tmp_path: Path):
    engine = create_engine_from_url(reset_postgres_database)
    factory = create_session_factory(engine)
    with factory() as session:
        session.add(Tenant(id="artifact-tenant", name="Synthetic", rfc="SYNTHETIC", created_at=NOW))
        session.commit()
    repository = SatCampaignRepository(factory)
    campaign = repository.create_campaign(
        campaign_ref="campaign-artifacts", tenant_id="artifact-tenant", profile_ref="profile",
        manifest_sha256=MANIFEST, commit_ref="commit", phase="metadata-proof",
        status="planned", budget=1, now=NOW,
    )
    window = repository.reserve_window(
        campaign_ref=campaign.campaign_ref, work_ref="window-artifacts", direction="received",
        start_date=date(2026, 1, 1), end_date=date(2026, 1, 14), now=NOW,
    )
    submission = repository.claim_operation(
        campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
        operation_kind="submit", idempotency_key="submit:artifact", worker_ref="test",
        now=NOW, lease_until=NOW + timedelta(minutes=5),
    )
    request = repository.record_submission(
        claim_ref=submission.claim_ref, campaign_ref=campaign.campaign_ref,
        work_ref=window.work_ref, tenant_id="artifact-tenant", id_solicitud="request-artifact",
        criteria_hash=MANIFEST, direction="received", request_type="Metadata", requested_at=NOW,
        next_check_at=NOW, service_window_expires_at=NOW + timedelta(hours=48),
    )
    return repository, campaign.campaign_ref, window.work_ref, request.id, tmp_path


@pytest.mark.integration
def test_package_bytes_stay_external_and_are_registered_as_metadata(artifact_context) -> None:
    repository, campaign_ref, work_ref, request_id, root = artifact_context
    payload = BytesIO()
    with ZipFile(payload, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "metadata.txt",
            "uuid~rfcEmisor~rfcReceptor~fechaEmision~estadoComprobante~tipoComprobante\n"
            "synthetic~synthetic~synthetic~2026-01-01~Vigente~I\n",
        )
    stored = SatCampaignArtifactCoordinator(repository, str(root)).store_package(
        campaign_ref=campaign_ref, work_ref=work_ref, request_id=request_id,
        package_ref="package-artifact", ordinal=1, kind="metadata_zip",
        chunks=(payload.getvalue(),), max_bytes=1024, now=NOW,
    )
    assert (root / Path(stored.relative_key)).is_file()
    with repository._session_factory() as session:
        artifact = session.scalar(select(SatArtifactRecord))
        package = session.scalar(select(SatPackageRecord))
        assert artifact.size_bytes == len(payload.getvalue())
        assert package.artifact_id == artifact.id
        assert package.download_state == "downloaded"
        assert artifact.validation_status == "valid"
        assert artifact.counts == {}


@pytest.mark.integration
def test_parse_handoff_is_published_before_download_claim_is_terminal(artifact_context) -> None:
    """The queue handoff observes an open claim until package persistence follows."""

    repository, campaign_ref, work_ref, request_id, root = artifact_context
    claim = repository.claim_operation(
        campaign_ref=campaign_ref, window_ref=work_ref, request_id=request_id,
        operation_kind="download", idempotency_key="download:handoff-order", worker_ref="test",
        now=NOW, lease_until=NOW + timedelta(minutes=5),
    )
    payload = BytesIO()
    with ZipFile(payload, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "metadata.txt",
            "uuid~rfcEmisor~rfcReceptor~fechaEmision~estadoComprobante~tipoComprobante\n"
            "synthetic~synthetic~synthetic~2026-01-01~Vigente~I\n",
        )
    observations: list[tuple[bool, bool]] = []

    def publish(_message) -> None:  # type: ignore[no-untyped-def]
        with repository._session_factory() as session:  # noqa: SLF001
            package = session.scalar(select(SatPackageRecord).where(
                SatPackageRecord.id_solicitud == "request-artifact",
            ))
            persisted_claim = session.scalar(select(SatClaimRecord).where(
                SatClaimRecord.claim_ref == claim.claim_ref,
            ))
            observations.append((package is None, bool(persisted_claim and persisted_claim.active)))

    SatCampaignArtifactCoordinator(
        repository, str(root), job_publisher=publish,
    ).store_package(
        campaign_ref=campaign_ref, work_ref=work_ref, request_id=request_id,
        package_ref="package-handoff-order", ordinal=1, kind="metadata_zip",
        chunks=(payload.getvalue(),), max_bytes=1024, claim_ref=claim.claim_ref, now=NOW,
    )

    assert observations == [(True, True)]
    with repository._session_factory() as session:  # noqa: SLF001
        package = session.scalar(select(SatPackageRecord).where(
            SatPackageRecord.id_paquete == "package-handoff-order",
        ))
        persisted_claim = session.scalar(select(SatClaimRecord).where(
            SatClaimRecord.claim_ref == claim.claim_ref,
        ))
    assert package is not None
    assert persisted_claim is not None
    assert persisted_claim.result == "package"


@pytest.mark.integration
def test_invalid_artifact_kind_is_rejected_before_claim(artifact_context) -> None:
    repository, campaign_ref, work_ref, request_id, root = artifact_context
    with pytest.raises(Exception) as error:
        SatCampaignArtifactCoordinator(repository, str(root)).store_package(
            campaign_ref=campaign_ref, work_ref=work_ref, request_id=request_id,
            package_ref="package-invalid", ordinal=1, kind="raw_payload",
            chunks=(b"bytes",), max_bytes=1024, now=NOW,
        )
    assert getattr(error.value, "reason", "") == "artifact-kind-invalid"


@pytest.mark.integration
def test_mismatched_download_claim_is_not_quarantined(artifact_context) -> None:
    """A cross-context package call cannot mark an unrelated claim uncertain."""

    repository, campaign_ref, work_ref, request_id, root = artifact_context
    claim = repository.claim_operation(
        campaign_ref=campaign_ref, window_ref=work_ref, request_id=request_id,
        operation_kind="download", idempotency_key="download:identity-check", worker_ref="test",
        now=NOW, lease_until=NOW + timedelta(minutes=5),
    )
    with pytest.raises(CampaignArtifactError, match="download-claim-invalid"):
        SatCampaignArtifactCoordinator(repository, str(root)).store_package(
            campaign_ref="different-campaign", work_ref=work_ref, request_id=request_id,
            package_ref="package-identity-check", ordinal=1, kind="metadata_zip",
            chunks=(b"not-used",), max_bytes=1024, claim_ref=claim.claim_ref, now=NOW,
        )

    persisted = repository.get_claim(claim.claim_ref)
    assert persisted is not None
    assert persisted.active is True
    assert persisted.result is None


@pytest.mark.integration
def test_same_package_bytes_use_campaign_scoped_artifact_refs(artifact_context) -> None:
    """Equal content in separate campaigns must not collide globally."""

    repository, campaign_ref, work_ref, request_id, root = artifact_context
    second_campaign = repository.create_campaign(
        campaign_ref="campaign-artifacts-second", tenant_id="artifact-tenant", profile_ref="profile",
        manifest_sha256="c" * 64, commit_ref="commit", phase="metadata-proof",
        status="planned", budget=1, now=NOW,
    )
    second_window = repository.reserve_window(
        campaign_ref=second_campaign.campaign_ref, work_ref="window-artifacts-second",
        direction="received", start_date=date(2026, 1, 1), end_date=date(2026, 1, 14), now=NOW,
    )
    second_claim = repository.claim_operation(
        campaign_ref=second_campaign.campaign_ref, window_ref=second_window.work_ref,
        operation_kind="submit", idempotency_key="submit:artifact-second", worker_ref="test",
        now=NOW, lease_until=NOW + timedelta(minutes=5),
    )
    second_request = repository.record_submission(
        claim_ref=second_claim.claim_ref, campaign_ref=second_campaign.campaign_ref,
        work_ref=second_window.work_ref, tenant_id="artifact-tenant", id_solicitud="request-artifact-second",
        criteria_hash="c" * 64, direction="received", request_type="Metadata", requested_at=NOW,
        next_check_at=NOW, service_window_expires_at=NOW + timedelta(hours=48),
    )
    payload = BytesIO()
    with ZipFile(payload, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "metadata.txt",
            "uuid~rfcEmisor~rfcReceptor~fechaEmision~estadoComprobante~tipoComprobante\n"
            "synthetic~synthetic~synthetic~2026-01-01~Vigente~I\n",
        )
    content = payload.getvalue()
    coordinator = SatCampaignArtifactCoordinator(repository, str(root))
    coordinator.store_package(
        campaign_ref=campaign_ref, work_ref=work_ref, request_id=request_id,
        package_ref="package-artifact-first", ordinal=1, kind="metadata_zip",
        chunks=(content,), max_bytes=1024, now=NOW,
    )
    coordinator.store_package(
        campaign_ref=second_campaign.campaign_ref, work_ref=second_window.work_ref,
        request_id=second_request.id, package_ref="package-artifact-second", ordinal=1,
        kind="metadata_zip", chunks=(content,), max_bytes=1024, now=NOW,
    )

    with repository._session_factory() as session:  # noqa: SLF001
        artifacts = session.scalars(select(SatArtifactRecord)).all()

    assert len(artifacts) == 2
    assert len({artifact.artifact_ref for artifact in artifacts}) == 2
    assert {artifact.sha256 for artifact in artifacts} == {sha256(content).hexdigest()}
    assert all("campaign-artifacts" not in artifact.artifact_ref for artifact in artifacts)
