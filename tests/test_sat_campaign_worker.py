from __future__ import annotations

from datetime import date, datetime, timezone
from hashlib import sha256
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from sqlalchemy import select

from cfdi_vault.db import create_engine_from_url, create_session_factory
from cfdi_vault.domain import QueueName, SatRequestState
from cfdi_vault.queueing import InMemoryQueue
from cfdi_vault.recovery_db import CfdiDocument, Tenant, XmlEvidence
from cfdi_vault.recovery_service import RecoveryService
from cfdi_vault.sat_campaign_artifacts import SatCampaignArtifactCoordinator
from cfdi_vault.sat_campaign_jobs import publish_artifact_parse_job
from cfdi_vault.sat_campaign_repository import SatCampaignRepository
from cfdi_vault.sat_contract import SatDownloadResult, SatOutcomeAction, SatVerificationResult
from cfdi_vault.sat_db_campaign_runner import SatCampaignRunner
from cfdi_vault.worker import RecoveryWorker

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


@pytest.mark.integration
def test_worker_consumes_metadata_artifact_reference(reset_postgres_database: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    engine = create_engine_from_url(reset_postgres_database)
    factory = create_session_factory(engine)
    with factory() as session:
        session.add(Tenant(id="worker-tenant", name="Synthetic", rfc="SYNTHETIC", created_at=NOW))
        session.commit()
    repository = SatCampaignRepository(factory)
    campaign = repository.create_campaign(
        campaign_ref="campaign-worker", tenant_id="worker-tenant", profile_ref="profile-worker",
        manifest_sha256="a" * 64, commit_ref="commit-worker", phase="metadata-proof",
        status="planned", budget=2, now=NOW,
    )
    window = repository.reserve_window(
        campaign_ref=campaign.campaign_ref, work_ref="window-worker", direction="received",
        start_date=date(2026, 1, 1), end_date=date(2026, 1, 14), now=NOW,
    )
    content = (
        "uuid~rfcEmisor~nombreEmisor~rfcReceptor~nombreReceptor~fechaEmision~montoTotal~"
        "estadoComprobante~tipoComprobante\n"
        "00000000-0000-4000-8000-000000000101~SYNTHETIC~Issuer~SYNTHETIC~Receiver~"
        "2026-01-01~1~Vigente~I\n"
    ).encode()
    archive = BytesIO()
    with ZipFile(archive, "w", ZIP_DEFLATED) as zipped:
        zipped.writestr("metadata.txt", content)
    package = archive.getvalue()
    storage_key = "sat-metadata/campaign-worker/package.zip"
    package_path = tmp_path / storage_key
    package_path.parent.mkdir(parents=True)
    package_path.write_bytes(package)
    artifact = repository.record_artifact(
        campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
        artifact_ref="artifact-worker", kind="metadata_zip", storage_key=storage_key,
        sha256=sha256(package).hexdigest(), size_bytes=len(package),
        validation_status="valid", now=NOW,
    )
    del artifact
    queue = InMemoryQueue()
    publish_artifact_parse_job(
        queue.publish, tenant_id="worker-tenant", artifact_ref="artifact-worker",
        kind="metadata_zip", now=NOW,
    )
    service = RecoveryService(
        database_url=reset_postgres_database, storage_root=tmp_path, queue=queue,
    )
    try:
        worker = RecoveryWorker(service)
        report = worker.run_once(queue_name=QueueName.CFDI_PARSE_METADATA.value)
        publish_artifact_parse_job(
            queue.publish, tenant_id="worker-tenant", artifact_ref="artifact-worker",
            kind="metadata_zip", now=NOW,
        )
        replay = worker.run_once(queue_name=QueueName.CFDI_PARSE_METADATA.value)
    finally:
        service.close()
        engine.dispose()

    assert report.processed == 1
    assert replay.processed == 0
    assert queue.pending_count(QueueName.CFDI_PARSE_METADATA.value) == 0


@pytest.mark.integration
def test_runner_downloads_once_then_worker_parses_reference(
    reset_postgres_database: str, tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    engine = create_engine_from_url(reset_postgres_database)
    factory = create_session_factory(engine)
    with factory() as session:
        session.add(Tenant(id="pipeline-tenant", name="Synthetic", rfc="SYNTHETIC", created_at=NOW))
        session.commit()
    repository = SatCampaignRepository(factory)
    campaign = repository.create_campaign(
        campaign_ref="campaign-pipeline", tenant_id="pipeline-tenant", profile_ref="profile-pipeline",
        manifest_sha256="b" * 64, commit_ref="commit-pipeline", phase="metadata-proof",
        status="planned", budget=2, now=NOW,
    )
    window = repository.reserve_window(
        campaign_ref=campaign.campaign_ref, work_ref="window-pipeline", direction="received",
        start_date=date(2026, 1, 1), end_date=date(2026, 1, 14), now=NOW,
    )
    repository.create_grant(
        campaign_ref=campaign.campaign_ref, grant_ref="grant-pipeline", phase="metadata-proof",
        reason="synthetic", budget=2, expires_at=NOW.replace(day=2), now=NOW,
    )
    submit_claim = repository.claim_operation(
        campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
        operation_kind="submit", idempotency_key="submit:pipeline", worker_ref="test",
        now=NOW, lease_until=NOW.replace(hour=13), grant_ref="grant-pipeline", require_grant=True,
    )
    repository.record_submission(
        claim_ref=submit_claim.claim_ref, campaign_ref=campaign.campaign_ref,
        work_ref=window.work_ref, tenant_id="pipeline-tenant", id_solicitud="request-pipeline",
        criteria_hash="c" * 64, direction="received", request_type="Metadata", requested_at=NOW,
        next_check_at=NOW, service_window_expires_at=NOW.replace(day=2), grant_ref="grant-pipeline",
    )
    content = (
        "uuid~rfcEmisor~nombreEmisor~rfcReceptor~nombreReceptor~fechaEmision~montoTotal~"
        "estadoComprobante~tipoComprobante\n"
        "00000000-0000-4000-8000-000000000102~SYNTHETIC~Issuer~SYNTHETIC~Receiver~"
        "2026-01-01~1~Vigente~I\n"
    ).encode()
    archive = BytesIO()
    with ZipFile(archive, "w", ZIP_DEFLATED) as zipped:
        zipped.writestr("metadata.txt", content)
    package = archive.getvalue()
    queue = InMemoryQueue()
    coordinator = SatCampaignArtifactCoordinator(
        repository, str(tmp_path), job_publisher=queue.publish,
    )

    class Verifier:
        def verify_request(self, request_id: str) -> SatVerificationResult:
            return SatVerificationResult(
                request_id=request_id, state=SatRequestState.FINISHED, sat_code="5000",
                message="synthetic", package_ids=("package-pipeline",),
            )

    class Downloader:
        def download_package(self, package_id: str) -> SatDownloadResult:
            return SatDownloadResult(
                package_id=package_id, sat_code="5000", message="synthetic",
                action=SatOutcomeAction.FINISHED, content=package,
            )

    report = SatCampaignRunner(
        repository, lambda _request_id: Verifier(), campaign_ref=campaign.campaign_ref,
        grant_ref="grant-pipeline", downloader_factory=lambda _package_id: Downloader(),
        artifact_coordinator=coordinator,
    ).run(now=NOW)
    service = RecoveryService(
        database_url=reset_postgres_database, storage_root=tmp_path, queue=queue,
    )
    try:
        worker_report = RecoveryWorker(service).run_once(
            queue_name=QueueName.CFDI_PARSE_METADATA.value,
        )
    finally:
        service.close()
        engine.dispose()

    assert report.package_count == 1
    assert queue.pending_count(QueueName.CFDI_PARSE_METADATA.value) == 0
    assert worker_report.processed == 1


@pytest.mark.integration
def test_worker_stores_campaign_xml_under_opaque_key_without_reading_zip_bytes(
    reset_postgres_database: str, tmp_path, sample_xml: bytes,
) -> None:  # type: ignore[no-untyped-def]
    """Campaign XML evidence must not expose UUIDs or materialize its ZIP."""

    engine = create_engine_from_url(reset_postgres_database)
    factory = create_session_factory(engine)
    with factory() as session:
        session.add(Tenant(id="xml-worker-tenant", name="Synthetic", rfc="SYNTHETIC", created_at=NOW))
        session.commit()
    repository = SatCampaignRepository(factory)
    campaign = repository.create_campaign(
        campaign_ref="campaign-xml-worker", tenant_id="xml-worker-tenant", profile_ref="profile-xml-worker",
        manifest_sha256="d" * 64, commit_ref="commit-xml-worker", phase="cfdi-proof",
        status="planned", budget=2, now=NOW,
    )
    window = repository.reserve_window(
        campaign_ref=campaign.campaign_ref, work_ref="window-xml-worker", direction="received",
        start_date=date(2026, 1, 1), end_date=date(2026, 1, 14), now=NOW,
    )
    archive = BytesIO()
    with ZipFile(archive, "w", ZIP_DEFLATED) as zipped:
        zipped.writestr("invoice.xml", sample_xml)
    package = archive.getvalue()
    storage_key = "sat-cfdi/input/package.zip"
    package_path = tmp_path / storage_key
    package_path.parent.mkdir(parents=True)
    package_path.write_bytes(package)
    repository.record_artifact(
        campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
        artifact_ref="artifact-xml-worker", kind="cfdi_zip", storage_key=storage_key,
        sha256=sha256(package).hexdigest(), size_bytes=len(package),
        validation_status="valid", now=NOW,
    )
    queue = InMemoryQueue()
    publish_artifact_parse_job(
        queue.publish, tenant_id="xml-worker-tenant", artifact_ref="artifact-xml-worker",
        kind="cfdi_zip", now=NOW,
    )
    service = RecoveryService(
        database_url=reset_postgres_database, storage_root=tmp_path, queue=queue,
    )
    try:
        worker = RecoveryWorker(service)
        report = worker.run_once(queue_name=QueueName.CFDI_PARSE_XML.value)
        publish_artifact_parse_job(
            queue.publish, tenant_id="xml-worker-tenant", artifact_ref="artifact-xml-worker",
            kind="cfdi_zip", now=NOW,
        )
        replay = worker.run_once(queue_name=QueueName.CFDI_PARSE_XML.value)
        with factory() as session:
            evidence = session.scalars(select(XmlEvidence)).all()
            documents = session.scalars(select(CfdiDocument)).all()
    finally:
        service.close()
        engine.dispose()

    assert report.processed == 1
    assert replay.processed == 0
    assert len(evidence) == 1
    assert len(documents) == 1
    uuid = documents[0].uuid
    key = evidence[0].storage_key
    assert key.startswith("sat-cfdi/")
    assert "/xml/" in key
    assert key.endswith(".xml")
    assert uuid not in key
    assert (tmp_path / key).is_file()
    assert queue.pending_count(QueueName.CFDI_PARSE_XML.value) == 0
