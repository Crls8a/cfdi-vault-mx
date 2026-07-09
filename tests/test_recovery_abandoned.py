from __future__ import annotations

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select

from cfdi_vault.cache_recovery import AbandonedJobObservation
from cfdi_vault.domain import DownloadDirection, JobStatus, RequestType
from cfdi_vault.recovery_db import DownloadJob, QueueJobEvent
from cfdi_vault.recovery_service import RecoveryService, build_default_query


def test_recovery_service_conditionally_persists_abandoned_job_transition(
    tmp_path,
    reset_postgres_database: str,
) -> None:
    service = RecoveryService(
        database_url=reset_postgres_database,
        storage_root=tmp_path / "storage",
    )
    try:
        queued = service.sync_metadata(
            build_default_query(
                tenant_id="tenant-demo",
                rfc="XAXX010101000",
                direction=DownloadDirection.RECEIVED,
                request_type=RequestType.METADATA,
                start=datetime(2024, 1, 1, tzinfo=timezone.utc),
                end=datetime(2024, 1, 31, tzinfo=timezone.utc),
            ),
            enqueue=True,
        )
        progress = service.progress(queued.job_id)
        assert progress is not None
        assert progress["job_id"] == queued.job_id
        assert progress["tenant_id"] == "tenant-demo"
        assert progress["worker_ref"] == "unassigned"
        assert progress["status"] == "pending"
        assert progress["percent"] == 0
        assert set(progress) == {
            "job_id",
            "tenant_id",
            "worker_ref",
            "status",
            "percent",
            "updated_at",
        }
        with service.session_factory() as session:
            job = session.get(DownloadJob, queued.job_id)
            assert job is not None
            job.status = JobStatus.RUNNING.value
            session.commit()

        observation = AbandonedJobObservation(
            job_id=queued.job_id,
            tenant_id="tenant-demo",
            worker_ref="worker-001",
            observed_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
            reason_code="worker_heartbeat_stale",
        )

        assert service.mark_job_abandoned(observation) is True
        assert service.mark_job_abandoned(observation) is False

        with service.session_factory() as session:
            job = session.get(DownloadJob, queued.job_id)
            event = session.scalar(
                select(QueueJobEvent)
                .where(QueueJobEvent.job_id == queued.job_id)
                .order_by(QueueJobEvent.id.desc())
            )
        assert job is not None
        assert job.status == JobStatus.RETRY_SCHEDULED.value
        assert job.updated_at == observation.observed_at
        assert event is not None
        assert event.status == JobStatus.RETRY_SCHEDULED.value
        assert event.message == "worker_heartbeat_stale"
        assert event.payload == {}
    finally:
        service.close()


def test_recovery_service_rejects_cross_tenant_abandoned_observation(
    tmp_path,
    reset_postgres_database: str,
) -> None:
    service = RecoveryService(
        database_url=reset_postgres_database,
        storage_root=tmp_path / "storage",
    )
    try:
        observation = AbandonedJobObservation(
            job_id="job-missing",
            tenant_id="tenant-demo",
            worker_ref="worker-001",
            observed_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
            reason_code="worker_heartbeat_missing",
        )
        assert service.mark_job_abandoned(observation) is False
    finally:
        service.close()


def test_concurrent_abandoned_observations_create_one_transition_and_one_audit(
    tmp_path,
    reset_postgres_database: str,
) -> None:
    service = RecoveryService(
        database_url=reset_postgres_database,
        storage_root=tmp_path / "storage",
    )
    try:
        queued = service.sync_metadata(
            build_default_query(
                tenant_id="tenant-demo",
                rfc="XAXX010101000",
                direction=DownloadDirection.RECEIVED,
                request_type=RequestType.METADATA,
                start=datetime(2024, 2, 1, tzinfo=timezone.utc),
                end=datetime(2024, 2, 29, tzinfo=timezone.utc),
            ),
            enqueue=True,
        )
        with service.session_factory() as session:
            job = session.get(DownloadJob, queued.job_id)
            assert job is not None
            job.status = JobStatus.RUNNING.value
            session.commit()
        observation = AbandonedJobObservation(
            job_id=queued.job_id,
            tenant_id="tenant-demo",
            worker_ref="worker-001",
            observed_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
            reason_code="worker_heartbeat_stale",
        )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(service.mark_job_abandoned, [observation, observation]))

        with service.session_factory() as session:
            events = session.scalars(
                select(QueueJobEvent).where(
                    QueueJobEvent.job_id == queued.job_id,
                    QueueJobEvent.message == "worker_heartbeat_stale",
                )
            ).all()
        assert sorted(results) == [False, True]
        assert len(events) == 1
    finally:
        service.close()
