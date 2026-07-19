from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from cfdi_vault.accounting_ledger_jobs_v6 import LedgerJobStoreV6
from cfdi_vault.accounting_ledger_worker import LedgerParseAggregate, LedgerParseJob
from cfdi_vault.db import create_engine_from_url
from cfdi_vault.domain import QueueName

pytestmark = pytest.mark.integration
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _store(database_url: str) -> LedgerJobStoreV6:
    return LedgerJobStoreV6(create_engine_from_url(database_url))


def _tenant(database_url: str) -> None:
    engine = create_engine_from_url(database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO tenants (id, name, rfc, created_at) "
                "VALUES ('ledger-synthetic', 'Synthetic Tenant', 'SYNTHETIC', :now)"
            ),
            {"now": NOW},
        )
    engine.dispose()


def _create(store: LedgerJobStoreV6, suffix: str = "a") -> bool:
    return store.create_job(
        job_id=f"job-{suffix}",
        tenant_id="ledger-synthetic",
        job_type="metadata_parse",
        queue_name="cfdi.parse.metadata",
        artifact_ref=f"artifact-{suffix}",
        idempotency_key=f"idem-{suffix}",
        available_at=NOW,
    )


def test_job_claim_completion_is_idempotent_and_status_is_sanitized(reset_postgres_database: str) -> None:
    _tenant(reset_postgres_database)
    store = _store(reset_postgres_database)
    assert _create(store)
    assert not _create(store)
    claim = store.claim_job(now=NOW, worker_ref="worker-synthetic", lease=timedelta(minutes=5))
    assert claim is not None
    assert store.claim_job(now=NOW, worker_ref="worker-second", lease=timedelta(minutes=5)) is None
    assert store.mark_running(claim.claim_id, now=NOW)
    aggregate = LedgerParseAggregate(records_seen=2, records_written=1, invalid=1)
    assert store.complete_job(claim.claim_id, aggregate, now=NOW)
    assert not store.complete_job(claim.claim_id, aggregate, now=NOW)
    status = store.get_job_status("job-a")
    assert status is not None and status.status == "succeeded"
    assert status.aggregate_counts == {"records": 2, "eligible": 1, "unknown": 1}
    assert "artifact-a" not in repr(status)
    assert "job-a" not in repr(status)


def test_expired_claim_is_closed_before_retry_and_uncertain_is_not_retried(reset_postgres_database: str) -> None:
    _tenant(reset_postgres_database)
    store = _store(reset_postgres_database)
    _create(store)
    first = store.claim_job(now=NOW, worker_ref="worker-one", lease=timedelta(minutes=1))
    assert first is not None
    second = store.claim_job(now=NOW + timedelta(minutes=2), worker_ref="worker-two", lease=timedelta(minutes=1))
    assert second is not None and second.claim_id != first.claim_id and second.attempt == 2
    assert store.mark_uncertain(second.claim_id, "download.v1-uncertain", now=NOW + timedelta(minutes=2))
    assert (
        store.claim_job(now=NOW + timedelta(minutes=3), worker_ref="worker-three", lease=timedelta(minutes=1)) is None
    )


def test_worker_protocol_claims_exact_artifact_and_uses_v5_aggregate(reset_postgres_database: str) -> None:
    _tenant(reset_postgres_database)
    store = _store(reset_postgres_database)
    job = LedgerParseJob("ledger-synthetic", "artifact-protocol", QueueName.CFDI_PARSE_METADATA, "idem-protocol")
    assert store.create_job(
        job_id="job-protocol",
        tenant_id=job.tenant_id,
        job_type=job.queue.value,
        queue_name=job.queue.value,
        artifact_ref=job.artifact_ref,
        idempotency_key=job.idempotency_key,
        available_at=NOW,
    )
    wrong_artifact = LedgerParseJob(
        "ledger-synthetic", "artifact-other", QueueName.CFDI_PARSE_METADATA, "idem-protocol"
    )
    assert not store.claim_parse_job(wrong_artifact, worker_ref="worker-protocol", now=NOW).accepted
    claim = store.claim_parse_job(job, worker_ref="worker-protocol", now=NOW)
    assert claim.accepted
    store.complete_parse_job(claim.claim_ref, LedgerParseAggregate(concepts=1), now=NOW)
    assert store.get_job_status("job-protocol").status == "succeeded"  # type: ignore[union-attr]


def test_two_workers_claim_distinct_jobs(reset_postgres_database: str) -> None:
    _tenant(reset_postgres_database)
    store = _store(reset_postgres_database)
    assert _create(store, "a") and _create(store, "b")

    def claim(worker: str):  # type: ignore[no-untyped-def]
        local = _store(reset_postgres_database)
        return local.claim_job(now=NOW, worker_ref=worker, lease=timedelta(minutes=5))

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(claim, ("worker-one", "worker-two")))
    assert {item.job_id for item in claims if item is not None} == {"job-a", "job-b"}


def test_unknown_aggregate_fields_are_rejected(reset_postgres_database: str) -> None:
    _tenant(reset_postgres_database)
    store = _store(reset_postgres_database)
    with pytest.raises(ValueError, match="unsupported counter"):
        store.create_job(
            job_id="job-invalid",
            tenant_id="ledger-synthetic",
            job_type="metadata_parse",
            queue_name="cfdi.parse.metadata",
            artifact_ref="artifact-invalid",
            idempotency_key="idem-invalid",
            aggregate_counts={"raw_payload": 1},
        )
