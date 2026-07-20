from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from cfdi_vault.accounting_ledger_jobs_v6 import LedgerJobStoreV6
from cfdi_vault.db import create_engine_from_url

pytestmark = pytest.mark.integration
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _store(database_url: str) -> LedgerJobStoreV6:
    return LedgerJobStoreV6(create_engine_from_url(database_url))


def _seed(database_url: str) -> LedgerJobStoreV6:
    engine = create_engine_from_url(database_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO tenants (id, name, rfc, created_at) "
                "VALUES ('outbox-synthetic', 'Synthetic Tenant', 'SYNTHETIC', :now)"
            ),
            {"now": NOW},
        )
    engine.dispose()
    store = _store(database_url)
    assert store.create_job(
        job_id="outbox-job",
        tenant_id="outbox-synthetic",
        job_type="metadata_parse",
        queue_name="cfdi.parse.metadata",
        artifact_ref="outbox-artifact",
        idempotency_key="outbox-idem",
        available_at=NOW,
    )
    return store


def test_outbox_and_inbox_are_idempotent_and_reason_codes_are_redacted(reset_postgres_database: str) -> None:
    store = _seed(reset_postgres_database)
    kwargs = {
        "event_id": "event-synthetic",
        "job_id": "outbox-job",
        "event_type": "metadata_parse",
        "routing_key": "cfdi.parse.metadata",
        "idempotency_key": "event-idem",
        "available_at": NOW,
    }
    assert store.create_outbox_event(**kwargs)
    assert not store.create_outbox_event(**kwargs)
    claim = store.claim_outbox_event(now=NOW, worker_ref="publisher-synthetic", lease=timedelta(minutes=5))
    assert claim is not None and "event-synthetic" not in repr(claim)
    assert store.mark_outbox_failed(claim.event_id, claim.claim_id, "publish.v1-failed", now=NOW)
    retry_time = NOW + timedelta(seconds=5)
    retry = store.claim_outbox_event(
        now=retry_time,
        worker_ref="publisher-synthetic",
        lease=timedelta(minutes=5),
    )
    assert retry is not None
    assert store.mark_outbox_published(retry.event_id, retry.claim_id, now=retry_time)
    assert not store.mark_outbox_published(retry.event_id, retry.claim_id, now=retry_time)
    assert store.register_inbox_event(retry.event_id, "ledger-worker", received_at=NOW).status == "new"
    assert store.register_inbox_event(retry.event_id, "ledger-worker", received_at=NOW).status == "in_flight"
    assert store.mark_inbox_processed(retry.event_id, "ledger-worker", "parse.v1-failed", now=NOW)
    assert not store.mark_inbox_processed(retry.event_id, "ledger-worker", "parse.v1-failed", now=NOW)


def test_inbox_receipt_reclaims_unprocessed_delivery_after_lease(reset_postgres_database: str) -> None:
    store = _seed(reset_postgres_database)
    assert store.create_outbox_event(
        event_id="reclaim-event",
        job_id="outbox-job",
        event_type="metadata_parse",
        routing_key="cfdi.parse.metadata",
        idempotency_key="reclaim-idem",
        available_at=NOW,
    )
    first = store.register_inbox_event("reclaim-event", "ledger-worker", received_at=NOW)
    assert first.status == "new"
    assert store.register_inbox_event("reclaim-event", "ledger-worker", received_at=NOW).status == "in_flight"
    reclaimed = store.register_inbox_event("reclaim-event", "ledger-worker", received_at=NOW + timedelta(minutes=31))
    assert reclaimed.status == "reclaimed"


def test_outbox_does_not_claim_before_availability(reset_postgres_database: str) -> None:
    store = _seed(reset_postgres_database)
    assert store.create_outbox_event(
        event_id="future-event",
        job_id="outbox-job",
        event_type="metadata_parse",
        routing_key="cfdi.parse.metadata",
        idempotency_key="future-idem",
        available_at=NOW + timedelta(hours=1),
    )
    assert store.claim_outbox_event(now=NOW, worker_ref="publisher-synthetic", lease=timedelta(minutes=5)) is None


def test_outbox_failure_uses_capped_backoff_and_remains_retryable(reset_postgres_database: str) -> None:
    store = _seed(reset_postgres_database)
    assert store.create_outbox_event(
        event_id="backoff-event",
        job_id="outbox-job",
        event_type="metadata_parse",
        routing_key="cfdi.parse.metadata",
        idempotency_key="backoff-idem",
        available_at=NOW,
    )

    first = store.claim_outbox_event(NOW, "publisher-synthetic", timedelta(minutes=5))
    assert first is not None
    assert store.mark_outbox_failed(first.event_id, first.claim_id, "publish_uncertain", now=NOW)
    assert store.claim_outbox_event(NOW + timedelta(seconds=4), "publisher-synthetic", timedelta(minutes=5)) is None

    second_time = NOW + timedelta(seconds=5)
    second = store.claim_outbox_event(second_time, "publisher-synthetic", timedelta(minutes=5))
    assert second is not None
    assert store.mark_outbox_failed(second.event_id, second.claim_id, "publish_uncertain", now=second_time)
    assert (
        store.claim_outbox_event(second_time + timedelta(seconds=29), "publisher-synthetic", timedelta(minutes=5))
        is None
    )

    third_time = second_time + timedelta(seconds=30)
    third = store.claim_outbox_event(third_time, "publisher-synthetic", timedelta(minutes=5))
    assert third is not None
    assert store.mark_outbox_failed(third.event_id, third.claim_id, "publish_uncertain", now=third_time)
    assert (
        store.claim_outbox_event(
            third_time + timedelta(minutes=4, seconds=59), "publisher-synthetic", timedelta(minutes=5)
        )
        is None
    )
    fourth = store.claim_outbox_event(third_time + timedelta(minutes=5), "publisher-synthetic", timedelta(minutes=5))
    assert fourth is not None


def test_expired_outbox_claim_cannot_fence_new_owner(reset_postgres_database: str) -> None:
    store = _seed(reset_postgres_database)
    assert store.create_outbox_event(
        event_id="fenced-event",
        job_id="outbox-job",
        event_type="xml_parse",
        routing_key="cfdi.parse.xml",
        idempotency_key="fenced-idem",
        available_at=NOW,
    )
    first = store.claim_outbox_event(NOW, "publisher-one", timedelta(minutes=1))
    assert first is not None
    second = store.claim_outbox_event(NOW + timedelta(minutes=2), "publisher-two", timedelta(minutes=5))
    assert second is not None and second.claim_id != first.claim_id
    assert not store.mark_outbox_published(first.event_id, first.claim_id, now=NOW + timedelta(minutes=2))
    assert store.mark_outbox_published(second.event_id, second.claim_id, now=NOW + timedelta(minutes=2))
