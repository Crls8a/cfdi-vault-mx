from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cfdi_vault.accounting_ledger_worker import (
    LedgerClaim,
    LedgerParseAggregate,
    LedgerParseError,
    LedgerParseJob,
    LedgerWorker,
    LedgerWorkerReport,
)
from cfdi_vault.domain import QueueMessage, QueueName

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class FakeDurableStore:
    """Test double for the future V6 durable claim/outbox repository."""

    def __init__(self, *, accepted: bool = True) -> None:
        self.accepted = accepted
        self.transaction_open = False
        self.events: list[str] = []
        self.completed: list[LedgerParseAggregate] = []
        self.failed: list[str] = []

    def claim_parse_job(self, job, *, worker_ref, now):  # type: ignore[no-untyped-def]
        self.transaction_open = True
        self.events.append("claim")
        claim = LedgerClaim(claim_ref="claim-ref", accepted=self.accepted)
        self.transaction_open = False
        return claim

    def complete_parse_job(self, claim_ref, aggregate, *, now):  # type: ignore[no-untyped-def]
        assert not self.transaction_open
        self.events.append("complete")
        self.completed.append(aggregate)

    def fail_parse_job(self, claim_ref, reason_code, *, now):  # type: ignore[no-untyped-def]
        assert not self.transaction_open
        self.events.append("fail")
        self.failed.append(reason_code)


def _message() -> QueueMessage:
    return QueueMessage(
        queue=QueueName.CFDI_PARSE_METADATA,
        tenant_id="tenant-synthetic",
        job_id="artifact-synthetic",
        correlation_id="artifact-synthetic",
        message_id="message-synthetic",
        idempotency_key="parse:artifact-synthetic",
        created_at=NOW,
    )


def test_worker_claims_before_parser_and_completes_after_transaction() -> None:
    store = FakeDurableStore()
    worker = LedgerWorker(store, worker_ref="worker-synthetic", clock=lambda: NOW)
    observed: list[bool] = []

    def parse(job):  # type: ignore[no-untyped-def]
        observed.append(store.transaction_open)
        return LedgerParseAggregate(records_seen=3, records_written=2, duplicates=1)

    report = worker.run_once(_message(), parse)

    assert observed == [False]
    assert store.events == ["claim", "complete"]
    assert report.status == "succeeded"
    assert report.aggregate.records_written == 2


def test_duplicate_claim_is_acknowledged_without_parser_or_external_effect() -> None:
    store = FakeDurableStore(accepted=False)
    worker = LedgerWorker(store, worker_ref="worker-synthetic", clock=lambda: NOW)
    called = False

    def parse(job):  # type: ignore[no-untyped-def]
        nonlocal called
        called = True
        return LedgerParseAggregate(records_seen=1)

    report = worker.run_once(_message(), parse)

    assert report.status == "duplicate"
    assert report.aggregate == LedgerParseAggregate()
    assert called is False
    assert store.events == ["claim"]


def test_parser_failure_is_categorized_without_raw_error() -> None:
    store = FakeDurableStore()
    worker = LedgerWorker(store, worker_ref="worker-synthetic", clock=lambda: NOW)

    def parse(job):  # type: ignore[no-untyped-def]
        raise LedgerParseError("parse_invalid")

    report = worker.run_once(_message(), parse)

    assert report.status == "failed"
    assert report.reason_code == "parse_invalid"
    assert store.events == ["claim", "fail"]
    assert store.failed == ["parse_invalid"]
    assert "artifact" not in report.as_dict()
    assert "message" not in report.as_dict()


def test_job_rejects_non_parse_queue_and_aggregate_rejects_fiscal_values() -> None:
    message = QueueMessage(
        queue=QueueName.SAT_REQUEST,
        tenant_id="tenant-synthetic",
        job_id="job-synthetic",
        correlation_id="job-synthetic",
        message_id="message-synthetic",
        created_at=NOW,
    )
    with pytest.raises(ValueError, match="parse queue"):
        LedgerParseJob.from_message(message)
    with pytest.raises(ValueError, match="aggregate count"):
        LedgerParseAggregate(records_seen=-1)


def test_reference_values_are_redacted_from_repr_and_direct_jobs_are_validated() -> None:
    job = LedgerParseJob.from_message(_message())
    claim = LedgerClaim(claim_ref="claim-synthetic", accepted=True)
    report = LedgerWorkerReport(status="succeeded")

    for rendered in (repr(job), repr(claim), repr(report)):
        assert "tenant-synthetic" not in rendered
        assert "artifact-synthetic" not in rendered
        assert "parse:artifact-synthetic" not in rendered
        assert "claim-synthetic" not in rendered

    with pytest.raises(ValueError, match="parse queue"):
        LedgerParseJob(
            tenant_id="tenant-synthetic",
            artifact_ref="artifact-synthetic",
            queue=QueueName.SAT_REQUEST,
            idempotency_key="parse:artifact-synthetic",
        )
    with pytest.raises(TypeError, match="boolean"):
        LedgerClaim(claim_ref="claim-synthetic", accepted=1)  # type: ignore[arg-type]
