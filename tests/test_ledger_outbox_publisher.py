from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from cfdi_vault.accounting_ledger_outbox_v6 import OutboxClaim
from cfdi_vault.domain import QueueMessage
from cfdi_vault.ledger_outbox_publisher import (
    LedgerOutboxPublisher,
    OutboxPublishAmbiguous,
    OutboxPublishFailure,
)

NOW = datetime(2026, 1, 14, 12, tzinfo=timezone.utc)


def _claim(*, artifact_ref: str | None = "artifact-synthetic") -> OutboxClaim:
    return OutboxClaim(
        event_id="event-synthetic",
        job_id="job-synthetic",
        claim_id="claim-synthetic",
        event_type="metadata_parse",
        routing_key="cfdi.parse.metadata",
        tenant_id="tenant-synthetic",
        job_type="metadata_parse",
        artifact_ref=artifact_ref,
        queue_name="cfdi.parse.metadata",
        idempotency_key="event-idempotency",
        schema_version=1,
    )


@dataclass
class FakeStore:
    claim: OutboxClaim | None = _claim()
    publish_result: bool = True
    failure_result: bool = True
    uncertain_result: bool = True

    def __post_init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def claim_outbox_event(self, now: datetime, worker_ref: str, lease: timedelta) -> OutboxClaim | None:
        self.calls.append(("claim", (now, worker_ref, lease)))
        return self.claim

    def mark_outbox_published(self, event_id: str, claim_id: str, *, now: datetime | None = None) -> bool:
        self.calls.append(("published", (event_id, claim_id, now)))
        return self.publish_result

    def mark_outbox_failed(
        self, event_id: str, claim_id: str, reason_code: str, *, now: datetime | None = None
    ) -> bool:
        self.calls.append(("failed", (event_id, claim_id, reason_code, now)))
        return self.failure_result

    def mark_outbox_uncertain(
        self, event_id: str, claim_id: str, reason_code: str, *, now: datetime | None = None
    ) -> bool:
        self.calls.append(("uncertain", (event_id, claim_id, reason_code, now)))
        return self.uncertain_result


class FakePublisher:
    def __init__(self, error: Exception | None = None, confirmed: bool | None = True) -> None:
        self.error = error
        self.confirmed = confirmed
        self.messages: list[QueueMessage] = []

    def publish(self, message: QueueMessage) -> bool | None:
        self.messages.append(message)
        if self.error is not None:
            raise self.error
        return self.confirmed


def _publisher(store: FakeStore, broker: FakePublisher) -> LedgerOutboxPublisher:
    return LedgerOutboxPublisher(store, broker, lease=timedelta(minutes=5))


def test_claim_happens_before_publish_and_confirmation_before_close() -> None:
    store = FakeStore()
    broker = FakePublisher()
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "published", "reason_code": None}
    assert [name for name, _value in store.calls] == ["claim", "published"]
    assert len(broker.messages) == 1
    assert broker.messages[0].message_id == "event-synthetic"


@pytest.mark.parametrize("error", [OutboxPublishFailure("broker_rejected"), OutboxPublishFailure()])
def test_known_publish_failure_is_categorized_and_fenced(error: Exception) -> None:
    store = FakeStore()
    broker = FakePublisher(error)
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.status == "failed"
    assert store.calls[-1][0] == "failed"
    assert store.calls[-1][1][2] in {"broker_rejected", "publish_failed"}


@pytest.mark.parametrize("error", [TimeoutError(), OutboxPublishAmbiguous()])
def test_ambiguous_confirmation_remains_retryable(error: Exception) -> None:
    store = FakeStore()
    broker = FakePublisher(error)
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "failed", "reason_code": "publish_uncertain"}
    assert store.calls[-1][0] == "failed"


def test_stale_fencing_result_never_reports_published() -> None:
    store = FakeStore(publish_result=False)
    broker = FakePublisher()
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.status == "stale"
    assert result.reason_code == "stale_claim"


def test_unconfirmed_publish_remains_retryable_and_not_marked_published() -> None:
    store = FakeStore()
    broker = FakePublisher(confirmed=None)

    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "failed", "reason_code": "publish_uncertain"}
    assert store.calls[-1][0] == "failed"


def test_failed_close_is_reported_as_stale() -> None:
    store = FakeStore(publish_result=False)
    broker = FakePublisher()

    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "stale", "reason_code": "stale_claim"}


def test_failed_ambiguous_close_is_reported_as_stale() -> None:
    store = FakeStore(failure_result=False)
    broker = FakePublisher(error=TimeoutError())

    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "stale", "reason_code": "stale_claim"}


def test_parse_artifact_reference_is_required_before_broker_io() -> None:
    store = FakeStore(claim=_claim(artifact_ref=None))
    broker = FakePublisher()
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "invalid", "reason_code": "invalid_reference"}
    assert broker.messages == []
    assert store.calls[-1][0] == "uncertain"


def test_envelope_contains_only_reference_fields_and_redacts_repr() -> None:
    envelope = _publisher(FakeStore(), FakePublisher())._envelope(_claim(), NOW)
    payload = envelope.as_dict()

    assert {"queue", "message_id", "job_id", "idempotency_key", "correlation_id"} <= payload.keys()
    assert "artifact_ref" not in payload
    forbidden = {"payload", "xml", "zip", "txt", "rfc", "uuid", "rows", "amounts", "soap", "secret"}
    assert forbidden.isdisjoint(payload)
    decoded = QueueMessage.from_dict(payload)
    assert decoded == envelope
    assert "artifact-synthetic" not in repr(envelope)


def test_dispatch_metadata_mismatch_is_rejected_before_broker_io() -> None:
    claim = _claim()
    claim = OutboxClaim(
        claim.event_id,
        claim.job_id,
        claim.claim_id,
        claim.event_type,
        "cfdi.parse.xml",
        claim.tenant_id,
        claim.job_type,
        claim.artifact_ref,
        claim.queue_name,
        claim.idempotency_key,
        claim.schema_version,
    )
    store = FakeStore(claim=claim)
    broker = FakePublisher()

    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "invalid", "reason_code": "invalid_reference"}
    assert broker.messages == []
    assert store.calls[-1][0] == "uncertain"


def test_future_schema_version_is_rejected_before_broker_io() -> None:
    claim = _claim()
    claim = OutboxClaim(
        claim.event_id,
        claim.job_id,
        claim.claim_id,
        claim.event_type,
        claim.routing_key,
        claim.tenant_id,
        claim.job_type,
        claim.artifact_ref,
        claim.queue_name,
        claim.idempotency_key,
        2,
    )
    store = FakeStore(claim=claim)
    broker = FakePublisher()

    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "invalid", "reason_code": "invalid_reference"}
    assert broker.messages == []


def test_unclassified_broker_exception_remains_retryable() -> None:
    store = FakeStore()
    broker = FakePublisher(Exception("transport detail must not escape"))

    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "failed", "reason_code": "publish_uncertain"}
    assert store.calls[-1][0] == "failed"


def test_no_due_event_does_not_touch_broker() -> None:
    store = FakeStore(claim=None)
    broker = FakePublisher()
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.status == "idle"
    assert broker.messages == []
