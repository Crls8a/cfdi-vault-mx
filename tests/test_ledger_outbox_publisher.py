from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from cfdi_vault.accounting_ledger_outbox_v6 import OutboxClaim
from cfdi_vault.ledger_outbox_publisher import (
    LedgerOutboxEnvelope,
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
        return True

    def mark_outbox_uncertain(
        self, event_id: str, claim_id: str, reason_code: str, *, now: datetime | None = None
    ) -> bool:
        self.calls.append(("uncertain", (event_id, claim_id, reason_code, now)))
        return True


class FakePublisher:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.messages: list[LedgerOutboxEnvelope] = []

    def publish(self, message: LedgerOutboxEnvelope) -> None:
        self.messages.append(message)
        if self.error is not None:
            raise self.error


def _publisher(store: FakeStore, broker: FakePublisher) -> LedgerOutboxPublisher:
    return LedgerOutboxPublisher(store, broker, lease=timedelta(minutes=5))


def test_claim_happens_before_publish_and_confirmation_before_close() -> None:
    store = FakeStore()
    broker = FakePublisher()
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "published", "reason_code": None}
    assert [name for name, _value in store.calls] == ["claim", "published"]
    assert len(broker.messages) == 1
    assert broker.messages[0].event_id == "event-synthetic"


@pytest.mark.parametrize("error", [OutboxPublishFailure("broker_rejected"), OutboxPublishFailure()])
def test_known_publish_failure_is_categorized_and_fenced(error: Exception) -> None:
    store = FakeStore()
    broker = FakePublisher(error)
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.status == "failed"
    assert store.calls[-1][0] == "failed"
    assert store.calls[-1][1][2] in {"broker_rejected", "publish_failed"}


@pytest.mark.parametrize("error", [TimeoutError(), OutboxPublishAmbiguous()])
def test_ambiguous_confirmation_is_uncertain_and_not_retried(error: Exception) -> None:
    store = FakeStore()
    broker = FakePublisher(error)
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "uncertain", "reason_code": "publish_uncertain"}
    assert store.calls[-1][0] == "uncertain"


def test_stale_fencing_result_never_reports_published() -> None:
    store = FakeStore(publish_result=False)
    broker = FakePublisher()
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.status == "stale"
    assert result.reason_code == "stale_claim"


def test_missing_artifact_is_rejected_before_broker_io() -> None:
    store = FakeStore(claim=_claim(artifact_ref=None))
    broker = FakePublisher()
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.as_dict() == {"status": "invalid", "reason_code": "invalid_reference"}
    assert broker.messages == []
    assert store.calls[-1][0] == "failed"


def test_envelope_contains_only_reference_fields_and_redacts_repr() -> None:
    envelope = _publisher(FakeStore(), FakePublisher())._envelope(_claim(), NOW)
    payload = envelope.as_dict()

    assert {
        "event_id",
        "job_id",
        "job_type",
        "artifact_ref",
        "schema_version",
        "idempotency_key",
        "correlation_id",
    } <= payload.keys()
    forbidden = {"payload", "xml", "zip", "txt", "rfc", "uuid", "rows", "amounts", "soap", "secret"}
    assert forbidden.isdisjoint(payload)
    assert "event-synthetic" not in repr(envelope)
    assert "artifact-synthetic" not in repr(envelope)


def test_no_due_event_does_not_touch_broker() -> None:
    store = FakeStore(claim=None)
    broker = FakePublisher()
    result = _publisher(store, broker).run_once(now=NOW, worker_ref="publisher-synthetic")

    assert result.status == "idle"
    assert broker.messages == []
