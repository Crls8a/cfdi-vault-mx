from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_contract import DeliveryAction, QueueAuditEvent, RetryPolicy, WorkerJobEnvelope, WorkerJobType


NOW = datetime(2026, 7, 9, tzinfo=timezone.utc)


def _message() -> QueueMessage:
    return QueueMessage(
        queue=QueueName.CFDI_PARSE_XML,
        tenant_id="synthetic-tenant",
        profile_id="profile-ref-001",
        job_id="job-001",
        correlation_id="correlation-001",
        created_at=NOW,
        message_id="message-001",
        idempotency_key="idem-001",
    )


def test_queue_message_round_trip_preserves_versioned_delivery_metadata() -> None:
    message = _message()

    restored = QueueMessage.from_dict(message.as_dict())

    assert restored == message
    assert restored.envelope_version == 1
    assert restored.message_id == "message-001"
    assert restored.idempotency_key == "idem-001"
    assert restored.attempt == 0


@pytest.mark.parametrize("field,value", [("attempt", True), ("attempt", 1.5), ("attempt", "1"), ("envelope_version", False), ("envelope_version", "1")])
def test_queue_message_from_dict_rejects_coerced_integer_fields(field: str, value: object) -> None:
    payload = _message().as_dict()
    payload[field] = value

    with pytest.raises((TypeError, ValueError), match=field):
        QueueMessage.from_dict(payload)


@pytest.mark.parametrize("forbidden", ["rfc", "uuid", "criteria", "payload", "xml", "zip", "token"])
def test_queue_message_from_dict_rejects_non_reference_fields(forbidden: str) -> None:
    payload = _message().as_dict()
    payload[forbidden] = "must-not-enter-envelope"

    with pytest.raises(ValueError, match="unsupported queue envelope fields"):
        QueueMessage.from_dict(payload)


def test_retry_policy_is_bounded_and_backoff_is_representable() -> None:
    policy = RetryPolicy(max_attempts=3, backoff_seconds=(5, 30))

    assert policy.delay_after_failure(0) == 5
    assert policy.delay_after_failure(1) == 30
    assert policy.delay_after_failure(2) is None


def test_queue_audit_event_is_correlatable_and_redacted() -> None:
    message = _message()

    event = QueueAuditEvent.from_delivery(
        message,
        DeliveryAction.RETRY,
        reason_code="transport_unavailable",
        occurred_at=NOW,
    )

    assert event.as_dict() == {
        "job_id": "job-001",
        "tenant_id": "synthetic-tenant",
        "queue": QueueName.CFDI_PARSE_XML.value,
        "message_id": "message-001",
        "correlation_id": "correlation-001",
        "idempotency_key": "idem-001",
        "attempt": 0,
        "action": DeliveryAction.RETRY.value,
        "reason_code": "transport_unavailable",
        "occurred_at": NOW.isoformat(),
    }
    assert all(key not in event.as_dict() for key in ("payload", "rfc", "uuid", "criteria"))


def test_worker_job_envelope_is_typed_reference_only_and_auditable() -> None:
    envelope = WorkerJobEnvelope.from_message(_message())

    assert envelope.job_type is WorkerJobType.CFDI_PARSE_XML
    assert envelope.queue is QueueName.CFDI_PARSE_XML
    assert envelope.idempotency_key == "idem-001"
    assert envelope.as_dict() == {
        "job_type": QueueName.CFDI_PARSE_XML.value,
        "queue": QueueName.CFDI_PARSE_XML.value,
        "tenant_id": "synthetic-tenant",
        "job_id": "job-001",
        "profile_id": "profile-ref-001",
        "message_id": "message-001",
        "correlation_id": "correlation-001",
        "idempotency_key": "idem-001",
        "attempt": 0,
        "envelope_version": 1,
        "created_at": NOW.isoformat(),
        "not_before": None,
    }

    audit = envelope.audit_event(DeliveryAction.RETRY, reason_code="transport_unavailable", occurred_at=NOW)

    assert audit.as_dict()["reason_code"] == "transport_unavailable"
    assert all(key not in envelope.as_dict() for key in ("payload", "rfc", "uuid", "criteria", "xml", "zip", "soap", "secret"))


@pytest.mark.parametrize("forbidden", ["rfc", "uuid", "criteria", "payload", "xml", "zip", "soap", "token", "secret"])
def test_worker_job_envelope_from_dict_rejects_non_reference_fields(forbidden: str) -> None:
    payload = WorkerJobEnvelope.from_message(_message()).as_dict()
    payload[forbidden] = "must-not-enter-worker-envelope"

    with pytest.raises(ValueError, match="unsupported worker envelope fields"):
        WorkerJobEnvelope.from_dict(payload)


def test_worker_job_envelope_rejects_queue_type_mismatch() -> None:
    payload = WorkerJobEnvelope.from_message(_message()).as_dict()
    payload["job_type"] = WorkerJobType.SAT_REQUEST.value

    with pytest.raises(ValueError, match="job_type must match queue"):
        WorkerJobEnvelope.from_dict(payload)
