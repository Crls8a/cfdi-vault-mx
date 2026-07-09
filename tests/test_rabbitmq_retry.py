from __future__ import annotations

import json

import pytest

from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_contract import DeliveryAction, RetryableQueueError, TerminalQueueError
from tests.rabbitmq_fakes import message, rabbit


def test_rabbit_transition_topology_does_not_mutate_existing_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, channel = rabbit(monkeypatch, message())
    adapter.consume_one_reliably(QueueName.CFDI_PARSE_XML.value, lambda envelope: "ok")

    declarations = [event[1] for event in channel.events if event[0] == "queue_declare"]
    original = next(item for item in declarations if item["queue"] == QueueName.CFDI_PARSE_XML.value)
    retries = [item for item in declarations if ".retry.v1." in item["queue"]]
    assert original.get("arguments") is None
    assert {item["arguments"]["x-message-ttl"] for item in retries} == {5000, 30000}
    assert all(item["arguments"]["x-dead-letter-exchange"] == "" for item in retries)
    assert all(item["arguments"]["x-dead-letter-routing-key"] == QueueName.CFDI_PARSE_XML.value for item in retries)


def test_rabbit_ack_happens_after_successful_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, channel = rabbit(monkeypatch, message())
    outcome = adapter.consume_one_reliably(
        QueueName.CFDI_PARSE_XML.value,
        lambda envelope: channel.events.append(("handled",)) or "ok",
    )
    assert outcome is not None and outcome.action is DeliveryAction.ACK
    assert [event[0] for event in channel.events][-2:] == ["handled", "ack"]


def test_rabbit_retry_is_confirmed_before_original_ack(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, channel = rabbit(monkeypatch, message())
    outcome = adapter.consume_one_reliably(
        QueueName.CFDI_PARSE_XML.value,
        lambda envelope: (_ for _ in ()).throw(RetryableQueueError("transport_unavailable")),
    )
    publish = next(event[1] for event in channel.events if event[0] == "publish")
    retried = QueueMessage.from_dict(json.loads(publish["body"].decode()))
    assert outcome is not None and outcome.action is DeliveryAction.RETRY
    assert publish["exchange"] == "" and publish["routing_key"].endswith(".retry.v1.5s")
    assert publish["mandatory"] is True and publish["properties"].expiration is None
    assert retried.attempt == 1 and retried.idempotency_key == "idem-001"
    assert [event[0] for event in channel.events][-2:] == ["publish", "ack"]


def test_rabbit_terminal_failure_publishes_redacted_versioned_dlq(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, channel = rabbit(monkeypatch, message())
    outcome = adapter.consume_one_reliably(
        QueueName.CFDI_PARSE_XML.value,
        lambda envelope: (_ for _ in ()).throw(TerminalQueueError("invalid_reference")),
    )
    publish = next(event[1] for event in channel.events if event[0] == "publish")
    dead_letter = json.loads(publish["body"].decode())
    assert outcome is not None and outcome.action is DeliveryAction.DEAD_LETTER
    assert publish["exchange"] == "" and publish["routing_key"] == "dead.letter.v1"
    assert dead_letter["reason_code"] == "invalid_reference"
    assert all(key not in dead_letter for key in ("payload", "rfc", "uuid", "criteria"))
    assert [event[0] for event in channel.events][-2:] == ["publish", "ack"]


def test_rabbit_invalid_envelope_is_redacted_before_dead_letter(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, channel = rabbit(monkeypatch, message())
    channel.body = b'{"token":"must-not-leak"}'
    outcome = adapter.consume_one_reliably(QueueName.CFDI_PARSE_XML.value, lambda envelope: "unused")

    publish = next(event[1] for event in channel.events if event[0] == "publish")
    dead_letter = json.loads(publish["body"].decode())
    assert outcome is not None and outcome.action is DeliveryAction.DEAD_LETTER
    assert outcome.message is None and dead_letter["reason_code"] == "invalid_envelope"
    assert "must-not-leak" not in str(dead_letter)
    assert [event[0] for event in channel.events][-2:] == ["publish", "ack"]


def test_rabbit_rejects_envelope_spoofing_another_source_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, channel = rabbit(monkeypatch, message())
    channel.body = json.dumps(message().as_dict() | {"queue": QueueName.SAT_REQUEST.value}).encode()
    handled: list[str] = []

    outcome = adapter.consume_one_reliably(
        QueueName.CFDI_PARSE_XML.value,
        lambda envelope: handled.append(envelope.message_id),
    )

    publish = next(event[1] for event in channel.events if event[0] == "publish")
    dead_letter = json.loads(publish["body"].decode())
    assert outcome is not None and outcome.action is DeliveryAction.DEAD_LETTER
    assert dead_letter["original_queue"] == QueueName.CFDI_PARSE_XML.value
    assert dead_letter["reason_code"] == "queue_origin_mismatch"
    assert handled == []


def test_rabbit_transition_failure_nacks_with_explicit_requeue(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, channel = rabbit(monkeypatch, message(), fail_publish=True)
    with pytest.raises(RuntimeError, match="retry transition failed"):
        adapter.consume_one_reliably(
            QueueName.CFDI_PARSE_XML.value,
            lambda envelope: (_ for _ in ()).throw(RetryableQueueError("transport_unavailable")),
        )
    assert channel.events[-1] == ("nack", {"delivery_tag": 7, "requeue": True})
    assert not any(event[0] == "ack" for event in channel.events)


def test_rabbit_refuses_early_ack_consumption_without_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, channel = rabbit(monkeypatch, message())
    with pytest.raises(RuntimeError, match="requires a handler"):
        adapter.consume_one(QueueName.CFDI_PARSE_XML.value)
    assert not any(event[0] in {"ack", "nack"} for event in channel.events)
