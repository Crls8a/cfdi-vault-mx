from __future__ import annotations

import pytest

from cfdi_vault.domain import QueueName
from tests.rabbitmq_fakes import message, rabbit


def test_rabbit_initial_publish_is_mandatory_and_confirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, channel = rabbit(monkeypatch, message())

    adapter.publish(message())

    publish = next(event[1] for event in channel.events if event[0] == "publish")
    assert publish["exchange"] == "" and publish["routing_key"] == QueueName.CFDI_PARSE_XML.value
    assert publish["mandatory"] is True
    assert [event[0] for event in channel.events][-2:] == ["confirm_delivery", "publish"]


def test_rabbit_initial_publish_rejects_negative_confirm(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, _channel = rabbit(monkeypatch, message(), confirm_result=False)

    with pytest.raises(RuntimeError, match="initial publish was not confirmed"):
        adapter.publish(message())


def test_rabbit_initial_publish_redacts_broker_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, _channel = rabbit(monkeypatch, message(), fail_publish=True)

    with pytest.raises(RuntimeError, match="queue initial publish failed"):
        adapter.publish(message())


def test_rabbit_custom_exchange_is_declared_and_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter, channel = rabbit(monkeypatch, message())
    adapter.exchange = "cfdi.jobs"

    adapter.publish(message())

    assert ("exchange_declare", {"exchange": "cfdi.jobs", "exchange_type": "direct", "durable": True}) in channel.events
    assert (
        "queue_bind",
        {
            "exchange": "cfdi.jobs",
            "queue": QueueName.CFDI_PARSE_XML.value,
            "routing_key": QueueName.CFDI_PARSE_XML.value,
        },
    ) in channel.events
