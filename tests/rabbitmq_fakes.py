from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queueing import RabbitMqQueue


def message(*, attempt: int = 0, message_id: str = "message-001") -> QueueMessage:
    return QueueMessage(
        queue=QueueName.CFDI_PARSE_XML,
        tenant_id="synthetic-tenant",
        profile_id="profile-ref-001",
        job_id="job-001",
        correlation_id="correlation-001",
        attempt=attempt,
        message_id=message_id,
        idempotency_key="idem-001",
    )


class Properties:
    def __init__(self, **values: object) -> None:
        self.__dict__.update(values)


class Channel:
    def __init__(self, envelope: QueueMessage, *, fail_publish: bool = False, confirm_result: bool = True) -> None:
        self.body = json.dumps(envelope.as_dict()).encode()
        self.fail_publish = fail_publish
        self.confirm_result = confirm_result
        self.events: list[tuple[object, ...]] = []

    def confirm_delivery(self) -> None:
        self.events.append(("confirm_delivery",))

    def exchange_declare(self, **kwargs: object) -> None:
        self.events.append(("exchange_declare", kwargs))

    def queue_bind(self, **kwargs: object) -> None:
        self.events.append(("queue_bind", kwargs))

    def queue_declare(self, **kwargs: object) -> object:
        self.events.append(("queue_declare", kwargs))
        return SimpleNamespace(method=SimpleNamespace(message_count=1))

    def basic_get(self, **kwargs: object) -> tuple[object, None, bytes]:
        self.events.append(("get", kwargs))
        return SimpleNamespace(delivery_tag=7), None, self.body

    def basic_publish(self, **kwargs: object) -> bool:
        self.events.append(("publish", kwargs))
        if self.fail_publish:
            raise OSError("synthetic broker transition failure")
        return self.confirm_result

    def basic_ack(self, **kwargs: object) -> None:
        self.events.append(("ack", kwargs))

    def basic_nack(self, **kwargs: object) -> None:
        self.events.append(("nack", kwargs))


class Connection:
    def __init__(self, channel: Channel) -> None:
        self._channel = channel

    def channel(self) -> Channel:
        return self._channel

    def close(self) -> None:
        pass


class Pika:
    BasicProperties = Properties

    def __init__(self, channel: Channel) -> None:
        self.channel = channel

    def URLParameters(self, url: str) -> str:
        return url

    def BlockingConnection(self, parameters: object) -> Connection:
        return Connection(self.channel)


def rabbit(
    monkeypatch: pytest.MonkeyPatch,
    envelope: QueueMessage,
    *,
    fail_publish: bool = False,
    confirm_result: bool = True,
) -> tuple[RabbitMqQueue, Channel]:
    channel = Channel(envelope, fail_publish=fail_publish, confirm_result=confirm_result)
    monkeypatch.setattr("cfdi_vault.queueing._load_pika", lambda: Pika(channel))
    return RabbitMqQueue("amqp://synthetic"), channel
