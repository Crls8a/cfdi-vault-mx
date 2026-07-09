from __future__ import annotations

import json
import os
import time

import pytest

from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_contract import DeliveryAction, RetryPolicy, RetryableQueueError, TerminalQueueError
from cfdi_vault.queueing import RabbitMqQueue


RABBITMQ_URL = os.getenv("CFDI_VAULT_TEST_RABBITMQ_URL")
pytestmark = pytest.mark.skipif(not RABBITMQ_URL, reason="dedicated RabbitMQ test broker is not configured")


def _message(message_id: str) -> QueueMessage:
    return QueueMessage(
        queue=QueueName.CFDI_EXPORT,
        tenant_id="synthetic-tenant",
        profile_id="profile-ref-001",
        job_id=f"job-{message_id}",
        correlation_id=f"correlation-{message_id}",
        message_id=message_id,
        idempotency_key=f"idem-{message_id}",
    )


def test_real_rabbit_retry_ttl_dlx_redeclare_and_confirms() -> None:
    assert RABBITMQ_URL is not None
    import pika

    source = QueueName.CFDI_EXPORT.value
    retry = f"{source}.retry.v1.1s"
    dead = "dead.letter.v1"
    parameters = pika.URLParameters(RABBITMQ_URL)
    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()
    for queue_name in (source, retry, dead):
        channel.queue_delete(queue=queue_name)
    channel.queue_declare(queue=source, durable=True)
    channel.queue_declare(queue=source, durable=True)  # source remains compatible
    connection.close()

    queue = RabbitMqQueue(
        RABBITMQ_URL,
        retry_policy=RetryPolicy(max_attempts=2, backoff_seconds=(1,)),
    )
    try:
        queue.publish(_message("retry"))
        retry_outcome = queue.consume_one_reliably(
            source,
            lambda message: (_ for _ in ()).throw(RetryableQueueError("transient")),
        )
        assert retry_outcome is not None and retry_outcome.action is DeliveryAction.RETRY

        deadline = time.monotonic() + 5
        completed = None
        while completed is None and time.monotonic() < deadline:
            completed = queue.consume_one_reliably(source, lambda message: message.message_id)
            if completed is None:
                time.sleep(0.1)
        assert completed is not None and completed.action is DeliveryAction.ACK

        queue.publish(_message("terminal"))
        terminal = queue.consume_one_reliably(
            source,
            lambda message: (_ for _ in ()).throw(TerminalQueueError("invalid_reference")),
        )
        assert terminal is not None and terminal.action is DeliveryAction.DEAD_LETTER

        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
        channel.queue_declare(queue=source, durable=True)  # no inequivalent args
        method, _properties, body = channel.basic_get(queue=dead, auto_ack=True)
        assert method is not None
        record = json.loads(body.decode("utf-8"))
        assert record["reason_code"] == "invalid_reference"
        assert all(key not in record for key in ("payload", "rfc", "uuid", "criteria"))
        connection.close()
    finally:
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
        for queue_name in (source, retry, dead):
            channel.queue_delete(queue=queue_name)
        connection.close()
