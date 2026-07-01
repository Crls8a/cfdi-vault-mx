"""Queue adapters for CFDI recovery jobs.

RabbitMQ is the production adapter. The in-memory adapter exists for tests,
doctor checks, and the fake SAT path so contributors can run the first workflow
without external services.
"""

from __future__ import annotations

from collections.abc import Callable
from collections import defaultdict, deque
import json
from typing import Deque

from cfdi_vault.domain import QueueMessage, QueueName


class InMemoryQueue:
    """Dependency-light queue adapter for tests and local fake workflows."""

    def __init__(self) -> None:
        self._messages: dict[str, Deque[QueueMessage]] = defaultdict(deque)

    def publish(self, message: QueueMessage) -> None:
        self._messages[message.queue.value].append(message)

    def consume_one(self, queue_name: str) -> QueueMessage | None:
        queue = self._messages.get(queue_name)
        if not queue:
            return None
        return queue.popleft()

    def consume_one_with_handler(self, queue_name: str, handler: Callable[[QueueMessage], object]) -> object | None:
        message = self.consume_one(queue_name)
        if message is None:
            return None
        return handler(message)

    def pending_count(self, queue_name: str | None = None) -> int:
        if queue_name:
            return len(self._messages.get(queue_name, ()))
        return sum(len(messages) for messages in self._messages.values())

    def snapshot(self) -> dict[str, int]:
        return {queue.value: self.pending_count(queue.value) for queue in QueueName}


class RabbitMqQueue:
    """RabbitMQ adapter using durable queues and persistent messages."""

    def __init__(self, url: str, *, exchange: str = "") -> None:
        self.url = url
        self.exchange = exchange

    def publish(self, message: QueueMessage) -> None:
        pika = _load_pika()
        parameters = pika.URLParameters(self.url)
        connection = pika.BlockingConnection(parameters)
        try:
            channel = connection.channel()
            _declare_queue(channel, message.queue.value)
            body = json.dumps(message.as_dict(), sort_keys=True).encode("utf-8")
            channel.basic_publish(
                exchange=self.exchange,
                routing_key=message.queue.value,
                body=body,
                properties=pika.BasicProperties(
                    content_type="application/json",
                    delivery_mode=2,
                    correlation_id=message.correlation_id,
                    message_id=message.job_id,
                ),
            )
        finally:
            connection.close()

    def pending_count(self, queue_name: str | None = None) -> int:
        pika = _load_pika()
        parameters = pika.URLParameters(self.url)
        connection = pika.BlockingConnection(parameters)
        try:
            channel = connection.channel()
            if queue_name:
                result = _declare_queue(channel, queue_name)
                return int(result.method.message_count)
            total = 0
            for queue in QueueName:
                result = _declare_queue(channel, queue.value)
                total += int(result.method.message_count)
            return total
        finally:
            connection.close()

    def consume_one(self, queue_name: str) -> QueueMessage | None:
        pika = _load_pika()
        parameters = pika.URLParameters(self.url)
        connection = pika.BlockingConnection(parameters)
        try:
            channel = connection.channel()
            _declare_queue(channel, queue_name)
            method_frame, _properties, body = channel.basic_get(queue=queue_name, auto_ack=False)
            if method_frame is None:
                return None
            try:
                payload = json.loads(body.decode("utf-8"))
                message = QueueMessage.from_dict(payload)
            except Exception:
                channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=False)
                raise
            channel.basic_ack(delivery_tag=method_frame.delivery_tag)
            return message
        finally:
            connection.close()

    def consume_one_with_handler(self, queue_name: str, handler: Callable[[QueueMessage], object]) -> object | None:
        pika = _load_pika()
        parameters = pika.URLParameters(self.url)
        connection = pika.BlockingConnection(parameters)
        try:
            channel = connection.channel()
            _declare_queue(channel, queue_name)
            method_frame, _properties, body = channel.basic_get(queue=queue_name, auto_ack=False)
            if method_frame is None:
                return None
            try:
                payload = json.loads(body.decode("utf-8"))
                message = QueueMessage.from_dict(payload)
                result = handler(message)
            except Exception:
                channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=True)
                raise
            channel.basic_ack(delivery_tag=method_frame.delivery_tag)
            return result
        finally:
            connection.close()


def _declare_queue(channel: object, queue_name: str) -> object:
    return channel.queue_declare(queue=queue_name, durable=True)


def _load_pika():
    try:
        import pika  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("RabbitMQ support requires the infra extra: pip install -e .[infra]") from exc
    return pika
