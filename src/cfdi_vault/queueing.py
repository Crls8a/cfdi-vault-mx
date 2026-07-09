"""Queue adapters for CFDI recovery jobs.

RabbitMQ is the production adapter. The in-memory adapter exists for tests,
doctor checks, and the fake SAT path so contributors can run the first workflow
without external services.
"""

from __future__ import annotations

from collections.abc import Callable
from collections import defaultdict, deque
from datetime import datetime, timezone
import json
from typing import Deque

from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_contract import (
    DeadLetterRecord,
    DeliveryAction,
    DeliveryOutcome,
    RetryPolicy,
    RetryableQueueError,
    TerminalQueueError,
)



class InMemoryQueue:
    """Dependency-light queue adapter for tests and local fake workflows."""

    def __init__(
        self,
        *,
        retry_policy: RetryPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._messages: dict[str, Deque[QueueMessage]] = defaultdict(deque)
        self._dead_letters: Deque[DeadLetterRecord] = deque()
        self.retry_policy = retry_policy or RetryPolicy()
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def publish(self, message: QueueMessage) -> None:
        self._messages[message.queue.value].append(message)

    def peek(self, queue_name: str) -> QueueMessage | None:
        """Inspect the head without acknowledging or removing it."""

        queue = self._messages.get(queue_name)
        if not queue:
            return None
        return queue[0]

    def consume_one_reliably(
        self,
        queue_name: str,
        handler: Callable[[QueueMessage], object],
    ) -> DeliveryOutcome | None:
        """Consume with bounded retry and redacted dead-letter transitions."""

        queue = self._messages.get(queue_name)
        if not queue:
            return None
        message = queue[0]
        now = self.clock()
        if message.not_before is not None and message.not_before > now:
            return None
        try:
            result = handler(message)
        except RetryableQueueError as exc:
            delay = self.retry_policy.delay_after_failure(message.attempt)
            queue.popleft()
            if delay is not None:
                self.publish(message.retry_after(delay, now=now))
                return DeliveryOutcome(DeliveryAction.RETRY, message, reason_code=exc.reason_code, delay_seconds=delay)
            return self._dead_letter(message, exc.reason_code)
        except TerminalQueueError as exc:
            queue.popleft()
            return self._dead_letter(message, exc.reason_code)
        except Exception:
            queue.popleft()
            return self._dead_letter(message, "unclassified_failure")
        queue.popleft()
        return DeliveryOutcome(DeliveryAction.ACK, message, result=result)

    def consume_one_with_handler(
        self,
        queue_name: str,
        handler: Callable[[QueueMessage], object],
    ) -> object | None:
        """Compatibility bridge that still uses reliable handler ordering."""

        outcome = self.consume_one_reliably(queue_name, handler)
        if outcome is None or outcome.action is not DeliveryAction.ACK:
            return None
        return outcome.result

    def dead_letters(self) -> tuple[DeadLetterRecord, ...]:
        """Return redacted dead-letter records for tests/operator adapters."""

        return tuple(self._dead_letters)

    def _dead_letter(self, message: QueueMessage, reason_code: str) -> DeliveryOutcome:
        record = DeadLetterRecord(
            original_queue=message.queue.value,
            job_id=message.job_id,
            tenant_id=message.tenant_id,
            message_id=message.message_id,
            correlation_id=message.correlation_id,
            idempotency_key=message.idempotency_key,
            attempt=message.attempt,
            reason_code=reason_code,
        )
        self._dead_letters.append(record)
        return DeliveryOutcome(DeliveryAction.DEAD_LETTER, message, reason_code=reason_code)

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
            if self.exchange:
                channel.exchange_declare(exchange=self.exchange, exchange_type="direct", durable=True)
                channel.queue_bind(
                    exchange=self.exchange,
                    queue=message.queue.value,
                    routing_key=message.queue.value,
                )
            body = json.dumps(message.as_dict(), sort_keys=True).encode("utf-8")
            channel.confirm_delivery()
            try:
                confirmed = channel.basic_publish(
                    exchange=self.exchange,
                    routing_key=message.queue.value,
                    body=body,
                    properties=self._message_properties(pika, message),
                    mandatory=True,
                )
                if confirmed is False:
                    raise RuntimeError("queue initial publish was not confirmed")
            except RuntimeError:
                raise
            except Exception:
                raise RuntimeError("queue initial publish failed") from None
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


    @staticmethod
    def _message_properties(
        pika: object,
        message: QueueMessage,
        *,
        expiration: str | None = None,
    ) -> object:
        return pika.BasicProperties(
            content_type="application/json",
            delivery_mode=2,
            correlation_id=message.correlation_id,
            message_id=message.message_id,
            expiration=expiration,
            headers={
                "envelope_version": message.envelope_version,
                "idempotency_key": message.idempotency_key,
                "attempt": message.attempt,
            },
        )


def _declare_queue(channel: object, queue_name: str) -> object:
    return channel.queue_declare(queue=queue_name, durable=True)


def _load_pika():
    try:
        import pika  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("RabbitMQ support requires the infra extra: pip install -e .[infra]") from exc
    return pika
