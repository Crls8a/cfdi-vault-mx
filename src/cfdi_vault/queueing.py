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


_DEAD_LETTER_QUEUE = "dead.letter.v1"


def _retry_queue_name(queue_name: str, delay_seconds: int) -> str:
    return f"{queue_name}.retry.v1.{delay_seconds}s"


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

    def __init__(
        self,
        url: str,
        *,
        exchange: str = "",
        retry_policy: RetryPolicy | None = None,
    ) -> None:
        self.url = url
        self.exchange = exchange
        self.retry_policy = retry_policy or RetryPolicy()

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
        """Reject unsafe consumption that cannot defer ack until processing."""

        raise RuntimeError("RabbitMQ consumption requires a handler")

    def consume_one_reliably(
        self,
        queue_name: str,
        handler: Callable[[QueueMessage], object],
    ) -> DeliveryOutcome | None:
        """Apply one bounded at-least-once delivery transition."""

        pika = _load_pika()
        parameters = pika.URLParameters(self.url)
        connection = pika.BlockingConnection(parameters)
        try:
            channel = connection.channel()
            self._declare_transition_topology(channel, queue_name)
            channel.confirm_delivery()
            method_frame, _properties, body = channel.basic_get(queue=queue_name, auto_ack=False)
            if method_frame is None:
                return None
            try:
                payload = json.loads(body.decode("utf-8"))
                message = QueueMessage.from_dict(payload)
            except Exception:
                return self._dead_letter_invalid(
                    pika,
                    channel,
                    method_frame.delivery_tag,
                    queue_name,
                )
            if message.queue.value != queue_name:
                return self._dead_letter_delivery(
                    pika,
                    channel,
                    method_frame.delivery_tag,
                    message,
                    "queue_origin_mismatch",
                    original_queue=queue_name,
                )

            try:
                result = handler(message)
            except RetryableQueueError as exc:
                delay = self.retry_policy.delay_after_failure(message.attempt)
                if delay is None:
                    return self._dead_letter_delivery(
                        pika, channel, method_frame.delivery_tag, message, exc.reason_code
                    )
                retry = message.retry_after(delay)
                try:
                    confirmed = channel.basic_publish(
                        exchange="",
                        routing_key=_retry_queue_name(queue_name, delay),
                        body=json.dumps(retry.as_dict(), sort_keys=True).encode("utf-8"),
                        properties=self._message_properties(pika, retry),
                        mandatory=True,
                    )
                    if confirmed is False:
                        raise RuntimeError("retry publish was not confirmed")
                except Exception:
                    channel.basic_nack(delivery_tag=method_frame.delivery_tag, requeue=True)
                    raise RuntimeError("queue retry transition failed") from None
                channel.basic_ack(delivery_tag=method_frame.delivery_tag)
                return DeliveryOutcome(
                    DeliveryAction.RETRY,
                    message,
                    reason_code=exc.reason_code,
                    delay_seconds=delay,
                )
            except TerminalQueueError as exc:
                return self._dead_letter_delivery(
                    pika, channel, method_frame.delivery_tag, message, exc.reason_code
                )
            except Exception:
                return self._dead_letter_delivery(
                    pika, channel, method_frame.delivery_tag, message, "unclassified_failure"
                )

            channel.basic_ack(delivery_tag=method_frame.delivery_tag)
            return DeliveryOutcome(DeliveryAction.ACK, message, result=result)
        finally:
            connection.close()

    def _declare_transition_topology(self, channel: object, queue_name: str) -> None:
        """Add versioned transition queues without changing the durable source queue."""

        _declare_queue(channel, queue_name)
        retry_delays = {
            delay
            for attempt in range(self.retry_policy.max_attempts)
            if (delay := self.retry_policy.delay_after_failure(attempt)) is not None
        }
        for delay in sorted(retry_delays):
            _declare_queue(
                channel,
                _retry_queue_name(queue_name, delay),
                arguments={
                    "x-message-ttl": delay * 1000,
                    "x-dead-letter-exchange": "",
                    "x-dead-letter-routing-key": queue_name,
                },
            )
        _declare_queue(channel, _DEAD_LETTER_QUEUE)

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

    def _dead_letter_delivery(
        self,
        pika: object,
        channel: object,
        delivery_tag: object,
        message: QueueMessage,
        reason_code: str,
        *,
        original_queue: str | None = None,
    ) -> DeliveryOutcome:
        record = DeadLetterRecord(
            original_queue=original_queue or message.queue.value,
            job_id=message.job_id,
            tenant_id=message.tenant_id,
            message_id=message.message_id,
            correlation_id=message.correlation_id,
            idempotency_key=message.idempotency_key,
            attempt=message.attempt,
            reason_code=reason_code,
        )
        self._publish_dead_letter_record(pika, channel, delivery_tag, record, message)
        return DeliveryOutcome(
            DeliveryAction.DEAD_LETTER,
            message,
            reason_code=reason_code,
        )

    def _dead_letter_invalid(
        self,
        pika: object,
        channel: object,
        delivery_tag: object,
        queue_name: str,
    ) -> DeliveryOutcome:
        record = DeadLetterRecord(
            original_queue=queue_name,
            job_id="unavailable",
            tenant_id="unavailable",
            message_id="unavailable",
            correlation_id="unavailable",
            idempotency_key="unavailable",
            attempt=0,
            reason_code="invalid_envelope",
        )
        self._publish_dead_letter_record(pika, channel, delivery_tag, record)
        return DeliveryOutcome(
            DeliveryAction.DEAD_LETTER,
            None,
            reason_code="invalid_envelope",
        )

    @staticmethod
    def _publish_dead_letter_record(
        pika: object,
        channel: object,
        delivery_tag: object,
        record: DeadLetterRecord,
        message: QueueMessage | None = None,
    ) -> None:
        property_values: dict[str, object] = {
            "content_type": "application/json",
            "delivery_mode": 2,
        }
        if message is not None:
            property_values.update(
                correlation_id=message.correlation_id,
                message_id=message.message_id,
            )
        try:
            confirmed = channel.basic_publish(
                exchange="",
                routing_key=_DEAD_LETTER_QUEUE,
                body=json.dumps(record.as_dict(), sort_keys=True).encode("utf-8"),
                properties=pika.BasicProperties(**property_values),
                mandatory=True,
            )
            if confirmed is False:
                raise RuntimeError("dead-letter publish was not confirmed")
        except Exception:
            channel.basic_nack(delivery_tag=delivery_tag, requeue=True)
            raise RuntimeError("queue dead-letter transition failed") from None
        channel.basic_ack(delivery_tag=delivery_tag)


def _declare_queue(
    channel: object,
    queue_name: str,
    *,
    arguments: dict[str, object] | None = None,
) -> object:
    return channel.queue_declare(queue=queue_name, durable=True, arguments=arguments)


def _load_pika():
    try:
        import pika  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("RabbitMQ support requires the infra extra: pip install -e .[infra]") from exc
    return pika
