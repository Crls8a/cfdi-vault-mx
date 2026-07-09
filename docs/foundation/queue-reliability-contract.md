# Queue reliability contract

Status: QUEUE-003 foundation contract.

## Delivery model

Workers use **at-least-once** delivery and require the adapter's reliable
handler API. There is no message-returning or early-ack consumption fallback.
A successful handler is acknowledged only after processing completes. Retry
and dead-letter transitions are published with RabbitMQ publisher confirms and
`mandatory=true` before the source delivery is acknowledged.

This ordering prevents acknowledged transition loss, but it is not atomic. A
process failure after publishing a transition and before acknowledging the
source may create a duplicate. The worker's default duplicate suppression is a
bounded TTL/LRU process-local cache. It is neither durable nor exactly-once.

## Reference-only envelope v1

The JSON allowlist is limited to:

- `envelope_version`, currently integer `1`;
- `queue`, `tenant_id`, `job_id`, and optional opaque `profile_id`;
- unique `message_id`;
- stable `correlation_id` and `idempotency_key`;
- zero-based integer `attempt`;
- `created_at` and optional `not_before` timestamps.

Unknown fields are rejected. The decoder does not coerce booleans, floats, or
strings into integer version/attempt fields. RFCs, CFDI UUIDs, search criteria,
XML, ZIP, SOAP bodies, tokens, credentials, secrets, and arbitrary payload
objects cannot be represented by this envelope.

`RecoveryService` stores request criteria in the existing durable
`DownloadJob` record before publishing. The consumer hydrates that record by
the opaque `job_id` and verifies `tenant_id`; criteria never travel through
RabbitMQ. This is the current job-reference handoff, not a new storage schema.

## Audit event shape

`QueueAuditEvent` specifies the persistence boundary for a transition:

- job, tenant, queue, message, correlation, and idempotency identifiers;
- delivery attempt and action;
- optional safe machine `reason_code`;
- occurrence timestamp.

It has no payload, RFC, UUID, criteria, or exception text. QUEUE-003 defines and
tests this shape. It does **not** claim that every existing `QueueJobEvent` row
already uses it. Durable per-delivery persistence and claim coordination remain
QUEUE-004 and the later database/Redis work.

## Retry policy

`max_attempts` means total deliveries, including the first delivery. The
default policy is:

| Delivery attempt | Failure transition |
|---:|---|
| `0` | retry after 5 seconds as attempt `1` |
| `1` | retry after 30 seconds as attempt `2` |
| `2` | exhausted; publish a redacted dead-letter record |

Retry counts, delivery attempts, and backoff delays are integer-only runtime
values. Booleans, floats, strings, and negative attempts are rejected rather
than coerced.

A retry receives a new `message_id` while preserving correlation and
idempotency identifiers. Only `RetryableQueueError` is retried.
`TerminalQueueError` and unclassified failures go to dead letter with a safe
reason code.

The in-memory adapter uses an injected clock and honors `not_before`. It keeps
the delivery at the queue head during handler execution and preserves FIFO
order while a scheduled head is not yet due.

## Backward-compatible RabbitMQ topology

QUEUE-003 never adds arguments to an existing durable source queue. This avoids
RabbitMQ `PRECONDITION_FAILED` errors from inequivalent redeclarations.

For source `<name>` and each configured delay, the adapter declares:

- `<name>.retry.v1.<seconds>s`, with queue-level `x-message-ttl` and dead-letter
  routing back to `<name>` through the default exchange;
- `dead.letter.v1`, containing only redacted dead-letter records.

Using one retry queue per delay prevents a long-delay message from blocking a
short-delay message behind it. Retry messages do not carry per-message expiry.

Direct queue transitions use the default exchange. Initial source publishes
also prefer the default exchange. If a custom direct exchange is configured,
the adapter explicitly declares it and binds the source queue before publish.
Initial and transition publishes use confirms plus mandatory routing. A false
confirm, unroutable publish, or exception is a failure; transition failure
causes `nack(requeue=true)` without acknowledging the source.

Invalid envelopes are never copied or logged. A redacted `invalid_envelope`
record must be confirmed before acknowledging the invalid source delivery.
An otherwise valid envelope whose declared queue differs from the consumed
source is dead-lettered as `queue_origin_mismatch`; the configured source queue,
not the spoofed envelope value, is recorded as the origin.

## Verification and remaining gates

- Fake adapter tests cover ordering, bounded retry, redaction, confirms, and
  transition failure without external services.
- A broker integration test covers source redeclaration, queue-level TTL/DLX,
  publisher confirms, and dead-letter redaction. It skips locally unless
  `CFDI_VAULT_TEST_RABBITMQ_URL` points to a dedicated test broker; CI provides
  that broker and installs the infrastructure dependencies.
- No MinIO, API/E2E, Redis implementation, or live SAT dependency is added.
- Durable idempotency, persisted delivery audit, progress, locks, and heartbeat
  remain later gated work.
