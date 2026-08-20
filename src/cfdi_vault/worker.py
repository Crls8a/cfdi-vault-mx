"""Worker entry points for queue-backed recovery jobs."""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event, Thread
from uuid import uuid4

from cfdi_vault.cache_contract import CacheKeys, WorkerEvent, WorkerEventType, WorkerHeartbeat
from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.ledger_job_consumer import LedgerConsumerReport, LedgerJobConsumer
from cfdi_vault.queue_contract import (
    DeliveryAction,
    IdempotencyPort,
    QueueHandlerError,
    TerminalQueueError,
    WorkerJobEnvelope,
)
from cfdi_vault.recovery_service import RecoveryService

# Queues that the generic ``--queue all`` fan-out must never consume.
#
# ``SAT_CAMPAIGN_RUN`` is a wake hint for a live, human-authorized SAT campaign
# run (ADR 0005). The docker-compose ``worker`` container runs this fan-out on a
# ``FakeSatClient``-backed ``RecoveryService`` and cannot reach the Windows
# Credential Manager that holds the FIEL phrase, so it must never claim or
# acknowledge a campaign-run hint: doing so would silently swallow the wake for
# the real consumer, and would route a live SAT command through the generic
# retry/dead-letter machinery that ADR 0004/0005 forbid for live SAT work. The
# only consumer is the host-only ``cfdi_vault.sat_campaign_run_service``.
FAN_OUT_EXCLUDED_QUEUES = frozenset({QueueName.SAT_CAMPAIGN_RUN})


@dataclass(frozen=True)
class WorkerReport:
    """Small report emitted by the worker command."""

    processed: int
    detail: str


class InMemoryIdempotencyStore:
    """Process-local test/default claims; this is not durable exactly-once."""

    def __init__(
        self,
        *,
        max_entries: int = 10_000,
        ttl_seconds: float = 3_600,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.max_entries = max_entries
        self.ttl_seconds = float(ttl_seconds)
        self.clock = clock or time.monotonic
        self._active: dict[str, float] = {}
        self._completed: OrderedDict[str, float] = OrderedDict()

    def acquire(self, key: str) -> bool:
        now = self.clock()
        self._prune(now)
        if key in self._active:
            return False
        if key in self._completed:
            self._completed.move_to_end(key)
            return False
        while len(self._active) + len(self._completed) >= self.max_entries:
            if not self._completed:
                raise RuntimeError("process-local idempotency capacity exhausted")
            self._completed.popitem(last=False)
        self._active[key] = now + self.ttl_seconds
        return True

    def complete(self, key: str) -> None:
        now = self.clock()
        self._prune(now)
        self._active.pop(key, None)
        self._completed.pop(key, None)
        while len(self._completed) >= self.max_entries:
            self._completed.popitem(last=False)
        self._completed[key] = now + self.ttl_seconds

    def release(self, key: str) -> None:
        self._active.pop(key, None)

    def _prune(self, now: float) -> None:
        self._active = {key: expiry for key, expiry in self._active.items() if expiry > now}
        for key, expiry in tuple(self._completed.items()):
            if expiry <= now:
                self._completed.pop(key, None)


class RecoveryWorker:
    """Worker shell for SAT request messages."""

    def __init__(
        self,
        service: RecoveryService,
        *,
        idempotency: IdempotencyPort | None = None,
        classify_failure: Callable[[Exception], QueueHandlerError] | None = None,
        worker_id: str | None = None,
        clock: Callable[[], datetime] | None = None,
        heartbeat_ttl_seconds: int = 30,
        heartbeat_interval_seconds: float | None = None,
        ledger_consumer: LedgerJobConsumer | None = None,
    ) -> None:
        if (
            isinstance(heartbeat_ttl_seconds, bool)
            or not isinstance(heartbeat_ttl_seconds, int)
            or heartbeat_ttl_seconds < 1
        ):
            raise ValueError("heartbeat_ttl_seconds must be a positive integer")
        self.service = service
        self.idempotency = idempotency or InMemoryIdempotencyStore()
        self.classify_failure = classify_failure or (lambda error: TerminalQueueError("unclassified_failure"))
        self.worker_id = worker_id or f"worker-{uuid4().hex}"
        CacheKeys.heartbeat(self.worker_id)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.heartbeat_ttl_seconds = heartbeat_ttl_seconds
        interval = heartbeat_interval_seconds
        if interval is None:
            interval = min(5.0, heartbeat_ttl_seconds / 3)
        if (
            isinstance(interval, bool)
            or not isinstance(interval, (int, float))
            or interval <= 0
            or interval >= heartbeat_ttl_seconds
        ):
            raise ValueError("heartbeat_interval_seconds must be positive and less than the heartbeat TTL")
        self.heartbeat_interval_seconds = float(interval)
        self.heartbeat_cache = getattr(service, "cache", None)
        self.ledger_consumer = ledger_consumer
        self._started_event_emitted = False

    def run_once(self, *, queue_name: str = QueueName.SAT_REQUEST.value) -> WorkerReport:
        self._emit_started_event()
        self._record_heartbeat()
        report = self._run_once(queue_name=queue_name)
        if report.processed == 0 and report.detail.startswith("No "):
            self._publish_worker_event(WorkerEventType.IDLE)
        return report

    def run_one_shot(self, *, queue_name: str = QueueName.SAT_REQUEST.value) -> WorkerReport:
        """Run one poll as a worker lifecycle and emit exactly one stop event."""

        self._emit_started_event()
        try:
            return self.run_once(queue_name=queue_name)
        finally:
            self._publish_worker_event(WorkerEventType.STOPPED)

    def _run_once(self, *, queue_name: str) -> WorkerReport:
        """Execute one poll after lifecycle/heartbeat bookkeeping."""

        if queue_name == "all":
            for candidate in QueueName:
                if candidate in FAN_OUT_EXCLUDED_QUEUES:
                    continue
                report = self._run_once(queue_name=candidate.value)
                if report.processed or not report.detail.startswith("No "):
                    return report
            return WorkerReport(processed=0, detail="No worker queue message available.")
        if self.ledger_consumer is not None and queue_name in {
            QueueName.CFDI_PARSE_METADATA.value,
            QueueName.CFDI_PARSE_XML.value,
        }:
            return self._run_ledger_once(queue_name)
        consume_reliably = getattr(self.service.queue, "consume_one_reliably", None)
        if consume_reliably is not None:
            outcome = consume_reliably(queue_name, self._handle)
            if outcome is None:
                return WorkerReport(processed=0, detail=f"No {queue_name} message available.")
            if outcome.action is DeliveryAction.ACK:
                return outcome.result  # type: ignore[return-value]
            if outcome.action is DeliveryAction.RETRY:
                reason = outcome.reason_code or "classified_transient_failure"
                return WorkerReport(processed=0, detail=f"Retry scheduled after classified reason: {reason}.")
            reason = outcome.reason_code or "unclassified_failure"
            return WorkerReport(processed=0, detail=f"Delivery moved to dead letter with redacted reason: {reason}.")
        raise RuntimeError("Queue adapter does not support reliable consumption.")

    def _run_ledger_once(self, queue_name: str) -> WorkerReport:
        """Consume a durable parse delivery; legacy queues remain unchanged."""

        assert self.ledger_consumer is not None
        consume_reliably = getattr(self.service.queue, "consume_one_reliably", None)
        if consume_reliably is None:
            raise RuntimeError("Queue adapter does not support reliable consumption.")
        heartbeat_stop = Event()
        heartbeat_thread = Thread(
            target=self._renew_heartbeat_until_stopped,
            args=(heartbeat_stop,),
            daemon=True,
        )
        heartbeat_thread.start()
        try:
            outcome = consume_reliably(queue_name, self.ledger_consumer.handle)
        finally:
            heartbeat_stop.set()
            heartbeat_thread.join()
        if outcome is None:
            return WorkerReport(processed=0, detail=f"No {queue_name} message available.")
        if outcome.action is DeliveryAction.ACK:
            result = outcome.result
            if isinstance(result, LedgerConsumerReport):
                return WorkerReport(
                    processed=1 if result.status == "succeeded" else 0,
                    detail=f"Ledger parse status={result.status}.",
                )
            return WorkerReport(processed=1, detail="Ledger parse delivery acknowledged.")
        if outcome.action is DeliveryAction.RETRY:
            return WorkerReport(
                processed=0,
                detail=f"Retry scheduled after classified reason: {outcome.reason_code or 'retry_scheduled'}.",
            )
        return WorkerReport(
            processed=0,
            detail=f"Delivery moved to dead letter with redacted reason: {outcome.reason_code or 'delivery_failed'}.",
        )

    def _handle(self, message: QueueMessage) -> WorkerReport:
        envelope = WorkerJobEnvelope.from_message(message)
        if not self.idempotency.acquire(envelope.idempotency_key):
            return WorkerReport(
                processed=0, detail="Duplicate delivery acknowledged; durable idempotency is not configured."
            )
        heartbeat_stop = Event()
        heartbeat_thread = Thread(
            target=self._renew_heartbeat_until_stopped,
            args=(heartbeat_stop,),
            daemon=True,
        )
        heartbeat_thread.start()
        try:
            try:
                process_envelope = getattr(self.service, "process_worker_job_envelope", None)
                if process_envelope is not None:
                    result = process_envelope(envelope, worker_ref=self.worker_id)
                else:
                    process_for_worker = getattr(self.service, "process_queue_message_for_worker", None)
                    if process_for_worker is None:
                        result = self.service.process_queue_message(message)
                    else:
                        result = process_for_worker(message, worker_ref=self.worker_id)
            finally:
                heartbeat_stop.set()
                heartbeat_thread.join()
        except QueueHandlerError:
            self.idempotency.release(envelope.idempotency_key)
            raise
        except Exception as exc:
            self.idempotency.release(envelope.idempotency_key)
            raise self.classify_failure(exc) from None
        self.idempotency.complete(envelope.idempotency_key)
        return WorkerReport(processed=1, detail=f"Processed job {result.job_id} with status {result.status}.")

    def _renew_heartbeat_until_stopped(self, stop: Event) -> None:
        while not stop.wait(self.heartbeat_interval_seconds):
            try:
                self._record_heartbeat()
            except Exception:
                # Cache visibility is best effort. A transient Redis failure
                # must not turn successful queue work into a retry or DLQ.
                continue

    def _record_heartbeat(self) -> None:
        if self.heartbeat_cache is None:
            return
        try:
            self.heartbeat_cache.record_heartbeat(
                WorkerHeartbeat(worker_id=self.worker_id, updated_at=self.clock()),
                self.heartbeat_ttl_seconds,
            )
        except Exception:
            # PostgreSQL and the queue remain authoritative for work state.
            return
        self._publish_worker_event(WorkerEventType.HEARTBEAT)

    def _emit_started_event(self) -> None:
        if self._started_event_emitted:
            return
        self._started_event_emitted = True
        self._publish_worker_event(WorkerEventType.STARTED)

    def _publish_worker_event(self, event_type: WorkerEventType) -> None:
        """Best-effort cache publication that can never fail the work poll."""

        if self.heartbeat_cache is None:
            return
        publish = getattr(self.heartbeat_cache, "publish_worker_event", None)
        if publish is None:
            return
        try:
            publish(
                WorkerEvent(
                    worker_id=self.worker_id,
                    event_type=event_type,
                    occurred_at=self.clock(),
                ),
                self.heartbeat_ttl_seconds,
            )
        except Exception:
            # Redis/cache visibility is transient; queue work and durable state
            # must continue even when the operational event cannot be written.
            return

    def run_forever(
        self,
        *,
        poll_seconds: float = 5.0,
        queue_name: str = QueueName.SAT_REQUEST.value,
        stop: Callable[[], bool] | None = None,
    ) -> None:
        """Poll until ``stop`` is true, publishing transient lifecycle events."""

        self._emit_started_event()
        try:
            while stop is None or not stop():
                report = self.run_once(queue_name=queue_name)
                print(f"processed={report.processed} detail={report.detail}", flush=True)
                time.sleep(poll_seconds)
        finally:
            self._publish_worker_event(WorkerEventType.STOPPED)
