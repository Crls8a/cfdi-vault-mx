"""Worker entry points for queue-backed recovery jobs."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event, Thread
import time
from uuid import uuid4

from cfdi_vault.cache_contract import CacheKeys, WorkerHeartbeat
from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.queue_contract import DeliveryAction, IdempotencyPort, QueueHandlerError, TerminalQueueError
from cfdi_vault.recovery_service import RecoveryService


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

    def run_once(self, *, queue_name: str = QueueName.SAT_REQUEST.value) -> WorkerReport:
        self._record_heartbeat()
        consume_reliably = getattr(self.service.queue, "consume_one_reliably", None)
        if consume_reliably is not None:
            outcome = consume_reliably(queue_name, self._handle)
            if outcome is None:
                return WorkerReport(processed=0, detail=f"No {queue_name} message available.")
            if outcome.action is DeliveryAction.ACK:
                return outcome.result  # type: ignore[return-value]
            if outcome.action is DeliveryAction.RETRY:
                return WorkerReport(processed=0, detail="Retry scheduled after a classified transient failure.")
            return WorkerReport(processed=0, detail="Delivery moved to dead letter with a redacted reason.")
        raise RuntimeError("Queue adapter does not support reliable consumption.")

    def _handle(self, message: QueueMessage) -> WorkerReport:
        if not self.idempotency.acquire(message.idempotency_key):
            return WorkerReport(processed=0, detail="Duplicate delivery acknowledged; durable idempotency is not configured.")
        heartbeat_stop = Event()
        heartbeat_errors: list[Exception] = []
        heartbeat_thread = Thread(
            target=self._renew_heartbeat_until_stopped,
            args=(heartbeat_stop, heartbeat_errors),
            daemon=True,
        )
        heartbeat_thread.start()
        try:
            try:
                process_for_worker = getattr(self.service, "process_queue_message_for_worker", None)
                if process_for_worker is None:
                    result = self.service.process_queue_message(message)
                else:
                    result = process_for_worker(message, worker_ref=self.worker_id)
            finally:
                heartbeat_stop.set()
                heartbeat_thread.join()
            if heartbeat_errors:
                raise RuntimeError("worker heartbeat renewal failed") from heartbeat_errors[0]
        except QueueHandlerError:
            self.idempotency.release(message.idempotency_key)
            raise
        except Exception as exc:
            self.idempotency.release(message.idempotency_key)
            raise self.classify_failure(exc) from None
        self.idempotency.complete(message.idempotency_key)
        return WorkerReport(processed=1, detail=f"Processed job {result.job_id} with status {result.status}.")

    def _renew_heartbeat_until_stopped(self, stop: Event, errors: list[Exception]) -> None:
        while not stop.wait(self.heartbeat_interval_seconds):
            try:
                self._record_heartbeat()
            except Exception as exc:
                errors.append(exc)
                return

    def _record_heartbeat(self) -> None:
        if self.heartbeat_cache is None:
            return
        self.heartbeat_cache.record_heartbeat(
            WorkerHeartbeat(worker_id=self.worker_id, updated_at=self.clock()),
            self.heartbeat_ttl_seconds,
        )

    def run_forever(self, *, poll_seconds: float = 5.0) -> None:
        while True:
            report = self.run_once()
            print(f"processed={report.processed} detail={report.detail}", flush=True)
            time.sleep(poll_seconds)
