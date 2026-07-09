"""Worker entry points for queue-backed recovery jobs."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
import time

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
    ) -> None:
        self.service = service
        self.idempotency = idempotency or InMemoryIdempotencyStore()
        self.classify_failure = classify_failure or (lambda error: TerminalQueueError("unclassified_failure"))

    def run_once(self, *, queue_name: str = QueueName.SAT_REQUEST.value) -> WorkerReport:
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
        try:
            result = self.service.process_queue_message(message)
        except QueueHandlerError:
            self.idempotency.release(message.idempotency_key)
            raise
        except Exception as exc:
            self.idempotency.release(message.idempotency_key)
            raise self.classify_failure(exc) from None
        self.idempotency.complete(message.idempotency_key)
        return WorkerReport(processed=1, detail=f"Processed job {result.job_id} with status {result.status}.")

    def run_forever(self, *, poll_seconds: float = 5.0) -> None:
        while True:
            report = self.run_once()
            print(f"processed={report.processed} detail={report.detail}", flush=True)
            time.sleep(poll_seconds)
