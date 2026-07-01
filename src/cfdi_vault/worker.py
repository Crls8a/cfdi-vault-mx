"""Worker entry points for queue-backed recovery jobs."""

from __future__ import annotations

from dataclasses import dataclass
import time

from cfdi_vault.domain import QueueMessage, QueueName
from cfdi_vault.recovery_service import RecoveryService


@dataclass(frozen=True)
class WorkerReport:
    """Small report emitted by the worker command."""

    processed: int
    detail: str


class RecoveryWorker:
    """Worker shell for SAT request messages."""

    def __init__(self, service: RecoveryService) -> None:
        self.service = service

    def run_once(self) -> WorkerReport:
        consume_one_with_handler = getattr(self.service.queue, "consume_one_with_handler", None)
        if consume_one_with_handler is None:
            status = self.service.queue_status()
            return WorkerReport(processed=0, detail=f"Queue adapter does not support consumption; observed {len(status)} queue status row(s).")

        def handle(message: QueueMessage) -> WorkerReport:
            result = self.service.process_queue_message(message)
            return WorkerReport(processed=1, detail=f"Processed job {result.job_id} with status {result.status}.")

        report = consume_one_with_handler(QueueName.SAT_REQUEST.value, handle)
        if report is None:
            return WorkerReport(processed=0, detail="No sat.request message available.")
        return report

    def run_forever(self, *, poll_seconds: float = 5.0) -> None:
        while True:
            report = self.run_once()
            print(f"processed={report.processed} detail={report.detail}", flush=True)
            time.sleep(poll_seconds)
