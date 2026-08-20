"""Regression guard for the ``--queue all`` fan-out deny-list (ADR 0005)."""

from __future__ import annotations

from cfdi_vault.domain import QueueName
from cfdi_vault.queue_contract import WorkerJobType
from cfdi_vault.queueing import InMemoryQueue
from cfdi_vault.worker import FAN_OUT_EXCLUDED_QUEUES, RecoveryWorker


class _Service:
    """Stand-in for the fake-SAT ``RecoveryService`` the worker container runs."""

    def __init__(self) -> None:
        self.queue = InMemoryQueue()
        self.polled: list[str] = []
        self.cache = None

    def process_queue_message(self, message: object) -> object:  # pragma: no cover - never reached
        raise AssertionError("fan-out must not process a campaign-run wake hint")


class _RecordingQueue(InMemoryQueue):
    def __init__(self, polled: list[str]) -> None:
        super().__init__()
        self._polled = polled

    def consume_one_reliably(self, queue_name: str, handler: object) -> None:
        self._polled.append(queue_name)
        return None


def test_campaign_run_queue_is_excluded_from_the_all_fan_out() -> None:
    assert QueueName.SAT_CAMPAIGN_RUN in FAN_OUT_EXCLUDED_QUEUES


def test_all_fan_out_never_polls_the_campaign_run_wake_hint() -> None:
    """The fake-SAT worker container must never claim a live campaign-run hint.

    Acknowledging one would swallow the wake for the real host-only consumer and
    route a live SAT command through the generic retry/dead-letter machinery.
    """

    polled: list[str] = []
    service = _Service()
    service.queue = _RecordingQueue(polled)
    worker = RecoveryWorker(service)  # type: ignore[arg-type]

    worker.run_once(queue_name="all")

    assert polled, "the fan-out must still poll the ordinary recovery queues"
    assert QueueName.SAT_CAMPAIGN_RUN.value not in polled
    assert QueueName.SAT_REQUEST.value in polled
    assert QueueName.CFDI_EXPORT.value in polled


def test_campaign_run_queue_has_no_typed_worker_job_family() -> None:
    """The wake hint stays outside the typed worker-job contract on purpose."""

    assert QueueName.SAT_CAMPAIGN_RUN.value not in {member.value for member in WorkerJobType}
