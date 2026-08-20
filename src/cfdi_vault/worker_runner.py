"""Typer-free process entry point for the durable recovery worker.

This module is the Compose ``worker`` service front door.  It owns argument
parsing and process wiring only: :class:`~cfdi_vault.worker.RecoveryWorker` and
:class:`~cfdi_vault.recovery_service.RecoveryService` keep every queue,
idempotency, and ledger-parse decision.  Nothing here contacts SAT, and no
credential or connection string is ever printed.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Sequence

if TYPE_CHECKING:
    from cfdi_vault.recovery_service import RecoveryService


class WorkerRuntimeConfigError(ValueError):
    """Raised when the worker process lacks safe non-secret settings."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)

    def __repr__(self) -> str:
        return "WorkerRuntimeConfigError(reason_code=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class WorkerRuntimeSettings:
    """Validated settings for one recovery worker process."""

    database_url: str
    storage_root: Path
    rabbitmq_url: str
    redis_url: str

    def __repr__(self) -> str:
        """Never expose URL credentials or storage paths through diagnostics."""

        return (
            "WorkerRuntimeSettings(database_configured=True, "
            f"queue_configured={bool(self.rabbitmq_url)!r}, "
            f"cache_configured={bool(self.redis_url)!r})"
        )


def resolve_worker_settings(
    environment: Mapping[str, str] | None = None,
    *,
    database_url: str | None = None,
    storage: Path | None = None,
) -> WorkerRuntimeSettings:
    """Resolve worker settings from flags and env without contacting services.

    Mirrors the historical CLI resolution order: an explicit flag wins, then
    ``DATABASE_URL``/``CFDI_STORAGE_ROOT``, and the queue/cache adapters stay
    optional exactly as ``RecoveryService`` expects.
    """

    values = environment if environment is not None else os.environ
    resolved_database_url = str(database_url or values.get("DATABASE_URL", "")).strip()
    if not resolved_database_url:
        raise WorkerRuntimeConfigError("database_required")
    resolved_storage = storage if storage is not None else Path(str(values.get("CFDI_STORAGE_ROOT", "storage")))
    return WorkerRuntimeSettings(
        database_url=resolved_database_url,
        storage_root=Path(resolved_storage),
        rabbitmq_url=str(values.get("RABBITMQ_URL", "")).strip(),
        redis_url=str(values.get("REDIS_URL", "")).strip(),
    )


def build_recovery_service(settings: WorkerRuntimeSettings) -> "RecoveryService":
    """Build the recovery service; construction opens no queue or cache session."""

    from cfdi_vault.cache import RedisCache
    from cfdi_vault.queueing import RabbitMqQueue
    from cfdi_vault.recovery_service import RecoveryService

    queue = RabbitMqQueue(settings.rabbitmq_url) if settings.rabbitmq_url else None
    cache = RedisCache(settings.redis_url) if settings.redis_url else None
    return RecoveryService(
        database_url=settings.database_url,
        storage_root=settings.storage_root,
        queue=queue,
        cache=cache,
    )


def build_ledger_consumer(service: object) -> object | None:
    """Build the durable parse consumer when PostgreSQL and Rabbit are present."""

    queue = getattr(service, "queue", None)
    factory = getattr(service, "session_factory", None)
    engine = getattr(factory, "kw", {}).get("bind") if factory is not None else None
    if queue is None or engine is None:
        return None
    from cfdi_vault.accounting_ledger_jobs_v6 import LedgerJobStoreV6
    from cfdi_vault.accounting_ledger_v5 import AccountingLedgerRepository
    from cfdi_vault.accounting_ledger_v5_mapper import LedgerWriteIntentMapper
    from cfdi_vault.accounting_ledger_worker import LedgerParseAggregate, LedgerParseError
    from cfdi_vault.domain import QueueMessage
    from cfdi_vault.ledger_artifact_bridge import V5LedgerProjectionWriter
    from cfdi_vault.ledger_job_consumer import LedgerJobConsumer
    from cfdi_vault.queue_contract import TerminalQueueError

    store = LedgerJobStoreV6(engine)
    if getattr(service, "ledger_writer", None) is None:
        repository = AccountingLedgerRepository(factory)
        mapper = LedgerWriteIntentMapper(repository)
        setattr(service, "ledger_writer", V5LedgerProjectionWriter(mapper))

    def parser(job: object) -> LedgerParseAggregate:
        from datetime import datetime, timezone

        queue_name = getattr(job, "queue")
        tenant_id = str(getattr(job, "tenant_id"))
        artifact_ref = str(getattr(job, "artifact_ref"))
        message = QueueMessage(
            queue=queue_name,
            tenant_id=tenant_id,
            job_id=artifact_ref,
            correlation_id=artifact_ref,
            idempotency_key=str(getattr(job, "idempotency_key")),
            created_at=datetime.now(timezone.utc),
        )
        try:
            result = service.process_queue_message_for_worker(message, worker_ref="ledger-worker")  # type: ignore[attr-defined]
        except TerminalQueueError as exc:
            raise LedgerParseError(exc.reason_code) from None
        count = max(0, int(getattr(result, "metadata_count", 0)))
        return LedgerParseAggregate(records_seen=count, records_written=count)

    return LedgerJobConsumer(
        store,
        parser,
        consumer_name="cfdi-vault-worker",
        worker_ref="cfdi-vault-worker",
    )


def build_worker(service: object) -> object:
    """Wire the recovery worker with its durable ledger parse consumer."""

    from cfdi_vault.worker import RecoveryWorker

    return RecoveryWorker(service, ledger_consumer=build_ledger_consumer(service))  # type: ignore[arg-type]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cfdi-vault-worker",
        description="Run the durable CFDI recovery worker shell.",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Keep polling the configured queue instead of running once.",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=5.0,
        help="Polling interval when --loop is used.",
    )
    parser.add_argument(
        "--queue",
        dest="queue_name",
        default="all",
        help="Queue name or all campaign/recovery queues.",
    )
    parser.add_argument(
        "--database-url",
        default=None,
        help="PostgreSQL URL. Defaults to DATABASE_URL.",
    )
    parser.add_argument(
        "--storage",
        default=None,
        type=Path,
        help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/.",
    )
    return parser


def main(argv: Sequence[str] | None = None, *, environment: Mapping[str, str] | None = None) -> int:
    """Run one recovery worker poll or the polling loop; SAT is never contacted."""

    args = _build_parser().parse_args(list(argv) if argv is not None else None)
    if args.poll_seconds < 0.5:
        _emit_runtime_error("poll_seconds_invalid")
        return 2
    try:
        settings = resolve_worker_settings(
            environment,
            database_url=args.database_url,
            storage=args.storage,
        )
    except WorkerRuntimeConfigError as exc:
        _emit_runtime_error(exc.reason_code)
        return 2

    worker = build_worker(build_recovery_service(settings))
    try:
        if args.loop:
            worker.run_forever(poll_seconds=args.poll_seconds, queue_name=args.queue_name)  # type: ignore[attr-defined]
            return 0
        report = worker.run_one_shot(queue_name=args.queue_name)  # type: ignore[attr-defined]
    except KeyboardInterrupt:
        # A stopped container is a normal shutdown; durable queue state and
        # PostgreSQL claims remain the source of truth for unfinished work.
        return 0
    print(f"processed={report.processed} detail={report.detail}")
    return 0


def _emit_runtime_error(reason_code: str) -> None:
    print(json.dumps({"status": "error", "reason_code": reason_code}, sort_keys=True))


__all__ = [
    "WorkerRuntimeConfigError",
    "WorkerRuntimeSettings",
    "build_ledger_consumer",
    "build_recovery_service",
    "build_worker",
    "main",
    "resolve_worker_settings",
]


if __name__ == "__main__":
    raise SystemExit(main())
