"""Restartable one-shot drain for the durable ledger outbox.

This internal service owns scheduling only.  PostgreSQL remains the source of
truth through :class:`LedgerOutboxPublisher`; the broker receives the existing
reference-only envelope, and the optional status sink receives only aggregate
counts and fixed reason codes.  No SAT call, artifact bytes, or fiscal fields
are handled here.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Sequence
from urllib.parse import urlsplit

from sqlalchemy.engine import Engine, make_url

from cfdi_vault.ledger_outbox_publisher import LedgerOutboxPublisher
from cfdi_vault.queue_safety import validate_reason_code, validate_reference_string


@dataclass(frozen=True, slots=True, repr=False)
class OutboxDrainReport:
    """Redacted aggregate result of one durable outbox drain pass."""

    status: str
    attempted: int = 0
    published: int = 0
    failed: int = 0
    stale: int = 0
    invalid: int = 0
    reason_code: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"idle", "drained", "partial", "error"}:
            raise ValueError("unsupported outbox drain status")
        for name in ("attempted", "published", "failed", "stale", "invalid"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"outbox drain {name} must be non-negative")
        if self.reason_code is not None:
            validate_reason_code(self.reason_code)

    def __repr__(self) -> str:
        return (
            "OutboxDrainReport(status={!r}, attempted={}, published={}, failed={}, "
            "stale={}, invalid={}, reason_code={!r})"
        ).format(
            self.status,
            self.attempted,
            self.published,
            self.failed,
            self.stale,
            self.invalid,
            self.reason_code,
        )

    def as_dict(self) -> dict[str, int | str | None]:
        """Return only operational aggregates safe for logs and status APIs."""

        return {
            "status": self.status,
            "attempted": self.attempted,
            "published": self.published,
            "failed": self.failed,
            "stale": self.stale,
            "invalid": self.invalid,
            "reason_code": self.reason_code,
        }


class LedgerOutboxDrainService:
    """Drain due outbox rows and resume them after process restarts.

    Every pass claims rows through the injected publisher, so a new service
    instance does not need local recovery state.  A retryable failure stops the
    current pass after recording its aggregate result; a later pass can claim
    the failed row again without repeatedly publishing it in one tight loop.
    """

    def __init__(
        self,
        publisher: LedgerOutboxPublisher,
        *,
        worker_ref: str = "ledger-outbox-worker",
        max_events: int = 100,
        poll_seconds: float = 5.0,
        clock: Callable[[], datetime] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        status_sink: Callable[[dict[str, int | str | None]], None] | None = None,
    ) -> None:
        validate_reference_string("worker_ref", worker_ref)
        if type(max_events) is not int or max_events < 1:
            raise ValueError("outbox drain max_events must be positive")
        if isinstance(poll_seconds, bool) or not isinstance(poll_seconds, (int, float)) or poll_seconds <= 0:
            raise ValueError("outbox drain poll_seconds must be positive")
        self.publisher = publisher
        self.worker_ref = worker_ref
        self.max_events = max_events
        self.poll_seconds = float(poll_seconds)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.sleep = sleep
        self.status_sink = status_sink or (lambda _status: None)

    def run_once(self, *, now: datetime | None = None, limit: int | None = None) -> OutboxDrainReport:
        """Drain up to ``limit`` due rows without waiting or contacting SAT."""

        stamp = self._stamp(now or self.clock())
        cap = self.max_events if limit is None else limit
        if type(cap) is not int or cap < 1:
            raise ValueError("outbox drain limit must be positive")
        cap = min(cap, self.max_events)
        attempted = published = failed = stale = invalid = 0
        reason_code: str | None = None
        for _ in range(cap):
            try:
                result = self.publisher.run_once(now=stamp, worker_ref=self.worker_ref)
            except Exception:
                # Do not leak transport text or let one broken adapter kill a
                # long-running monitor.  The durable claim lease will expire.
                reason_code = "publisher_exception"
                report = OutboxDrainReport("error", attempted, published, failed, stale, invalid, reason_code)
                self._publish_status(report)
                return report
            if result.status == "idle":
                status = "idle" if attempted == 0 else "drained"
                report = OutboxDrainReport(status, attempted, published, failed, stale, invalid, reason_code)
                self._publish_status(report)
                return report
            attempted += 1
            if result.status == "published":
                published += 1
                continue
            if result.status in {"failed", "uncertain"}:
                failed += 1
                reason_code = result.reason_code or "publish_failed"
                # Stop after one failed row. The store owns its bounded retry
                # schedule, so a later pass—not this loop—decides when it is
                # due again.
                break
            if result.status == "stale":
                stale += 1
            elif result.status == "invalid":
                invalid += 1
            reason_code = result.reason_code or reason_code
            break
        if failed == 0 and stale == 0 and invalid == 0:
            status = "partial" if attempted == cap else "drained"
            if status == "partial":
                reason_code = "max_events_reached"
        else:
            status = "partial"
        report = OutboxDrainReport(status, attempted, published, failed, stale, invalid, reason_code)
        self._publish_status(report)
        return report

    def run_forever(self, *, stop: Callable[[], bool] | None = None) -> None:
        """Wake periodically and drain due rows until the injected stop signal."""

        should_stop = stop or (lambda: False)
        while not should_stop():
            self.run_once()
            self.sleep(self.poll_seconds)

    @staticmethod
    def _stamp(value: datetime) -> datetime:
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ValueError("outbox drain timestamp must be timezone-aware")
        return value

    def _publish_status(self, report: OutboxDrainReport) -> None:
        try:
            self.status_sink(report.as_dict())
        except Exception:
            # Operational status is best effort; PostgreSQL and broker state
            # remain authoritative when a transient sink is unavailable.
            return


class OutboxRuntimeConfigError(ValueError):
    """Raised when the publisher process lacks safe non-secret settings."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = validate_reason_code(reason_code)
        super().__init__(self.reason_code)

    def __repr__(self) -> str:
        return "OutboxRuntimeConfigError(reason_code=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class OutboxRuntimeSettings:
    """Validated settings for the internal PostgreSQL-to-RabbitMQ publisher."""

    database_url: str
    rabbitmq_url: str
    worker_ref: str
    poll_seconds: float
    max_events: int
    enabled: bool

    def __repr__(self) -> str:
        """Never expose URL credentials through diagnostics or logs."""

        return (
            "OutboxRuntimeSettings(database_configured=True, rabbitmq_configured=True, "
            f"worker_ref={self.worker_ref!r}, poll_seconds={self.poll_seconds!r}, "
            f"max_events={self.max_events!r}, enabled={self.enabled!r})"
        )


@dataclass(slots=True, repr=False)
class OutboxRuntime:
    """Owned engine and drain service; callers must close the engine."""

    engine: Engine
    service: LedgerOutboxDrainService

    def __repr__(self) -> str:
        """Keep engine/queue URLs and nested publisher state out of output."""

        return "OutboxRuntime(configured=True)"

    def close(self) -> None:
        """Release PostgreSQL connections without exposing connection details."""

        self.engine.dispose()


def resolve_outbox_settings(environment: Mapping[str, str] | None = None) -> OutboxRuntimeSettings:
    """Resolve required URLs and bounded publisher settings without contacting services."""

    values = environment if environment is not None else os.environ
    database_url = str(values.get("DATABASE_URL", "")).strip()
    rabbitmq_url = str(values.get("RABBITMQ_URL", "")).strip()
    if not database_url:
        raise OutboxRuntimeConfigError("database_required")
    if not rabbitmq_url:
        raise OutboxRuntimeConfigError("rabbitmq_required")
    try:
        if not make_url(database_url).drivername.startswith("postgresql"):
            raise OutboxRuntimeConfigError("postgresql_required")
    except OutboxRuntimeConfigError:
        raise
    except Exception as exc:
        raise OutboxRuntimeConfigError("database_invalid") from exc
    try:
        parts = urlsplit(rabbitmq_url)
        if (
            parts.scheme.lower() not in {"amqp", "amqps"}
            or not parts.netloc
            or not parts.hostname
            or (parts.port is not None and not 1 <= parts.port <= 65_535)
        ):
            raise OutboxRuntimeConfigError("rabbitmq_invalid")
    except OutboxRuntimeConfigError:
        raise
    except (TypeError, UnicodeError, ValueError) as exc:
        raise OutboxRuntimeConfigError("rabbitmq_invalid") from exc

    enabled = _parse_bool(values.get("LEDGER_OUTBOX_ENABLED", "0"), "enabled")
    poll_seconds = _parse_float(values.get("LEDGER_OUTBOX_POLL_SECONDS", "5"), "poll_seconds", 1, 3600)
    max_events = _parse_int(values.get("LEDGER_OUTBOX_MAX_EVENTS", "100"), "max_events", 1, 1000)
    worker_ref = str(values.get("LEDGER_OUTBOX_WORKER_REF", "ledger-outbox-worker")).strip()
    try:
        validate_reference_string("worker_ref", worker_ref)
    except (TypeError, ValueError) as exc:
        raise OutboxRuntimeConfigError("worker_ref_invalid") from exc
    return OutboxRuntimeSettings(database_url, rabbitmq_url, worker_ref, poll_seconds, max_events, enabled)


def build_outbox_runtime(
    settings: OutboxRuntimeSettings,
    *,
    engine_factory: Callable[[str], Engine] | None = None,
    status_sink: Callable[[dict[str, int | str | None]], None] | None = None,
) -> OutboxRuntime:
    """Build the DB-backed outbox drain; construction never instantiates SAT adapters."""

    from cfdi_vault.accounting_ledger_jobs_v6 import LedgerJobStoreV6
    from cfdi_vault.db import create_engine_from_url, ensure_tables_exist
    from cfdi_vault.queueing import RabbitMqQueue

    factory = engine_factory or create_engine_from_url
    engine = factory(settings.database_url)
    try:
        ensure_tables_exist(engine, ("ledger_jobs", "ledger_outbox"))
        store = LedgerJobStoreV6(engine)
        broker = RabbitMqQueue(settings.rabbitmq_url)
        publisher = LedgerOutboxPublisher(store=store, publisher=broker)
        service = LedgerOutboxDrainService(
            publisher,
            worker_ref=settings.worker_ref,
            max_events=settings.max_events,
            poll_seconds=settings.poll_seconds,
            status_sink=status_sink,
        )
        return OutboxRuntime(engine, service)
    except Exception:
        engine.dispose()
        raise


def main(argv: Sequence[str] | None = None, *, environment: Mapping[str, str] | None = None) -> int:
    """Run one sanitized outbox pass or a periodic loop; SAT is never contacted."""

    parser = argparse.ArgumentParser(prog="ledger-publisher")
    parser.add_argument("--once", action="store_true", help="drain one due batch and exit")
    parser.add_argument("--loop", action="store_true", help="wake periodically and drain due batches")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.once and args.loop:
        _emit_runtime_error("mode_conflict")
        return 2
    try:
        settings = resolve_outbox_settings(environment)
    except OutboxRuntimeConfigError as exc:
        _emit_runtime_error(exc.reason_code)
        return 2
    if not settings.enabled:
        print(json.dumps({"status": "disabled", "reason_code": "feature_disabled"}, sort_keys=True))
        return 0

    def emit(status: dict[str, int | str | None]) -> None:
        print(json.dumps(status, sort_keys=True))

    runtime: OutboxRuntime | None = None
    try:
        runtime = build_outbox_runtime(settings, status_sink=emit)
        if args.once:
            runtime.service.run_once()
        else:
            runtime.service.run_forever()
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        _emit_runtime_error("runtime_unavailable")
        return 2
    finally:
        if runtime is not None:
            runtime.close()


def _emit_runtime_error(reason_code: str) -> None:
    print(json.dumps({"status": "error", "reason_code": reason_code}, sort_keys=True))


def _parse_bool(raw: object, name: str) -> bool:
    value = str(raw).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise OutboxRuntimeConfigError(f"{name}_invalid")


def _parse_int(raw: object, name: str, minimum: int, maximum: int) -> int:
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise OutboxRuntimeConfigError(f"{name}_invalid") from exc
    if not minimum <= value <= maximum:
        raise OutboxRuntimeConfigError(f"{name}_invalid")
    return value


def _parse_float(raw: object, name: str, minimum: float, maximum: float) -> float:
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise OutboxRuntimeConfigError(f"{name}_invalid") from exc
    if value != value or not minimum <= value <= maximum:
        raise OutboxRuntimeConfigError(f"{name}_invalid")
    return value


__all__ = [
    "LedgerOutboxDrainService",
    "OutboxDrainReport",
    "OutboxRuntime",
    "OutboxRuntimeConfigError",
    "OutboxRuntimeSettings",
    "build_outbox_runtime",
    "main",
    "resolve_outbox_settings",
]


if __name__ == "__main__":
    raise SystemExit(main())
