from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cfdi_vault.accounting_ledger_outbox_v6 import OutboxClaim
from cfdi_vault.ledger_outbox_publisher import LedgerOutboxPublisher, OutboxPublishFailure
from cfdi_vault.ledger_outbox_service import (
    LedgerOutboxDrainService,
    OutboxRuntimeConfigError,
    OutboxRuntimeSettings,
    build_outbox_runtime,
    main,
    resolve_outbox_settings,
)

NOW = datetime(2026, 1, 14, 12, tzinfo=timezone.utc)


def _claim(number: int) -> OutboxClaim:
    return OutboxClaim(
        event_id=f"event-{number}",
        job_id=f"job-{number}",
        claim_id=f"claim-{number}",
        event_type="metadata_parse",
        routing_key="cfdi.parse.metadata",
        tenant_id="tenant-synthetic",
        job_type="metadata_parse",
        artifact_ref=f"artifact-{number}",
        queue_name="cfdi.parse.metadata",
        idempotency_key=f"idempotency-{number}",
        schema_version=1,
    )


@dataclass
class Store:
    claims: deque[OutboxClaim]
    fail_claim: bool = False

    def __post_init__(self) -> None:
        self.calls: list[str] = []
        self.failed: list[str] = []
        self.published: list[str] = []

    def claim_outbox_event(self, now: datetime, worker_ref: str, lease: timedelta) -> OutboxClaim | None:
        self.calls.append("claim")
        return self.claims.popleft() if self.claims else None

    def mark_outbox_published(self, event_id: str, claim_id: str, *, now: datetime | None = None) -> bool:
        self.calls.append("published")
        self.published.append(event_id)
        return True

    def mark_outbox_failed(
        self, event_id: str, claim_id: str, reason_code: str, *, now: datetime | None = None
    ) -> bool:
        self.calls.append("failed")
        self.failed.append(reason_code)
        return not self.fail_claim

    def mark_outbox_uncertain(
        self, event_id: str, claim_id: str, reason_code: str, *, now: datetime | None = None
    ) -> bool:
        self.calls.append("uncertain")
        return True


class Broker:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.messages = []

    def publish(self, message: object) -> bool:
        self.messages.append(message)
        if self.error is not None:
            raise self.error
        return True


def _service(store: Store, broker: Broker, **kwargs: object) -> LedgerOutboxDrainService:
    publisher = LedgerOutboxPublisher(store, broker, lease=timedelta(minutes=5))
    return LedgerOutboxDrainService(publisher, worker_ref="outbox-worker-synthetic", **kwargs)


def test_drain_publishes_multiple_due_events() -> None:
    store = Store(deque([_claim(1), _claim(2)]))
    broker = Broker()

    report = _service(store, broker).run_once(now=NOW)

    assert report.as_dict() == {
        "status": "drained",
        "attempted": 2,
        "published": 2,
        "failed": 0,
        "stale": 0,
        "invalid": 0,
        "reason_code": None,
    }
    assert store.published == ["event-1", "event-2"]
    assert len(broker.messages) == 2


def test_no_due_events_is_idle_and_does_not_publish_status_details() -> None:
    store = Store(deque())
    broker = Broker()
    statuses: list[dict[str, object]] = []

    report = _service(store, broker, status_sink=statuses.append).run_once(now=NOW)

    assert report.status == "idle"
    assert broker.messages == []
    assert statuses == [report.as_dict()]


def test_new_service_instance_resumes_remaining_rows_after_restart() -> None:
    store = Store(deque([_claim(1), _claim(2)]))
    first_broker = Broker()
    first = _service(store, first_broker, max_events=1).run_once(now=NOW)

    second_broker = Broker()
    second = _service(store, second_broker).run_once(now=NOW)

    assert first.published == 1
    assert second.published == 1
    assert store.published == ["event-1", "event-2"]


def test_publisher_exception_is_redacted_and_does_not_escape_loop() -> None:
    store = Store(deque([_claim(1)]))
    statuses: list[dict[str, object]] = []
    service = _service(
        store,
        Broker(error=OutboxPublishFailure("broker_rejected")),
        status_sink=statuses.append,
    )

    report = service.run_once(now=NOW)

    assert report.status == "partial"
    assert report.failed == 1
    assert report.reason_code == "broker_rejected"
    assert statuses == [report.as_dict()]


def test_unexpected_publisher_exception_is_categorized_without_sensitive_text() -> None:
    class BrokenPublisher:
        def run_once(self, **_kwargs: object) -> object:
            raise RuntimeError("RFC secret XML payload")

    statuses: list[dict[str, object]] = []
    service = LedgerOutboxDrainService(
        BrokenPublisher(),  # type: ignore[arg-type]
        worker_ref="outbox-worker-synthetic",
        status_sink=statuses.append,
    )

    report = service.run_once(now=NOW)

    assert report.as_dict() == {
        "status": "error",
        "attempted": 0,
        "published": 0,
        "failed": 0,
        "stale": 0,
        "invalid": 0,
        "reason_code": "publisher_exception",
    }
    assert "RFC secret XML payload" not in repr(report)
    assert statuses == [report.as_dict()]


def test_loop_wakes_and_can_be_stopped_without_busy_retries() -> None:
    store = Store(deque())
    broker = Broker()
    sleeps: list[float] = []
    rounds = iter((False, True))
    _service(store, broker, poll_seconds=12, sleep=sleeps.append).run_forever(stop=lambda: next(rounds))

    assert sleeps == [12.0]


def test_runtime_settings_require_postgres_and_rabbit_urls() -> None:
    try:
        resolve_outbox_settings({})
    except OutboxRuntimeConfigError as exc:
        assert exc.reason_code == "database_required"
    else:  # pragma: no cover - assertion branch
        raise AssertionError("missing database URL must fail closed")

    environment = {"DATABASE_URL": "sqlite:///not-supported", "RABBITMQ_URL": "amqp://broker"}
    try:
        resolve_outbox_settings(environment)
    except OutboxRuntimeConfigError as exc:
        assert exc.reason_code == "postgresql_required"
    else:  # pragma: no cover - assertion branch
        raise AssertionError("non-PostgreSQL URL must fail closed")


def test_runtime_settings_are_bounded_and_disabled_by_default() -> None:
    settings = resolve_outbox_settings(
        {
            "DATABASE_URL": "postgresql+psycopg://user:password@db:5432/vault",
            "RABBITMQ_URL": "amqp://user:password@broker:5672/",
        }
    )
    assert settings.enabled is False
    assert settings.poll_seconds == 5
    assert settings.max_events == 100
    assert settings.worker_ref == "ledger-outbox-worker"

    try:
        resolve_outbox_settings(
            {
                "DATABASE_URL": settings.database_url,
                "RABBITMQ_URL": settings.rabbitmq_url,
                "LEDGER_OUTBOX_MAX_EVENTS": "1001",
            }
        )
    except OutboxRuntimeConfigError as exc:
        assert exc.reason_code == "max_events_invalid"
    else:  # pragma: no cover - assertion branch
        raise AssertionError("max-events bound must be enforced")


def test_runtime_configuration_repr_redacts_urls_and_credentials() -> None:
    settings = resolve_outbox_settings(
        {
            "DATABASE_URL": "postgresql+psycopg://fixture-user:fixture-value@db:5432/vault",
            "RABBITMQ_URL": "amqp://fixture-user:fixture-value@broker:5672/",
        }
    )

    rendered = repr(settings)
    assert "postgresql" not in rendered
    assert "amqp" not in rendered
    assert "password" not in rendered
    assert "secret" not in rendered


def test_runtime_builder_wires_db_store_and_reference_queue(monkeypatch) -> None:
    class Engine:
        def __init__(self) -> None:
            self.disposed = False

        def dispose(self) -> None:
            self.disposed = True

    engine = Engine()
    checked: list[tuple[object, tuple[str, ...]]] = []
    monkeypatch.setattr(
        "cfdi_vault.db.ensure_tables_exist",
        lambda target, tables: checked.append((target, tuple(tables))),
    )
    settings = OutboxRuntimeSettings(
        "postgresql+psycopg://user:password@db:5432/vault",
        "amqp://user:password@broker:5672/",
        "publisher-synthetic",
        5,
        2,
        True,
    )

    runtime = build_outbox_runtime(settings, engine_factory=lambda _url: engine)
    try:
        assert checked == [(engine, ("ledger_jobs", "ledger_outbox"))]
        assert runtime.service.worker_ref == "publisher-synthetic"
        assert runtime.service.max_events == 2
        assert runtime.service.publisher.publisher.url == settings.rabbitmq_url
    finally:
        runtime.close()
    assert engine.disposed is True


def test_main_missing_config_is_sanitized(capsys) -> None:
    assert main(["--once"], environment={}) == 2
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out.strip() == '{"reason_code": "database_required", "status": "error"}'


def test_main_disabled_gate_has_no_runtime_side_effect(capsys) -> None:
    environment = {
        "DATABASE_URL": "postgresql+psycopg://user:password@db:5432/vault",
        "RABBITMQ_URL": "amqp://user:password@broker:5672/",
    }
    assert main(["--once"], environment=environment) == 0
    assert capsys.readouterr().out.strip() == '{"reason_code": "feature_disabled", "status": "disabled"}'
