from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from cfdi_vault.sat_monitor_service import (
    AdaptiveWaitStrategy,
    PostgresAdvisoryLease,
    PostgresScheduleListener,
    RedisMonitorLease,
    SatMonitorService,
    ScheduleWakeSignal,
    _build_adaptive_monitor_service,
    _build_fixed_monitor_service,
    build_monitor_lease,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


class Lease:
    def __init__(self, acquired: bool = True) -> None:
        self.acquired = acquired
        self.released = 0

    def acquire(self) -> bool:
        return self.acquired

    def release(self) -> None:
        self.released += 1


class Runner:
    def __init__(self) -> None:
        self.calls: list[datetime] = []

    def run(self, *, now: datetime, limit: int = 2) -> object:
        self.calls.append(now)
        assert limit == 2
        return {"contacted_count": 0}


def test_busy_lease_does_not_invoke_runner() -> None:
    runner, lease = Runner(), Lease(acquired=False)
    report = SatMonitorService(runner, lease).run_once(now=NOW)
    assert report == {"busy": True, "contacted_count": 0}
    assert runner.calls == []
    assert lease.released == 0


def test_one_shot_releases_lease_and_sends_heartbeat() -> None:
    runner, lease, heartbeats = Runner(), Lease(), []
    report = SatMonitorService(runner, lease, heartbeat=heartbeats.append).run_once(now=NOW)
    assert report == {"contacted_count": 0}
    assert runner.calls == [NOW]
    assert lease.released == 1
    assert heartbeats == [report]


def test_redis_heartbeat_write_failure_is_transient(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import cfdi_vault.cache as cache_module
    import cfdi_vault.sat_monitor_service as subject

    class BrokenCache:
        def __init__(self, _url: str) -> None:
            pass

        def record_heartbeat(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("redis unavailable")

    monkeypatch.setattr(cache_module, "RedisCache", BrokenCache)
    callback = subject.redis_heartbeat_callback("redis://localhost:6379/0")

    callback({"contacted_count": 0})


def test_explicit_none_disables_redis_without_environment_fallback(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import cfdi_vault.cache as cache_module
    import cfdi_vault.sat_monitor_service as subject

    monkeypatch.setenv("REDIS_URL", "redis://must-not-be-used")
    monkeypatch.setattr(
        cache_module,
        "RedisCache",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("Redis must be disabled")),
    )

    callback = subject.redis_heartbeat_callback(None)
    callback({"contacted_count": 0})


def test_loop_wakes_at_interval_without_busy_waiting() -> None:
    runner, lease, sleeps = Runner(), Lease(), []
    rounds = iter((False, True))
    SatMonitorService(runner, lease, sleep=sleeps.append).run_forever(stop=lambda: next(rounds))
    assert len(runner.calls) == 1
    assert sleeps == [300]


def test_adaptive_wait_timeout_before_longer_deadline_is_watchdog() -> None:
    ticks = iter((0.0, 300.0))
    strategy = AdaptiveWaitStrategy(now=lambda: NOW, monotonic=lambda: next(ticks))
    result = strategy.wait_until(NOW + timedelta(minutes=20), lambda _timeout: False, watchdog_seconds=300)
    assert result == "watchdog"


def test_postgres_listener_reconnects_after_connection_failure() -> None:
    stop = SimpleNamespace(waits=0)
    stop.is_set = lambda: stop.waits >= 3
    stop.wait = lambda _timeout: setattr(stop, "waits", stop.waits + 1) or stop.is_set()

    class Engine:
        calls = 0

        def raw_connection(self) -> SimpleNamespace:
            self.calls += 1
            def poll() -> None:
                if self.calls == 1:
                    raise RuntimeError("listener connection lost")

            return SimpleNamespace(
                autocommit=False, notifies=[], poll=poll,
                cursor=lambda: SimpleNamespace(execute=lambda _sql: None), close=lambda: None,
            )

    engine, signal = Engine(), ScheduleWakeSignal()
    listener = PostgresScheduleListener(engine)
    listener._stop = stop  # noqa: SLF001
    listener._signal = signal  # noqa: SLF001

    listener._listen()  # noqa: SLF001
    assert engine.calls == 2
    assert signal.wait(0) == "reconnect"


def test_schedule_channel_is_fixed_across_trigger_and_listener() -> None:
    migration = Path(__file__).resolve().parents[1] / "db/migration/V8__sat_monitor_schedule.sql"
    sql = migration.read_text(encoding="utf-8")
    assert "pg_notify('sat_schedule_changed', '')" in " ".join(sql.split())
    assert PostgresScheduleListener(SimpleNamespace())._channel == "sat_schedule_changed"  # noqa: SLF001
    with pytest.raises(ValueError, match="schedule channel is fixed"):
        PostgresScheduleListener(SimpleNamespace(), channel="sat_schedule_changed_v2")


def test_adaptive_service_heartbeats_waiting_cycle_without_sat_contact() -> None:
    class ScheduleRepository:
        def get_next_due_at(self, *, now: datetime) -> datetime:
            return now + timedelta(minutes=20)

        def record_monitor_run(self, **_kwargs: object) -> None:
            return None

    class Wait:
        def wait_until(self, _deadline, _wake, _watchdog_seconds):  # type: ignore[no-untyped-def]
            return "watchdog"

    heartbeats: list[object] = []
    service = SatMonitorService(
        Runner(), Lease(), heartbeat=heartbeats.append, schedule_repository=ScheduleRepository(),
        wait_strategy=Wait(), clock=lambda: NOW,
    )
    rounds = iter((False, False, True))

    service.run_forever(stop=lambda: next(rounds))

    assert len(heartbeats) == 1
    assert heartbeats[0]["monitor_state"] == "waiting"
    assert heartbeats[0]["due_count"] == 0
    assert heartbeats[0]["contacted_count"] == 0


def test_adaptive_monitor_builder_wires_durable_schedule_inputs() -> None:
    repository = object()
    service = _build_adaptive_monitor_service(
        Runner(), Lease(), SimpleNamespace(), repository, lambda _result: None,
        channel="sat_schedule_changed", watchdog_seconds=900,
    )

    assert service._schedule_repository is repository  # noqa: SLF001
    assert isinstance(service._schedule_listener, PostgresScheduleListener)  # noqa: SLF001
    assert service._watchdog_seconds == 900  # noqa: SLF001
    assert service._schedule_listener._channel == "sat_schedule_changed"  # noqa: SLF001
    with pytest.raises(ValueError, match="schedule channel is fixed"):
        _build_adaptive_monitor_service(
            Runner(), Lease(), SimpleNamespace(), repository, lambda _result: None,
            channel="sat_schedule_changed_v2",
        )
    default_service = _build_adaptive_monitor_service(
        Runner(), Lease(), SimpleNamespace(), repository, lambda _result: None,
    )
    assert default_service._watchdog_seconds == 300  # noqa: SLF001


def test_fixed_monitor_builder_preserves_one_shot_fallback() -> None:
    service = _build_fixed_monitor_service(Runner(), Lease(), lambda _result: None, 900)

    assert service._schedule_repository is None  # noqa: SLF001
    assert service._interval == 900  # noqa: SLF001


def test_adaptive_service_records_sanitized_runner_error_before_propagating() -> None:
    class ScheduleRepository:
        def __init__(self) -> None:
            self.cycles: list[dict[str, object]] = []

        def get_next_due_at(self, *, now: datetime) -> datetime | None:
            return now

        def record_monitor_run(self, **kwargs: object) -> None:
            self.cycles.append(kwargs)

    class BrokenRunner:
        def run(self, *, now: datetime, limit: int = 2) -> object:
            raise RuntimeError("synthetic runner failure")

    class Wait:
        def wait_until(self, deadline, wake, watchdog_seconds):  # type: ignore[no-untyped-def]
            return "due"

    repository, heartbeats = ScheduleRepository(), []
    service = SatMonitorService(
        BrokenRunner(), Lease(), schedule_repository=repository, wait_strategy=Wait(),
        heartbeat=heartbeats.append, clock=lambda: NOW,
    )
    rounds = iter((False, False, True))

    with pytest.raises(RuntimeError, match="synthetic runner failure"):
        service.run_forever(stop=lambda: next(rounds))

    assert repository.cycles[0]["error_count"] == 1
    assert repository.cycles[0]["terminal_category"] == "runner_error"
    assert heartbeats[0]["error_count"] == 1


def test_advisory_lease_closes_connection_when_lock_query_fails() -> None:
    class Connection:
        closed = False

        def execute(self, *_args: object, **_kwargs: object) -> object:
            raise RuntimeError("database unavailable")

        def close(self) -> None:
            self.closed = True

    connection = Connection()
    engine = SimpleNamespace(connect=lambda: connection)

    with pytest.raises(RuntimeError, match="database unavailable"):
        PostgresAdvisoryLease(engine).acquire()

    assert connection.closed is True


def test_redis_monitor_lease_is_owner_fenced_and_releasable() -> None:
    class Cache:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, int]] = []
            self.released: list[tuple[str, str]] = []

        def acquire_lock(self, key: str, owner: str, ttl: int) -> bool:
            self.calls.append((key, owner, ttl))
            return True

        def release_lock(self, key: str, owner: str) -> bool:
            self.released.append((key, owner))
            return True

    cache = Cache()
    lease = RedisMonitorLease("redis://synthetic", "owner-synthetic", cache=cache)

    assert lease.acquire() is True
    lease.release()
    assert cache.calls == [("lock:sat-monitor", "owner-synthetic", 600)]
    assert cache.released == [("lock:sat-monitor", "owner-synthetic")]


def test_monitor_lease_falls_back_to_postgres_without_redis() -> None:
    engine = SimpleNamespace()
    lease = build_monitor_lease(engine, None)
    assert isinstance(lease, PostgresAdvisoryLease)


def test_monitor_main_disposes_engine_when_schema_check_fails(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import cfdi_vault.db as db
    import cfdi_vault.sat_monitor_service as subject

    engine = SimpleNamespace(disposed=False, dispose=lambda: setattr(engine, "disposed", True))
    settings = SimpleNamespace(
        sat_monitor_enabled=True,
        live_worker_enabled=True,
        database_url="postgresql+psycopg://user:password@localhost:5432/vault",
        campaign_profile=None,
        campaign_ref=None,
        campaign_grant=None,
        redis_url=None,
    )
    monkeypatch.setattr(subject, "_resolve_monitor_settings", lambda: settings)
    monkeypatch.setattr(db, "create_engine_from_url", lambda _url: engine)
    monkeypatch.setattr(
        db,
        "ensure_tables_exist",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("schema unavailable")),
    )

    with pytest.raises(RuntimeError, match="schema unavailable"):
        subject.main()

    assert engine.disposed is True


def test_enabled_runner_uses_guarded_runtime_factories_without_contact(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import cfdi_vault.sat_monitor_service as subject
    from cfdi_vault.sat_live_worker_runtime import SatWorkerFactories

    factories = SatWorkerFactories(
        submitter_factory=object(),
        verifier_factory=object(),
        downloader_factory=object(),
        query_factory=object(),
        artifact_coordinator=object(),
    )
    runtime_calls: list[dict[str, object]] = []
    runner_calls: list[dict[str, object]] = []

    def build_factories(*args, **kwargs):  # type: ignore[no-untyped-def]
        runtime_calls.append({"args": args, "kwargs": kwargs})
        return factories

    def build_runner(*args, **kwargs):  # type: ignore[no-untyped-def]
        runner_calls.append({"args": args, "kwargs": kwargs})
        return Runner()

    monkeypatch.setattr(
        "cfdi_vault.sat_live_worker_runtime.build_metadata_worker_factories",
        build_factories,
    )
    monkeypatch.setattr(subject, "build_database_runner", build_runner)
    repository = object()
    result = subject.build_enabled_database_runner(
        repository,
        profile_id="profile",
        campaign_ref="campaign",
        grant_ref="grant",
        environ={"CFDI_VAULT_LIVE_WORKER_ENABLED": "1"},
    )

    assert isinstance(result, Runner)
    assert runtime_calls[0]["args"] == ("profile", repository)
    assert runtime_calls[0]["kwargs"]["campaign_ref"] == "campaign"
    assert runtime_calls[0]["kwargs"]["grant_ref"] == "grant"
    assert runner_calls[0]["args"] == (repository, factories.verifier_factory)
    assert runner_calls[0]["kwargs"]["artifact_coordinator"] is factories.artifact_coordinator
    assert runner_calls[0]["kwargs"]["environ"] == {"CFDI_VAULT_LIVE_WORKER_ENABLED": "1"}


def test_empty_environment_does_not_fall_back_to_process_environment(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import cfdi_vault.sat_monitor_service as subject

    monkeypatch.setenv("RABBITMQ_URL", "amqp://should-not-be-read")
    monkeypatch.setenv("CFDI_STORAGE_ROOT", "C:/should-not-be-read")
    monkeypatch.setattr(
        "cfdi_vault.queueing.RabbitMqQueue",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("queue must not be built")),
    )

    runner = subject.build_database_runner(object(), lambda _request_id: object(), environ={})

    assert getattr(runner, "_artifact_coordinator") is None


def test_disabled_monitor_is_silent_and_does_not_build_sat_runtime(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import cfdi_vault.sat_monitor_service as subject

    monkeypatch.setenv("SAT_MONITOR_ENABLED", "0")
    monkeypatch.setenv("CFDI_VAULT_LIVE_WORKER_ENABLED", "1")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://user:password@localhost:5432/vault")
    monkeypatch.setenv("CFDI_STORAGE_ROOT", "C:/sat-monitor-test-storage")
    monkeypatch.setattr(
        subject,
        "build_enabled_database_runner",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("disabled monitor must not build runtime")),
    )

    assert subject.main() is None


def test_monitor_main_is_noop_without_live_worker_gate(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import cfdi_vault.sat_monitor_service as subject

    monkeypatch.setenv("SAT_MONITOR_ENABLED", "1")
    monkeypatch.setenv("CFDI_VAULT_LIVE_WORKER_ENABLED", "0")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://user:password@localhost:5432/vault")
    monkeypatch.setenv("CFDI_STORAGE_ROOT", "C:/sat-monitor-test-storage")
    monkeypatch.setattr(
        subject,
        "build_enabled_database_runner",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("must not build runtime")),
    )

    subject.main()
