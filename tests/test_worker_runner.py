"""Typer-free worker process entry point.

These tests carry over the worker/ledger-consumer coverage that used to live in
``tests/test_cli_download.py`` when the loop was reachable only as
``cfdi-vault worker run``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cfdi_vault import worker_runner


class FakeWorker:
    """Record the lifecycle calls the runner makes on ``RecoveryWorker``."""

    instance: "FakeWorker | None" = None

    def __init__(self, _service: object, *, ledger_consumer: object | None = None) -> None:
        self.one_shot_calls: list[str] = []
        self.forever_calls: list[dict[str, object]] = []
        FakeWorker.instance = self

    def run_one_shot(self, *, queue_name: str):
        self.one_shot_calls.append(queue_name)
        return type("Report", (), {"processed": 0, "detail": "No synthetic work."})()

    def run_forever(self, **kwargs: object) -> None:
        self.forever_calls.append(kwargs)


@pytest.fixture(autouse=True)
def _reset_fake_worker() -> None:
    FakeWorker.instance = None


def _patch_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_runner, "build_recovery_service", lambda _settings: object())
    monkeypatch.setattr(worker_runner, "build_ledger_consumer", lambda _service: None)
    monkeypatch.setattr("cfdi_vault.worker.RecoveryWorker", FakeWorker)


def test_one_shot_run_uses_lifecycle_wrapper(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _patch_worker(monkeypatch)

    exit_code = worker_runner.main(
        ["--queue", "all"],
        environment={"DATABASE_URL": "postgresql+psycopg://user@host/db"},
    )

    assert exit_code == 0
    assert FakeWorker.instance is not None
    assert FakeWorker.instance.one_shot_calls == ["all"]
    assert FakeWorker.instance.forever_calls == []
    assert "processed=0 detail=No synthetic work." in capsys.readouterr().out


def test_loop_run_forwards_queue_and_poll_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_worker(monkeypatch)

    exit_code = worker_runner.main(
        ["--loop", "--queue", "all", "--poll-seconds", "2.5"],
        environment={"DATABASE_URL": "postgresql+psycopg://user@host/db"},
    )

    assert exit_code == 0
    assert FakeWorker.instance is not None
    assert FakeWorker.instance.one_shot_calls == []
    assert FakeWorker.instance.forever_calls == [{"poll_seconds": 2.5, "queue_name": "all"}]


def test_compose_default_arguments_match_the_retired_cli_invocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``--loop --queue all`` must behave like ``worker run --loop --queue all``."""

    _patch_worker(monkeypatch)

    exit_code = worker_runner.main(
        ["--loop", "--queue", "all"],
        environment={"DATABASE_URL": "postgresql+psycopg://user@host/db"},
    )

    assert exit_code == 0
    assert FakeWorker.instance is not None
    assert FakeWorker.instance.forever_calls == [{"poll_seconds": 5.0, "queue_name": "all"}]


def test_main_fails_closed_without_a_database_url(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = worker_runner.main(["--loop"], environment={})

    assert exit_code == 2
    assert '"reason_code": "database_required"' in capsys.readouterr().out


def test_main_rejects_a_sub_half_second_poll_interval(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = worker_runner.main(
        ["--loop", "--poll-seconds", "0.1"],
        environment={"DATABASE_URL": "postgresql+psycopg://user@host/db"},
    )

    assert exit_code == 2
    assert '"reason_code": "poll_seconds_invalid"' in capsys.readouterr().out


def test_keyboard_interrupt_is_a_clean_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    class InterruptedWorker(FakeWorker):
        def run_forever(self, **_kwargs: object) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr(worker_runner, "build_recovery_service", lambda _settings: object())
    monkeypatch.setattr(worker_runner, "build_ledger_consumer", lambda _service: None)
    monkeypatch.setattr("cfdi_vault.worker.RecoveryWorker", InterruptedWorker)

    exit_code = worker_runner.main(
        ["--loop"], environment={"DATABASE_URL": "postgresql+psycopg://user@host/db"}
    )

    assert exit_code == 0


def test_settings_prefer_flags_over_environment() -> None:
    settings = worker_runner.resolve_worker_settings(
        {
            "DATABASE_URL": "postgresql+psycopg://env@host/env",
            "CFDI_STORAGE_ROOT": "/env/storage",
            "RABBITMQ_URL": "amqp://user@host/",
            "REDIS_URL": "redis://host:6379/0",
        },
        database_url="postgresql+psycopg://flag@host/flag",
        storage=Path("/flag/storage"),
    )

    assert settings.database_url == "postgresql+psycopg://flag@host/flag"
    assert settings.storage_root == Path("/flag/storage")
    assert settings.rabbitmq_url == "amqp://user@host/"
    assert settings.redis_url == "redis://host:6379/0"


def test_settings_default_storage_root_matches_the_retired_cli_default() -> None:
    settings = worker_runner.resolve_worker_settings({"DATABASE_URL": "postgresql+psycopg://user@host/db"})

    assert settings.storage_root == Path("storage")
    assert settings.rabbitmq_url == ""
    assert settings.redis_url == ""


def test_settings_repr_never_exposes_connection_strings() -> None:
    settings = worker_runner.resolve_worker_settings(
        {
            "DATABASE_URL": "postgresql+psycopg://user:secret@host/db",
            "RABBITMQ_URL": "amqp://user:secret@host/",
        }
    )

    assert "secret" not in repr(settings)
    assert "postgresql" not in repr(settings)
    assert "queue_configured=True" in repr(settings)
    assert "cache_configured=False" in repr(settings)


def test_worker_process_entry_point_loads_no_typer_or_cli_module() -> None:
    """The Compose worker must not depend on the shrinking Typer surface."""

    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    script = """
import sys
import cfdi_vault.worker_runner

loaded = sorted(
    name for name in sys.modules
    if name == "typer" or name.startswith(("typer.", "cfdi_vault.adapters.cli"))
)
if loaded:
    raise SystemExit("CLI/Typer modules loaded: " + ",".join(loaded))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout


def test_build_ledger_consumer_injects_v5_writer_from_service_factory() -> None:
    class SessionFactory:
        kw = {"bind": object()}

    service = type("Service", (), {"queue": object(), "session_factory": SessionFactory()})()
    consumer = worker_runner.build_ledger_consumer(service)

    from cfdi_vault.ledger_artifact_bridge import V5LedgerProjectionWriter

    assert consumer is not None
    assert isinstance(service.ledger_writer, V5LedgerProjectionWriter)
    assert service.ledger_writer._mapper._repository._session_factory is service.session_factory  # type: ignore[attr-defined]


def test_build_ledger_consumer_preserves_injected_writer() -> None:
    class SessionFactory:
        kw = {"bind": object()}

    existing = object()
    service = type(
        "Service",
        (),
        {"queue": object(), "session_factory": SessionFactory(), "ledger_writer": existing},
    )()

    consumer = worker_runner.build_ledger_consumer(service)

    assert consumer is not None
    assert service.ledger_writer is existing


def test_build_ledger_consumer_is_absent_without_queue_or_engine() -> None:
    assert worker_runner.build_ledger_consumer(object()) is None


def test_build_ledger_consumer_redacts_writer_failure_reason() -> None:
    class SessionFactory:
        kw = {"bind": object()}

    class Service:
        queue = object()
        session_factory = SessionFactory()

        def process_queue_message_for_worker(self, _message, *, worker_ref: str):  # type: ignore[no-untyped-def]
            from cfdi_vault.queue_contract import TerminalQueueError

            raise TerminalQueueError("ledger_write_failed")

    consumer = worker_runner.build_ledger_consumer(Service())
    from cfdi_vault.accounting_ledger_worker import LedgerParseError

    with pytest.raises(LedgerParseError) as raised:
        consumer._parser(  # type: ignore[union-attr]
            type(
                "Job",
                (),
                {
                    "queue": "cfdi.parse.xml",
                    "tenant_id": "tenant",
                    "artifact_ref": "artifact",
                    "idempotency_key": "key",
                },
            )()
        )

    assert raised.value.reason_code == "ledger_write_failed"
    assert str(raised.value) == "ledger_write_failed"
