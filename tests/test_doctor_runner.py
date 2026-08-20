"""One-shot dependency check for the Compose ``app`` service.

This replaces what ``cfdi-vault doctor`` provided.  The two behaviours the
retired CLI tests proved — the storage root resolves from ``CFDI_STORAGE_ROOT``
unless overridden, and a failing check exits non-zero — are asserted here
against the module the ``app`` service actually runs.

The redaction assertions are new and deliberate.  ``adapters/webapi/app.py``
already had to stop ``RecoveryService.doctor()`` from putting raw storage paths
and driver exception text into an HTTP response; container logs deserve the
same treatment, so the same rule is proved here rather than assumed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cfdi_vault import doctor_runner as subject
from cfdi_vault.recovery_service import DoctorCheck


class _FakeService:
    def __init__(self, checks: tuple[DoctorCheck, ...]) -> None:
        self._checks = checks
        self.closed = False

    def doctor(self) -> tuple[DoctorCheck, ...]:
        return self._checks

    def close(self) -> None:
        self.closed = True


def _install(
    monkeypatch: pytest.MonkeyPatch, checks: tuple[DoctorCheck, ...],
) -> tuple[_FakeService, list[tuple[str | None, Path | None]]]:
    service = _FakeService(checks)
    calls: list[tuple[str | None, Path | None]] = []

    def build(database_url: str | None = None, storage: Path | None = None) -> _FakeService:
        calls.append((database_url, storage))
        return service

    monkeypatch.setattr(subject, "recovery_service", build)
    return service, calls


ALL_OK = (
    DoctorCheck("database", True, "schema reachable"),
    DoctorCheck("queue", True, "adapter reachable; pending=0"),
    DoctorCheck("cache", True, "adapter reachable"),
    DoctorCheck("storage", True, "/var/lib/cfdi-vault/storage/xml, /var/lib/cfdi-vault/storage/logs"),
)


def test_all_checks_passing_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    service, _ = _install(monkeypatch, ALL_OK)

    exit_code, rows = subject.run_doctor({"DATABASE_URL": "postgresql://synthetic/db"})

    assert exit_code == 0
    assert [row["check"] for row in rows] == ["database", "queue", "cache", "storage"]
    assert all(row["ok"] for row in rows)
    assert service.closed is True


def test_any_failing_check_exits_non_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    checks = ALL_OK[:1] + (DoctorCheck("queue", False, "connection refused"),) + ALL_OK[2:]
    _install(monkeypatch, checks)

    exit_code, rows = subject.run_doctor({"DATABASE_URL": "postgresql://synthetic/db"})

    assert exit_code == 1
    assert rows[1] == {"check": "queue", "ok": False, "detail": "queue check failed"}


def test_storage_success_detail_never_carries_the_resolved_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The storage check's detail is the absolute paths it just created."""

    _install(monkeypatch, ALL_OK)

    _exit_code, rows = subject.run_doctor({"DATABASE_URL": "postgresql://synthetic/db"})

    storage_row = next(row for row in rows if row["check"] == "storage")
    assert storage_row == {"check": "storage", "ok": True, "detail": "layout ensured"}
    assert "/var/lib/cfdi-vault" not in json.dumps(rows)


def test_failing_check_detail_never_carries_driver_exception_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``doctor()`` builds a failure detail from ``str(exc)``, which can embed a URL."""

    leaky = "connection to server at postgresql://user:hunter2@db:5432 failed"
    _install(monkeypatch, (DoctorCheck("database", False, leaky),))

    _exit_code, rows = subject.run_doctor({"DATABASE_URL": "postgresql://synthetic/db"})

    rendered = json.dumps(rows)
    assert "hunter2" not in rendered
    assert "postgresql://" not in rendered
    assert rows == [{"check": "database", "ok": False, "detail": "database check failed"}]


def test_service_construction_failure_reports_a_fixed_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(database_url: str | None = None, storage: Path | None = None) -> _FakeService:
        raise RuntimeError("could not connect to postgresql://user:hunter2@db:5432")

    monkeypatch.setattr(subject, "recovery_service", fail)

    exit_code, rows = subject.run_doctor({"DATABASE_URL": "postgresql://synthetic/db"})

    assert exit_code == 1
    assert rows == [{"check": "database", "ok": False, "detail": "database check failed"}]
    assert "hunter2" not in json.dumps(rows)


def test_storage_root_comes_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _service, calls = _install(monkeypatch, ALL_OK)
    env_storage = tmp_path / "env-storage-root"

    subject.run_doctor(
        {"DATABASE_URL": "postgresql://synthetic/db", "CFDI_STORAGE_ROOT": str(env_storage)},
    )

    assert calls == [("postgresql://synthetic/db", env_storage)]


def test_absent_storage_root_is_left_for_the_service_to_resolve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``recovery_service`` owns the ``CFDI_STORAGE_ROOT``/``storage`` fallback."""

    _service, calls = _install(monkeypatch, ALL_OK)

    subject.run_doctor({"DATABASE_URL": "postgresql://synthetic/db"})

    assert calls == [("postgresql://synthetic/db", None)]


def test_main_prints_one_json_line_per_check_and_returns_the_exit_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    _install(monkeypatch, ALL_OK)

    exit_code = subject.main(environment={"DATABASE_URL": "postgresql://synthetic/db"})

    assert exit_code == 0
    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert len(lines) == 4
    assert json.loads(lines[0]) == {
        "check": "database", "ok": True, "detail": "schema reachable",
    }
    assert json.loads(lines[3])["detail"] == "layout ensured"
