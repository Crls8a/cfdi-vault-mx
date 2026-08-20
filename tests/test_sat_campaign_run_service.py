"""Host-only campaign-run consumer behaviour (ADR 0005)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pytest

from cfdi_vault.sat_campaign_run_service import (
    CampaignRunConfigError,
    CampaignRunReport,
    CampaignRunService,
    resolve_campaign_run_settings,
)

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)
COMMIT = "commit-consumer"
BASE_ENV = {
    "DATABASE_URL": "postgresql+psycopg://synthetic:synthetic@localhost/vault",
    "CFDI_VAULT_COMMIT_REF": COMMIT,
}


@dataclass
class _Run:
    run_ref: str = "run-synthetic"
    profile_ref: str = "profile-a"
    grant_ref: str = "grant-a"
    commit_ref: str = COMMIT


@dataclass
class _Repository:
    """Minimal stand-in for the durable campaign-run queue."""

    run: _Run | None = None
    campaign_ref: str | None = "campaign-a"
    abandoned: int = 0
    claims: list[str] = field(default_factory=list)
    running: list[str] = field(default_factory=list)
    results: list[dict[str, object]] = field(default_factory=list)
    claim_error: Exception | None = None
    reaper_error: Exception | None = None
    running_error: Exception | None = None

    def abandon_expired_campaign_runs(self, now: datetime) -> int:
        if self.reaper_error is not None:
            raise self.reaper_error
        return self.abandoned

    def claim_next_campaign_run(self, *, worker_ref: str, lease_seconds: int, now: datetime) -> _Run | None:
        if self.claim_error is not None:
            raise self.claim_error
        claimed, self.run = self.run, None
        if claimed is not None:
            self.claims.append(worker_ref)
        return claimed

    def campaign_ref_for_run(self, run_ref: str) -> str | None:
        return self.campaign_ref

    def mark_campaign_run_running(self, run_ref: str, *, lease_seconds: int, now: datetime) -> None:
        if self.running_error is not None:
            raise self.running_error
        self.running.append(run_ref)

    def record_campaign_run_result(self, run_ref: str, **values: object) -> None:
        self.results.append({"run_ref": run_ref, **values})


def _service(repository: _Repository, **overrides: object) -> CampaignRunService:
    options: dict[str, object] = {
        "commit_ref": COMMIT,
        "worker_ref": "worker-a",
        "lease_seconds": 900,
        "poll_seconds": 1.0,
        "clock": lambda: NOW,
        "sleep": lambda _seconds: None,
    }
    options.update(overrides)
    return CampaignRunService(repository, **options)  # type: ignore[arg-type]


def test_an_idle_pass_still_reaps_expired_leases() -> None:
    repository = _Repository(run=None, abandoned=2)
    report = _service(repository).run_once()

    assert report.status == "idle"
    assert report.abandoned == 2
    assert report.claimed == 0
    assert repository.results == []


def test_a_claimed_run_executes_the_shared_runner_and_records_its_aggregates() -> None:
    repository = _Repository(run=_Run())
    calls: list[tuple[str, str, str]] = []

    def runner(profile_ref: str, campaign_ref: str, grant_ref: str) -> dict[str, object]:
        calls.append((profile_ref, campaign_ref, grant_ref))
        return {
            "status": "processed", "contacted_count": 2, "submitted_count": 1, "package_count": 3,
        }

    report = _service(repository, runner=runner).run_once()

    assert calls == [("profile-a", "campaign-a", "grant-a")]
    assert repository.running == ["run-synthetic"]
    assert (report.status, report.claimed, report.succeeded, report.failed) == ("completed", 1, 1, 0)
    assert repository.results == [{
        "run_ref": "run-synthetic", "status": "succeeded", "result_code": "processed",
        "contacted_count": 2, "submitted_count": 1, "package_count": 3, "now": NOW,
    }]


def test_a_commit_ref_mismatch_is_recorded_as_failed_without_running_the_sequence() -> None:
    """The row was authorized against a different build; never execute it."""

    repository = _Repository(run=_Run(commit_ref="commit-other"))

    def runner(*_args: str) -> dict[str, object]:  # pragma: no cover - must not run
        raise AssertionError("a mismatched commit_ref must never reach SAT")

    report = _service(repository, runner=runner).run_once()

    assert repository.running == []
    assert (report.status, report.failed) == ("completed", 1)
    assert report.reason_code == "commit-ref-mismatch"
    assert repository.results == [{
        "run_ref": "run-synthetic", "status": "failed", "result_code": "commit-ref-mismatch",
        "contacted_count": 0, "submitted_count": 0, "package_count": 0, "now": NOW,
    }]


def test_a_runner_exception_never_escapes_to_the_broker_retry_machinery() -> None:
    """A live SAT run must never be re-delivered by generic queue infrastructure."""

    repository = _Repository(run=_Run())

    def runner(*_args: str) -> dict[str, object]:
        raise RuntimeError("SYNTHETIC-SECRET transport failure detail")

    report = _service(repository, runner=runner).run_once()

    assert (report.status, report.failed) == ("completed", 1)
    assert report.reason_code == "runner-unavailable"
    assert repository.results[0]["status"] == "failed"
    assert "SYNTHETIC-SECRET" not in repr(report)
    assert "SYNTHETIC-SECRET" not in str(repository.results[0])


def test_an_unrecognized_runner_status_is_closed_as_failed_rather_than_left_open() -> None:
    repository = _Repository(run=_Run())
    report = _service(repository, runner=lambda *_args: {"status": "something-new"}).run_once()

    assert report.reason_code == "runner-status-unknown"
    assert repository.results[0]["status"] == "failed"


@pytest.mark.parametrize(
    ("runner_status", "expected_status", "expected_code"),
    [
        ("processed", "succeeded", "processed"),
        ("no_due_operations", "succeeded", "no-due-operations"),
        ("busy", "failed", "campaign-busy"),
        ("error", "failed", "runner-error"),
    ],
)
def test_every_runner_status_maps_to_a_terminal_row(
    runner_status: str, expected_status: str, expected_code: str,
) -> None:
    repository = _Repository(run=_Run())
    _service(repository, runner=lambda *_args: {"status": runner_status}).run_once()

    assert repository.results[0]["status"] == expected_status
    assert repository.results[0]["result_code"] == expected_code


def test_a_missing_campaign_closes_the_run_instead_of_calling_the_runner() -> None:
    repository = _Repository(run=_Run(), campaign_ref=None)

    def runner(*_args: str) -> dict[str, object]:  # pragma: no cover - must not run
        raise AssertionError("an unresolvable campaign must never reach SAT")

    report = _service(repository, runner=runner).run_once()

    assert report.reason_code == "campaign-not-found"
    assert repository.results[0]["result_code"] == "campaign-not-found"


def test_a_failure_to_mark_the_run_running_closes_it_without_contacting_sat() -> None:
    repository = _Repository(run=_Run(), running_error=RuntimeError("db gone"))

    def runner(*_args: str) -> dict[str, object]:  # pragma: no cover - must not run
        raise AssertionError("state failure must not proceed to SAT")

    report = _service(repository, runner=runner).run_once()

    assert report.reason_code == "run-state-unavailable"
    assert repository.results[0]["status"] == "failed"


def test_a_reaper_or_claim_failure_reports_a_redacted_reason_and_claims_nothing() -> None:
    reaper_down = _Repository(run=_Run(), reaper_error=RuntimeError("db gone"))
    claim_down = _Repository(run=_Run(), claim_error=RuntimeError("db gone"))

    assert _service(reaper_down).run_once() == CampaignRunReport("error", reason_code="reaper_unavailable")
    assert reaper_down.claims == []

    claim_report = _service(claim_down).run_once()
    assert claim_report.status == "error"
    assert claim_report.reason_code == "claim_unavailable"


def test_wake_hints_are_drained_but_the_claim_still_comes_from_the_database() -> None:
    """The hint is an accelerator; the row is always re-read from PostgreSQL."""

    repository = _Repository(run=_Run())
    remaining = [1, 1, 0]
    report = _service(
        repository, runner=lambda *_args: {"status": "processed"},
        hint_consumer=lambda: remaining.pop(0),
    ).run_once()

    assert report.hints_drained == 2
    assert repository.claims == ["worker-a"]


def test_a_broker_outage_while_draining_hints_does_not_stop_the_pass() -> None:
    repository = _Repository(run=_Run())

    def failing_hint() -> int:
        raise RuntimeError("broker unreachable")

    report = _service(
        repository, runner=lambda *_args: {"status": "processed"}, hint_consumer=failing_hint,
    ).run_once()

    assert report.hints_drained == 0
    assert report.succeeded == 1


def test_run_forever_sleeps_only_when_there_was_nothing_to_do() -> None:
    repository = _Repository(run=_Run())
    passes: list[str] = []
    sleeps: list[float] = []

    service = _service(
        repository, runner=lambda *_args: {"status": "processed"},
        sleep=lambda seconds: sleeps.append(seconds),
    )
    service.run_forever(stop=lambda: len(passes) >= 2 or bool(passes.append("tick")))

    assert sleeps == [1.0]


def test_settings_require_a_postgres_url_and_a_commit_reference() -> None:
    with pytest.raises(CampaignRunConfigError) as missing_database:
        resolve_campaign_run_settings({"CFDI_VAULT_COMMIT_REF": COMMIT})
    assert missing_database.value.reason_code == "database_required"

    with pytest.raises(CampaignRunConfigError) as missing_commit:
        resolve_campaign_run_settings({"DATABASE_URL": BASE_ENV["DATABASE_URL"]})
    assert missing_commit.value.reason_code == "commit_ref_required"

    with pytest.raises(CampaignRunConfigError) as wrong_engine:
        resolve_campaign_run_settings({**BASE_ENV, "DATABASE_URL": "sqlite:///vault.db"})
    assert wrong_engine.value.reason_code == "postgresql_required"


def test_settings_are_disabled_by_default_and_never_expose_urls() -> None:
    settings = resolve_campaign_run_settings(BASE_ENV)

    assert settings.enabled is False
    assert settings.rabbitmq_url is None
    assert settings.lease_seconds == 900
    assert settings.poll_seconds == 5.0
    assert "postgresql" not in repr(settings)
    assert "synthetic" not in repr(settings)
    assert COMMIT not in repr(settings)


def test_settings_reject_out_of_range_bounded_values() -> None:
    for key, value, reason in (
        ("SAT_CAMPAIGN_RUN_LEASE_SECONDS", "30", "lease_seconds_invalid"),
        ("SAT_CAMPAIGN_RUN_POLL_SECONDS", "0", "poll_seconds_invalid"),
        ("SAT_CAMPAIGN_RUN_MAX_HINTS", "-1", "max_hints_invalid"),
        ("SAT_CAMPAIGN_RUN_WORKER_ENABLED", "maybe", "enabled_invalid"),
        ("RABBITMQ_URL", "http://localhost", "rabbitmq_invalid"),
    ):
        with pytest.raises(CampaignRunConfigError) as error:
            resolve_campaign_run_settings({**BASE_ENV, key: value})
        assert error.value.reason_code == reason


def test_a_configured_lease_and_broker_are_carried_into_the_settings() -> None:
    settings = resolve_campaign_run_settings({
        **BASE_ENV,
        "RABBITMQ_URL": "amqp://guest:guest@localhost:5672/",
        "SAT_CAMPAIGN_RUN_LEASE_SECONDS": "1200",
        "SAT_CAMPAIGN_RUN_WORKER_ENABLED": "1",
    })

    assert settings.enabled is True
    assert settings.lease_seconds == 1200
    assert settings.rabbitmq_url == "amqp://guest:guest@localhost:5672/"
    assert "guest" not in repr(settings)


def test_the_service_rejects_a_non_positive_lease_or_poll_interval() -> None:
    repository = _Repository()
    with pytest.raises(ValueError, match="lease_seconds"):
        _service(repository, lease_seconds=0)
    with pytest.raises(ValueError, match="poll_seconds"):
        _service(repository, poll_seconds=0)


def test_report_rejects_unknown_statuses_and_negative_counters() -> None:
    with pytest.raises(ValueError, match="unsupported campaign run status"):
        CampaignRunReport("running")
    with pytest.raises(ValueError, match="must be non-negative"):
        CampaignRunReport("idle", abandoned=-1)


def test_main_returns_zero_and_does_nothing_while_the_consumer_is_disabled(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from cfdi_vault.sat_campaign_run_service import main

    assert main(["--once"], environment=BASE_ENV) == 0
    assert '"status": "disabled"' in capsys.readouterr().out


def test_main_rejects_conflicting_modes_and_missing_configuration(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from cfdi_vault.sat_campaign_run_service import main

    assert main(["--once", "--loop"], environment=BASE_ENV) == 2
    assert '"reason_code": "mode_conflict"' in capsys.readouterr().out

    assert main(["--once"], environment={}) == 2
    assert '"reason_code": "database_required"' in capsys.readouterr().out


def test_the_default_runner_delegates_to_the_same_function_the_cli_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lane selection and SAT internals must never be reimplemented here."""

    import cfdi_vault.sat_campaign_db_cli as db_cli
    from cfdi_vault.sat_campaign_run_service import _default_runner

    captured: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        db_cli, "run_from_environment",
        lambda profile, campaign, grant: captured.append((profile, campaign, grant)) or {"status": "processed"},
    )

    assert _default_runner("profile-a", "campaign-a", "grant-a") == {"status": "processed"}
    assert captured == [("profile-a", "campaign-a", "grant-a")]


def test_the_service_never_reruns_a_row_after_it_records_a_terminal_result() -> None:
    """A second pass must find nothing; re-running needs a new human request."""

    repository = _Repository(run=_Run())
    service = _service(repository, runner=lambda *_args: {"status": "processed"})

    first = service.run_once()
    second = service.run_once()

    assert first.claimed == 1
    assert second.status == "idle"
    assert len(repository.results) == 1


def test_the_finished_timestamp_is_read_after_the_run_not_at_the_start_of_the_pass() -> None:
    """A live run takes minutes; ``finished_at`` must not be the pass start."""

    repository = _Repository(run=_Run())
    stamps: list[datetime] = []

    def clock() -> datetime:
        stamps.append(NOW + timedelta(seconds=len(stamps)))
        return stamps[-1]

    _service(repository, clock=clock, runner=lambda *_args: {"status": "processed"}).run_once()

    finish_stamp = repository.results[0]["now"]
    assert isinstance(finish_stamp, datetime)
    assert finish_stamp > stamps[0]
