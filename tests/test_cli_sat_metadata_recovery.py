from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner

from cfdi_vault.adapters.cli import sat_recovery as subject
from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_metadata_recovery import PackageRecoveryStatus
from cfdi_vault.sat_metadata_submission import SubmissionStatus

NOW = datetime(2026, 6, 30, tzinfo=timezone.utc)
RECOVER_ARGS = ["metadata-recover-live", "--profile", "profile-synthetic", "--direction", "received",
                "--from", "2026-06-30", "--to", "2026-06-30", "--authorization", "permit-synthetic"]
def _app() -> typer.Typer:
    app = typer.Typer()
    app.command("metadata-recover-live")(subject.sat_metadata_recover_live)
    app.command("metadata-recovery-status")(subject.sat_metadata_recovery_status)
    return app
def _query() -> DownloadQuery:
    return DownloadQuery(
        tenant_id="tenant-synthetic",
        requester_rfc="XAXX010101000",
        direction=DownloadDirection.RECEIVED,
        request_type=RequestType.METADATA,
        period=DateTimePeriod(NOW, NOW.replace(hour=23, minute=59)),
    )
def _document(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "status": "verify_scheduled",
        "verifyAttempts": 0,
        "nextCheckAt": "2026-06-30T00:05:00+00:00",
        "recordCount": "not_reported",
        "packageCount": 0,
        "zipValidCount": 0,
        "txtCount": 0,
    }
    value.update(overrides)
    return value
def _patch_front(monkeypatch, tmp_path: Path, events: list[str]) -> SimpleNamespace:
    profile = SimpleNamespace(profile_id="profile-synthetic", storage_root=tmp_path / "external")
    monkeypatch.setattr(
        subject, "_build_profile_download_query_with_profile", lambda **_: (events.append("query") or _query(), profile)
    )
    monkeypatch.setattr(subject, "_checked_recovery_repo_root", lambda: events.append("guard") or tmp_path / "repo")
    monkeypatch.setattr(subject, "_validate_recovery_state_path", lambda *_: events.append("path"))
    monkeypatch.setattr(
        subject,
        "_authorize_metadata_recovery",
        lambda **_: events.append("permit") or SimpleNamespace(permit_id="permit-synthetic"),
    )
    monkeypatch.setattr(subject, "_new_recovery_storage", lambda _: events.append("storage") or object())
    monkeypatch.setattr(subject, "_new_recovery_adapter", lambda *_: events.append("adapter") or object())
    monkeypatch.setattr(subject, "_recovery_now", lambda: NOW)
    return profile
@pytest.mark.parametrize(("consumed", "expected"), [(False, "consume"), (True, "continue")])
def test_authorization_consumes_once_then_validates_read_only(monkeypatch, consumed: bool, expected: str) -> None:
    permit, calls = SimpleNamespace(consumed=consumed, permit_id="permit-synthetic"), []
    monkeypatch.setattr(subject, "load_live_execution_permit", lambda _: permit)
    monkeypatch.setattr(subject, "validate_and_consume_live_permit",
                        lambda *_a, **kw: calls.append(("consume", kw)) or permit)
    monkeypatch.setattr(subject, "validate_consumed_metadata_recovery_permit",
                        lambda *_a, **kw: calls.append(("continue", kw)) or permit)

    result = subject._authorize_metadata_recovery(authorization="permit-synthetic",
        profile="profile-synthetic", query=_query(), now=NOW, repo_root=Path("repo"))

    assert result is permit and calls[0][0] == expected
    assert calls[0][1]["date_from"] == calls[0][1]["date_to"] == "2026-06-30"


def test_recover_live_orders_gates_and_prints_only_aggregates(monkeypatch, tmp_path: Path) -> None:
    events: list[str] = []
    profile = _patch_front(monkeypatch, tmp_path, events)
    claim = SimpleNamespace(status=SubmissionStatus.ACCEPTED, recovery_ref="run-000000000000")
    record = SimpleNamespace(authorization_ref="permit-synthetic")
    monkeypatch.setattr(subject, "submit_metadata_recovery_once", lambda **_: events.append("submit") or claim)
    monkeypatch.setattr(subject, "load_metadata_recovery_state", lambda *_a, **_k: events.append("load") or record)
    monkeypatch.setattr(
        subject,
        "advance_metadata_recovery_once",
        lambda **_: events.append("advance") or SimpleNamespace(recovery=_document()),
    )

    result = CliRunner().invoke(_app(), RECOVER_ARGS)

    assert result.exit_code == 0, result.output
    assert events == ["query", "guard", "path", "permit", "storage", "adapter", "submit", "load", "advance"]
    assert "stage=waiting_verify" in result.output
    assert "status=verify_scheduled" in result.output
    assert "operation_attempts=0" in result.output
    assert "record_count=not_reported" in result.output
    for forbidden in (
        "profile-synthetic",
        "permit-synthetic",
        "tenant-synthetic",
        "XAXX010101000",
        str(profile.storage_root),
        "recovery_ref",
        "packages=",
        "artifacts=",
    ):
        assert forbidden not in result.output


def test_recover_live_rejects_authorization_rebinding_before_advance(monkeypatch, tmp_path: Path) -> None:
    events: list[str] = []
    _patch_front(monkeypatch, tmp_path, events)
    monkeypatch.setattr(
        subject,
        "submit_metadata_recovery_once",
        lambda **_: SimpleNamespace(status=SubmissionStatus.ACCEPTED, recovery_ref="run-000000000000"),
    )
    monkeypatch.setattr(
        subject, "load_metadata_recovery_state", lambda *_a, **_k: SimpleNamespace(authorization_ref="different-permit")
    )
    monkeypatch.setattr(
        subject, "advance_metadata_recovery_once", lambda **_: (_ for _ in ()).throw(AssertionError("must not advance"))
    )

    result = CliRunner().invoke(_app(), RECOVER_ARGS)

    assert result.exit_code == 1
    assert result.output == "error=authorization_mismatch\n"
    assert "different-permit" not in result.output


def test_recover_live_terminal_submission_never_advances(monkeypatch, tmp_path: Path) -> None:
    events: list[str] = []
    _patch_front(monkeypatch, tmp_path, events)
    monkeypatch.setattr(
        subject,
        "submit_metadata_recovery_once",
        lambda **_: SimpleNamespace(status=SubmissionStatus.SUBMIT_UNCERTAIN, recovery_ref=""),
    )
    monkeypatch.setattr(
        subject,
        "load_metadata_recovery_state",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not load")),
    )

    result = CliRunner().invoke(_app(), RECOVER_ARGS)

    assert result.exit_code == 1
    assert "stage=submission\nstatus=submit_uncertain\noperation_attempts=1" in result.output


def test_status_is_read_only_and_omits_private_and_structural_arrays(monkeypatch, tmp_path: Path) -> None:
    profile = SimpleNamespace(profile_id="profile-synthetic", storage_root=tmp_path / "external")
    packages = (
        SimpleNamespace(status=PackageRecoveryStatus.COMPLETED),
        SimpleNamespace(status=PackageRecoveryStatus.PENDING),
    )
    record = SimpleNamespace(
        recovery=SimpleNamespace(packages=packages),
        to_redacted_document=lambda: (
            _document(
                status="packages_ready",
                verifyAttempts=2,
                packageCount=2,
                zipValidCount=1,
                txtCount=1,
            )
            | {"packages": [{"private": "value"}], "artifacts": [{"headers": ["private"]}]}
        ),
    )
    monkeypatch.setattr(subject, "_load_download_profile", lambda _: profile)
    monkeypatch.setattr(subject, "_recovery_repo_root", lambda: tmp_path / "repo")
    monkeypatch.setattr(subject, "_validate_recovery_state_path", lambda *_: None)
    monkeypatch.setattr(subject, "load_metadata_recovery_state", lambda *_a, **_k: record)

    result = CliRunner().invoke(
        _app(), ["metadata-recovery-status", "--profile", profile.profile_id, "--recovery-ref", "run-000000000000"]
    )

    assert result.exit_code == 0, result.output
    assert "stage=downloading\nstatus=packages_ready\noperation_attempts=3" in result.output
    assert "package_count=2\nzip_valid_count=1\ntxt_extracted=1" in result.output
    for forbidden in (
        "profile-synthetic",
        "run-000000000000",
        "private",
        "headers",
        "packages=",
        "artifacts=",
        str(profile.storage_root),
    ):
        assert forbidden not in result.output


def test_failed_checkout_guard_precedes_path_permit_storage_and_network(monkeypatch) -> None:
    monkeypatch.setattr(
        subject,
        "_build_profile_download_query_with_profile",
        lambda **_: (_query(), SimpleNamespace(storage_root=Path("unused"))),
    )
    monkeypatch.setattr(
        subject,
        "_checked_recovery_repo_root",
        lambda: (_ for _ in ()).throw(subject._RecoveryCliError("checkout_not_clean")),
    )
    monkeypatch.setattr(
        subject, "_validate_recovery_state_path", lambda *_: (_ for _ in ()).throw(AssertionError("must not validate"))
    )

    result = CliRunner().invoke(_app(), RECOVER_ARGS)

    assert result.exit_code == 1
    assert result.output == "error=checkout_not_clean\n"
