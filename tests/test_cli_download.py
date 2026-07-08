from __future__ import annotations

import re
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from typer.testing import CliRunner

from cfdi_vault import setup as setup_flow
from cfdi_vault.adapters.cli import common as common_cli
from cfdi_vault.adapters.cli import download as download_cli
from cfdi_vault.adapters.cli import sat_auth as sat_auth_cli
from cfdi_vault.adapters.cli import sat_common as sat_common_cli
from cfdi_vault.adapters.cli import sat_metadata as sat_metadata_cli
from cfdi_vault.adapters.cli import sat_verify as sat_verify_cli
from cfdi_vault.cli import app
from cfdi_vault.domain import SatRequestState
from cfdi_vault.live_permit import LivePermitRequest, create_live_execution_permit, load_live_execution_permit
from cfdi_vault.sat_contract import SatDownloadResult, SatOutcomeAction, SatVerificationResult
from cfdi_vault.sat_live_request_state import (
    PACKAGE_READY,
    list_live_metadata_requests,
    persist_live_metadata_request,
    redact_package_ref,
    upsert_live_metadata_request,
)
from cfdi_vault.sat_auth_constants import (
    AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
    AUTH_ENVELOPE_VARIANT_SECURITY_ONLY,
    AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION,
)
from cfdi_vault.secrets import DummySecretProvider


def test_download_plan_prints_safe_plan_and_criteria_hash(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)

    result = CliRunner().invoke(
        app,
        [
            "download",
            "plan",
            "--profile",
            "dummy-profile",
            "--from",
            "2024-01-01",
            "--to",
            "2024-01-31",
            "--kind",
            "metadata",
            "--direction",
            "received",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "fake"
    assert lines["profile"] == "dummy-profile"
    assert lines["kind"] == "metadata"
    assert lines["direction"] == "received"
    assert lines["from"] == "2024-01-01T00:00:00+00:00"
    assert lines["to"] == "2024-01-31T23:59:59.999999+00:00"
    assert lines["will_submit"] == "false"
    assert re.fullmatch(r"[0-9a-f]{64}", lines["criteria_hash"])
    assert "request_id" not in lines
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_download_request_prints_synthetic_accepted_result(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)

    result = CliRunner().invoke(
        app,
        [
            "download",
            "request",
            "--profile",
            "dummy-profile",
            "--from",
            "2024-02-01",
            "--to",
            "2024-02-29",
            "--kind",
            "cfdi",
            "--direction",
            "issued",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "fake"
    assert lines["profile"] == "dummy-profile"
    assert lines["kind"] == "cfdi"
    assert lines["direction"] == "issued"
    assert lines["will_submit"] == "true"
    assert lines["request_id"] == f"SYN-REQ-{lines['criteria_hash'][:12].upper()}"
    assert lines["action"] == "accepted"
    assert lines["sat_code"] == "5000"
    assert lines["message"] == "Synthetic request accepted"
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_download_sync_cfdi_runs_fake_pipeline_without_sensitive_output(tmp_path: Path, reset_postgres_database: str) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_setup_profile(appdata_root)

    result = CliRunner().invoke(
        app,
        [
            "download",
            "sync",
            "--profile",
            "dummy-profile",
            "--from",
            "2024-01-01",
            "--to",
            "2024-01-31",
            "--kind",
            "cfdi",
            "--direction",
            "received",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "fake"
    assert lines["profile"] == "dummy-profile"
    assert lines["kind"] == "cfdi"
    assert lines["direction"] == "received"
    assert lines["will_submit"] == "true"
    assert re.fullmatch(r"[0-9a-f]{64}", lines["criteria_hash"])
    assert lines["job_id"]
    assert lines["request_id"] == f"FAKE-{lines['criteria_hash'][:16].upper()}"
    assert lines["status"] == "succeeded"
    assert lines["metadata_count"] == "2"
    assert len(list(paths.storage_root.glob("*/xml/2024/01/*.xml"))) == 2
    assert "PKG-" not in result.output
    assert ".zip" not in result.output
    assert ".xml" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_download_status_reads_persisted_fake_sync_aggregates_safely(tmp_path: Path, reset_postgres_database: str) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)
    runner = CliRunner()

    sync = runner.invoke(
        app,
        [
            "download",
            "sync",
            "--profile",
            "dummy-profile",
            "--from",
            "2024-01-01",
            "--to",
            "2024-01-31",
            "--kind",
            "cfdi",
            "--direction",
            "received",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )
    assert sync.exit_code == 0, sync.output
    sync_lines = _key_value_lines(sync.output)

    status = runner.invoke(
        app,
        ["download", "status", "--profile", "dummy-profile", "--job-id", sync_lines["job_id"]],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert status.exit_code == 0, status.output
    lines = _key_value_lines(status.output)
    assert lines["mode"] == "fake"
    assert lines["profile"] == "dummy-profile"
    assert lines["job_id"] == sync_lines["job_id"]
    assert lines["request_id"] == sync_lines["request_id"]
    assert lines["status"] == "succeeded"
    assert lines["sat_state"] == "finished"
    assert lines["kind"] == "cfdi"
    assert lines["direction"] == "received"
    assert lines["criteria_hash"] == sync_lines["criteria_hash"]
    assert lines["metadata_count"] == "2"
    assert lines["package_count"] == "1"
    assert lines["downloaded_package_count"] == "1"
    assert lines["xml_count"] == "2"
    _assert_no_download_status_leaks(status.output, appdata_root)


def test_download_status_missing_or_unknown_job_fails_safely(tmp_path: Path, reset_postgres_database: str) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_setup_profile(appdata_root)
    runner = CliRunner()

    missing_job = runner.invoke(
        app,
        ["download", "status", "--profile", "dummy-profile", "--job-id", "missing-job"],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert missing_job.exit_code == 1
    assert "error=status_not_found" in missing_job.output
    _assert_no_download_status_leaks(missing_job.output, appdata_root)

    sync = runner.invoke(
        app,
        [
            "download",
            "sync",
            "--profile",
            "dummy-profile",
            "--from",
            "2024-01-01",
            "--to",
            "2024-01-31",
            "--kind",
            "cfdi",
            "--direction",
            "received",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )
    assert sync.exit_code == 0, sync.output

    unknown_job = runner.invoke(
        app,
        ["download", "status", "--profile", "dummy-profile", "--job-id", "unknown-job"],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert unknown_job.exit_code == 1
    assert "error=status_not_found" in unknown_job.output
    _assert_no_download_status_leaks(unknown_job.output, appdata_root)


def test_download_sync_replay_same_criteria_returns_stable_result(tmp_path: Path, reset_postgres_database: str) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)
    args = [
        "download",
        "sync",
        "--profile",
        "dummy-profile",
        "--from",
        "2024-02-01",
        "--to",
        "2024-02-29",
        "--kind",
        "metadata",
        "--direction",
        "issued",
    ]
    runner = CliRunner()

    first = runner.invoke(app, args, env={"LOCALAPPDATA": str(appdata_root)})
    replay = runner.invoke(app, args, env={"LOCALAPPDATA": str(appdata_root)})

    assert first.exit_code == 0, first.output
    assert replay.exit_code == 0, replay.output
    first_lines = _key_value_lines(first.output)
    replay_lines = _key_value_lines(replay.output)
    assert replay_lines["criteria_hash"] == first_lines["criteria_hash"]
    assert replay_lines["job_id"] == first_lines["job_id"]
    assert replay_lines["request_id"] == first_lines["request_id"]
    assert replay_lines["status"] == first_lines["status"] == "succeeded"
    assert replay_lines["metadata_count"] == first_lines["metadata_count"] == "2"
    _assert_no_profile_secrets_or_paths(first.output, appdata_root)
    _assert_no_profile_secrets_or_paths(replay.output, appdata_root)


def test_download_rejects_invalid_direction_folio(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)

    result = CliRunner().invoke(
        app,
        [
            "download",
            "plan",
            "--profile",
            "dummy-profile",
            "--from",
            "2024-01-01",
            "--to",
            "2024-01-31",
            "--kind",
            "metadata",
            "--direction",
            "folio",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code != 0
    assert "direction must be received or issued" in result.output


def test_download_rejects_from_after_to(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)

    result = CliRunner().invoke(
        app,
        [
            "download",
            "plan",
            "--profile",
            "dummy-profile",
            "--from",
            "2024-02-01",
            "--to",
            "2024-01-31",
            "--kind",
            "metadata",
            "--direction",
            "received",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 1
    assert "error=invalid_date_range" in result.output
    assert "detail=--from must be before or equal to --to" in result.output


def test_download_missing_profile_fails_without_absolute_path_leak(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"

    result = CliRunner().invoke(
        app,
        [
            "download",
            "plan",
            "--profile",
            "missing-profile",
            "--from",
            "2024-01-01",
            "--to",
            "2024-01-31",
            "--kind",
            "metadata",
            "--direction",
            "received",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 1
    assert "profile=missing-profile" in result.output
    assert "error=profile_not_configured" in result.output
    assert str(appdata_root) not in result.output


def test_download_live_option_is_rejected(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)

    result = CliRunner().invoke(
        app,
        [
            "download",
            "request",
            "--profile",
            "dummy-profile",
            "--from",
            "2024-01-01",
            "--to",
            "2024-01-31",
            "--kind",
            "metadata",
            "--direction",
            "received",
            "--live",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 2
    assert "request_id=" not in result.output
    assert "mode=fake" not in result.output


def test_download_sync_live_option_is_rejected_without_running(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_setup_profile(appdata_root)

    result = CliRunner().invoke(
        app,
        [
            "download",
            "sync",
            "--profile",
            "dummy-profile",
            "--from",
            "2024-01-01",
            "--to",
            "2024-01-31",
            "--kind",
            "cfdi",
            "--direction",
            "received",
            "--live",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 2
    assert "job_id=" not in result.output
    assert "request_id=" not in result.output
    assert "mode=fake" not in result.output


@pytest.mark.parametrize(
    ("args", "env_overrides", "interactive", "checkout", "doctor_ok", "reason"),
    [
        ([], {}, True, (True, True), True, "missing-manual-real-sat-flag"),
        (["--manual-real-sat"], {"CFDI_VAULT_ALLOW_REAL_SAT": None}, True, (True, True), True, "missing-explicit-real-sat-env"),
        (
            ["--manual-real-sat"],
            {"CFDI_VAULT_ALLOW_REAL_CREDENTIALS": None},
            True,
            (True, True),
            True,
            "missing-explicit-real-credentials-env",
        ),
        (["--manual-real-sat"], {"CI": "true"}, True, (True, True), True, "ci-enabled"),
        (["--manual-real-sat"], {}, False, (True, True), True, "non-interactive-terminal"),
        (["--manual-real-sat", "--kind", "cfdi"], {}, True, (True, True), True, "metadata-only-required"),
        (["--manual-real-sat", "--to", "2024-01-02"], {}, True, (True, True), True, "range-too-wide"),
        (["--manual-real-sat"], {}, True, (False, True), True, "repo-dirty"),
        (["--manual-real-sat"], {}, True, (True, False), True, "scanner-not-passed"),
        (["--manual-real-sat"], {}, True, (True, True), False, "doctor-not-ok"),
    ],
)
def test_download_live_smoke_aborts_before_adapter_for_guard_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
    env_overrides: dict[str, str | None],
    interactive: bool,
    checkout: tuple[bool, bool],
    doctor_ok: bool,
    reason: str,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=checkout, interactive=interactive, doctor_ok=doctor_ok)
    calls: list[str] = []
    monkeypatch.setattr(download_cli, "_run_live_metadata_smoke", lambda profile_id, query: calls.append(profile_id))

    result = CliRunner().invoke(
        app,
        _live_smoke_args(args),
        env=_live_smoke_env(appdata_root, env_overrides),
        input=f"{common_cli.LIVE_SMOKE_CONFIRMATION}\n",
    )

    assert result.exit_code == 1
    assert "error=live_sat_guard_denied" in result.output
    assert f"reason={reason}" in result.output
    assert calls == []
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_download_live_smoke_fake_adapter_happy_path_is_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=True, doctor_ok=True)
    monkeypatch.setattr(
        download_cli,
        "_run_live_metadata_smoke",
        lambda profile_id, query: common_cli.LiveSmokeCliResult(
            result="synthetic-ok",
            auth="attempted",
            request="metadata-submitted",
            verification="skipped",
        ),
    )

    result = CliRunner().invoke(
        app,
        _live_smoke_args(["--manual-real-sat"]),
        env=_live_smoke_env(appdata_root, {}),
        input=f"{common_cli.LIVE_SMOKE_CONFIRMATION}\n",
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "live-smoke"
    assert lines["profile"] == "dummy-profile"
    assert lines["kind"] == "metadata"
    assert lines["direction"] == "received"
    assert lines["will_submit"] == "false"
    assert lines["result"] == "synthetic-ok"
    assert lines["auth"] == "attempted"
    assert lines["request"] == "metadata-submitted"
    assert lines["xml_downloaded"] == "no"
    assert lines["zip_downloaded"] == "no"
    assert "request_id=" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_download_live_smoke_permit_replaces_interactive_prompt_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=False, doctor_ok=True)
    permit = create_live_execution_permit(
        LivePermitRequest(
            scope="metadata_live_smoke",
            profile_id="dummy-profile",
            kind="metadata",
            direction="received",
            date_from="2024-01-01",
            date_to="2024-01-01",
            reason="Carlos authorized metadata-only live smoke",
        ),
        env={"LOCALAPPDATA": str(appdata_root)},
    )
    seen: dict[str, object] = {}

    def fake_live_smoke(profile_id: str, query: object, *, live_permit_verified: bool = False) -> common_cli.LiveSmokeCliResult:
        seen["profile_id"] = profile_id
        seen["live_permit_verified"] = live_permit_verified
        return common_cli.LiveSmokeCliResult(
            result="synthetic-ok",
            auth="attempted",
            request="metadata-submitted",
            verification="skipped",
        )

    monkeypatch.setattr(download_cli, "_run_live_metadata_smoke", fake_live_smoke)

    result = CliRunner().invoke(
        app,
        _live_smoke_args(["--permit", permit.permit_id]),
        env=_live_smoke_env(
            appdata_root,
            {
                "CFDI_VAULT_ALLOW_REAL_SAT": None,
                "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": None,
            },
        ),
    )

    assert result.exit_code == 0, result.output
    assert seen["profile_id"] == "dummy-profile"
    assert seen["live_permit_verified"] is True
    assert "Type \"SAT REAL METADATA SMOKE\"" not in result.output
    assert "xml_downloaded=no" in result.output
    assert "zip_downloaded=no" in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_metadata_request_smoke_is_request_only_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=True, doctor_ok=True)
    seen: dict[str, object] = {}

    def fake_request_smoke(
        profile_id: str,
        query: object,
        *,
        live_permit_verified: bool = False,
        permit_ref: str | None = None,
    ) -> common_cli.LiveSmokeCliResult:
        seen["profile_id"] = profile_id
        seen["live_permit_verified"] = live_permit_verified
        seen["permit_ref"] = permit_ref
        seen["direction"] = getattr(query, "direction").value
        return common_cli.LiveSmokeCliResult(
            result="metadata-request-submitted",
            auth="authenticated",
            request="accepted",
            verification="not_run",
            operation="SolicitaDescargaRecibidos",
            id_solicitud_redacted="SYN-...-003",
            request_body_bytes_len=2048,
            envelope_sha256="a" * 64,
            signed_reference_count=1,
        )

    monkeypatch.setattr(sat_metadata_cli, "_run_live_metadata_request_smoke", fake_request_smoke)

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "metadata-request-smoke",
            "--profile",
            "dummy-profile",
            "--from",
            "2024-01-01",
            "--to",
            "2024-01-01",
            "--direction",
            "received",
            "--manual-real-sat",
        ],
        env=_live_smoke_env(appdata_root, {}),
        input=f"{common_cli.LIVE_SMOKE_CONFIRMATION}\n",
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert seen == {"profile_id": "dummy-profile", "live_permit_verified": False, "permit_ref": None, "direction": "received"}
    assert lines["mode"] == "live-smoke"
    assert lines["operation"] == "SolicitaDescargaRecibidos"
    assert lines["id_solicitud_redacted"] == "SYN-...-003"
    assert lines["verification"] == "not_run"
    assert lines["package_downloaded"] == "no"
    assert "request_id=" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_live_metadata_request_smoke_persists_accepted_id_without_printing_full_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    full_request_id = "648a0000-1111-2222-3333-444444447b27"

    class FakeAdapter:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def metadata_request_smoke(self, _query: object, *, max_range_days: int = 1) -> SimpleNamespace:
            assert max_range_days == 1
            return SimpleNamespace(
                result="metadata-request-submitted",
                auth="authenticated",
                request="accepted",
                verification="not_run",
                operation="SolicitaDescargaRecibidos",
                id_solicitud=full_request_id,
                id_solicitud_redacted="648a...7b27",
                sat_code="5000",
                sat_message="Accepted",
                package_count=0,
            )

    monkeypatch.setenv("LOCALAPPDATA", str(appdata_root))
    monkeypatch.setattr(sat_common_cli, "SatLiveMetadataSmokeAdapter", FakeAdapter)

    result = sat_common_cli._run_live_metadata_request_smoke(
        "dummy-profile",
        _metadata_query(),
        live_permit_verified=False,
        permit_ref="permit-local-id",
    )

    records = list_live_metadata_requests(paths.storage_root)
    assert len(records) == 1
    assert records[0].id_solicitud == full_request_id
    assert records[0].id_solicitud_redacted == "648a...7b27"
    assert records[0].permit_id_hash
    assert result.request_ref == records[0].request_ref
    assert result.id_solicitud_redacted == "648a...7b27"
    assert full_request_id not in repr(result)


def test_live_permit_create_prints_backfill_submit_max_range(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"

    result = CliRunner().invoke(
        app,
        [
            "live",
            "permit",
            "create",
            "--scope",
            "metadata_backfill_submit",
            "--profile",
            "dummy-profile",
            "--kind",
            "metadata",
            "--direction",
            "received",
            "--from",
            "2026-01-01",
            "--to",
            "2026-01-07",
            "--expires-minutes",
            "15",
            "--reason",
            "Carlos authorized synthetic backfill submit test",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["scope"] == "metadata_backfill_submit"
    assert lines["max_range_days"] == "7"


def test_sat_metadata_request_state_lists_pending_refs_redacted(
    tmp_path: Path,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    record = persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="dummy-profile",
        query=_metadata_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud="648a0000-1111-2222-3333-444444447b27",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat metadata-request-smoke",
        permit_ref=None,
    )

    result = CliRunner().invoke(
        app,
        ["sat", "metadata-request-state", "--profile", "dummy-profile"],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "metadata-request-state"
    assert lines["pending_count"] == "1"
    assert record.request_ref in result.output
    assert "648a...7b27" in result.output
    assert "648a0000-1111-2222-3333-444444447b27" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_verify_due_dry_run_lists_due_refs_without_verifying(
    tmp_path: Path,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    record = persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="dummy-profile",
        query=_metadata_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud="SYNTHETIC-SCHEDULER-REQUEST-0001",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat metadata-request-smoke",
        permit_ref=None,
        now=datetime.now(timezone.utc) - timedelta(minutes=5),
    )

    result = CliRunner().invoke(
        app,
        ["sat", "verify-due", "--profile", "dummy-profile", "--dry-run"],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "verify-due"
    assert lines["dry_run"] == "true"
    assert lines["due_count"] == "1"
    assert lines["processed_count"] == "0"
    assert lines["sat_real_execution"] == "no"
    assert lines["package_downloaded"] == "no"
    assert record.request_ref in result.output
    stored = list_live_metadata_requests(paths.storage_root)[0]
    assert stored.attempt_count == 0
    assert "SYNTHETIC-SCHEDULER-REQUEST-0001" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_verify_due_one_shot_updates_next_check_and_exits(
    tmp_path: Path,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="dummy-profile",
        query=_metadata_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud="SYNTHETIC-SCHEDULER-REQUEST-0001",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat metadata-request-smoke",
        permit_ref=None,
        now=datetime.now(timezone.utc) - timedelta(minutes=5),
    )

    result = CliRunner().invoke(
        app,
        ["sat", "verify-due", "--profile", "dummy-profile", "--limit", "1"],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["dry_run"] == "false"
    assert lines["processed_count"] == "1"
    assert lines["package_downloaded"] == "no"
    assert lines["sleep_used"] == "no"
    assert lines["loop_used"] == "no"
    stored = list_live_metadata_requests(paths.storage_root)[0]
    assert stored.status == "VERIFY_IN_PROGRESS_SAT"
    assert stored.attempt_count == 1
    assert stored.next_check_at
    assert "SYNTHETIC-SCHEDULER-REQUEST-0001" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_verify_due_live_requires_request_ref_before_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    calls: list[str] = []
    monkeypatch.setattr(sat_verify_cli, "_validate_live_smoke_guard", lambda **_kwargs: calls.append("guard"))

    result = CliRunner().invoke(
        app,
        ["sat", "verify-due", "--profile", "dummy-profile", "--manual-real-sat", "--permit", "permit-local-id"],
        env=_live_smoke_env(appdata_root, {}),
    )

    assert result.exit_code == 1
    assert "error=live_scheduler_verify_denied" in result.output
    assert "reason=request-ref-required-for-live" in result.output
    assert calls == []


def test_sat_verify_due_live_requires_limit_one_before_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    record = persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="dummy-profile",
        query=_metadata_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud="SYNTHETIC-SCHEDULER-REQUEST-0001",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat metadata-request-smoke",
        permit_ref=None,
        now=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    calls: list[str] = []
    monkeypatch.setattr(sat_verify_cli, "_validate_live_smoke_guard", lambda **_kwargs: calls.append("guard"))

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "verify-due",
            "--profile",
            "dummy-profile",
            "--request-ref",
            record.request_ref,
            "--limit",
            "2",
            "--manual-real-sat",
            "--permit",
            "permit-local-id",
        ],
        env=_live_smoke_env(appdata_root, {}),
    )

    assert result.exit_code == 1
    assert "reason=limit-one-required" in result.output
    assert calls == []


def test_sat_verify_due_live_requires_permit_before_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    record = persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="dummy-profile",
        query=_metadata_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud="SYNTHETIC-SCHEDULER-REQUEST-0001",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat metadata-request-smoke",
        permit_ref=None,
        now=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    calls: list[str] = []
    monkeypatch.setattr(sat_verify_cli, "_validate_live_smoke_guard", lambda **_kwargs: calls.append("guard"))

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "verify-due",
            "--profile",
            "dummy-profile",
            "--request-ref",
            record.request_ref,
            "--limit",
            "1",
            "--manual-real-sat",
        ],
        env=_live_smoke_env(appdata_root, {}),
    )

    assert result.exit_code == 1
    assert "reason=permit-required-for-live" in result.output
    assert calls == []


def test_sat_verify_due_live_permit_runs_scheduler_once_without_download(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    full_request_id = "648a0000-1111-2222-3333-444444447b27"
    query = _weekly_metadata_query()
    record = persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="dummy-profile",
        query=query,
        operation="SolicitaDescargaRecibidos",
        id_solicitud=full_request_id,
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat metadata-request-smoke",
        permit_ref=None,
        now=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=False, doctor_ok=True)
    permit = create_live_execution_permit(
        LivePermitRequest(
            scope="metadata_live_smoke",
            profile_id="dummy-profile",
            kind="metadata",
            direction="received",
            date_from="2024-01-01",
            date_to="2024-01-07",
            reason="Carlos authorized scheduler verify-due live smoke",
        ),
        env={"LOCALAPPDATA": str(appdata_root)},
    )
    seen: dict[str, object] = {}

    class FakeLiveVerifier:
        def __init__(self, profile_id: str, *, live_permit_verified: bool = False) -> None:
            seen["profile_id"] = profile_id
            seen["live_permit_verified"] = live_permit_verified
            self.download_calls: list[str] = []

        def verify_request(self, request_id: str) -> SatVerificationResult:
            seen["request_id"] = request_id
            return SatVerificationResult(
                request_id=request_id,
                state=SatRequestState.FINISHED,
                sat_code="5000",
                message="Synthetic finished",
                action=SatOutcomeAction.FINISHED,
                package_ids=("SYNTHETIC-PACKAGE-0001", "SYNTHETIC-PACKAGE-0002"),
            )

        def download_package(self, package_id: str) -> bytes:
            seen["download_called"] = package_id
            return b""

    monkeypatch.setattr(sat_verify_cli, "_live_verify_due_verifier", FakeLiveVerifier)

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "verify-due",
            "--profile",
            "dummy-profile",
            "--request-ref",
            record.request_ref,
            "--limit",
            "1",
            "--manual-real-sat",
            "--permit",
            permit.permit_id,
        ],
        env=_live_smoke_env(
            appdata_root,
            {
                "CFDI_VAULT_ALLOW_REAL_SAT": None,
                "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": None,
            },
        ),
    )

    assert result.exit_code == 0, result.output
    assert seen == {
        "profile_id": "dummy-profile",
        "live_permit_verified": True,
        "request_id": full_request_id,
    }
    lines = _key_value_lines(result.output)
    assert lines["dry_run"] == "false"
    assert lines["selected_count"] == "1"
    assert lines["processed_count"] == "1"
    assert lines["sat_real_execution"] == "adapter_enabled"
    assert lines["package_downloaded"] == "no"
    assert lines["zip_downloaded"] == "no"
    assert lines["xml_downloaded"] == "no"
    assert lines["verify_item"].startswith(f"request_ref={record.request_ref}|status=PACKAGE_READY")
    assert "package_count=2" in lines["verify_item"]
    assert record.request_ref in result.output
    assert full_request_id not in result.output
    assert "SYNTHETIC-PACKAGE-0001" not in result.output
    assert "SYNTHETIC-PACKAGE-0002" not in result.output
    stored = list_live_metadata_requests(paths.storage_root)[0]
    assert stored.status == "PACKAGE_READY"
    assert stored.attempt_count == 1
    assert stored.numero_cfdis == 2
    assert stored.package_ids == ("SYNTHETIC-PACKAGE-0001", "SYNTHETIC-PACKAGE-0002")
    assert len(stored.package_refs_redacted) == 2
    assert all(item.startswith("pkg-") for item in stored.package_refs_redacted)
    assert "download_called" not in seen
    assert load_live_execution_permit(permit.permit_id, env={"LOCALAPPDATA": str(appdata_root)}).consumed is True
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_package_download_smoke_downloads_one_metadata_txt_without_printing_package_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    package_id = "SYNTHETIC-PACKAGE-SECRET-0001"
    package_ref = redact_package_ref(package_id)
    record = persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="dummy-profile",
        query=_weekly_metadata_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud="648a0000-1111-2222-3333-444444447b27",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat backfill submit",
        permit_ref=None,
        now=datetime.now(timezone.utc) - timedelta(minutes=10),
    )
    ready = replace(
        record,
        status=PACKAGE_READY,
        package_ids=(package_id,),
        package_refs_redacted=(package_ref,),
        numero_cfdis=1,
    )
    upsert_live_metadata_request(storage_root=paths.storage_root, record=ready)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=False, doctor_ok=True)
    permit = create_live_execution_permit(
        LivePermitRequest(
            scope="package_download_smoke",
            profile_id="dummy-profile",
            kind="metadata",
            direction="received",
            date_from="2024-01-01",
            date_to="2024-01-07",
            reason="Carlos authorized package download smoke test",
        ),
        env={"LOCALAPPDATA": str(appdata_root)},
    )
    seen: dict[str, object] = {}

    class FakeDownloader:
        def __init__(self, profile_id: str, *, live_permit_verified: bool = False) -> None:
            seen["profile_id"] = profile_id
            seen["live_permit_verified"] = live_permit_verified

        def download_package(self, requested_package_id: str) -> SatDownloadResult:
            seen["package_id"] = requested_package_id
            return SatDownloadResult(
                package_id=requested_package_id,
                sat_code="5000",
                message="Downloaded",
                action=SatOutcomeAction.FINISHED,
                content=_metadata_txt_zip(),
            )

    monkeypatch.setattr(sat_verify_cli, "_live_package_downloader", FakeDownloader)

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "package-download-smoke",
            "--profile",
            "dummy-profile",
            "--request-ref",
            ready.request_ref,
            "--package-ref",
            package_ref,
            "--manual-real-sat",
            "--permit",
            permit.permit_id,
        ],
        env=_live_smoke_env(
            appdata_root,
            {
                "CFDI_VAULT_ALLOW_REAL_SAT": None,
                "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": None,
            },
        ),
    )

    assert result.exit_code == 0, result.output
    assert seen == {"profile_id": "dummy-profile", "live_permit_verified": True, "package_id": package_id}
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "package-download-smoke"
    assert lines["request_ref"] == ready.request_ref
    assert lines["package_ref"] == package_ref
    assert lines["package_downloaded"] == "yes"
    assert lines["zip_valid"] == "true"
    assert lines["txt_files"] == "1"
    assert lines["xml_files"] == "0"
    assert lines["metadata_accepted_count"] == "1"
    assert lines["status_after"] == "PACKAGE_DOWNLOADED"
    assert package_id not in result.output
    assert "648a0000-1111-2222-3333-444444447b27" not in result.output
    assert str(appdata_root) not in result.output
    stored = list_live_metadata_requests(paths.storage_root)[0]
    assert stored.status == "PACKAGE_DOWNLOADED"
    assert load_live_execution_permit(permit.permit_id, env={"LOCALAPPDATA": str(appdata_root)}).consumed is True


def test_download_status_without_job_id_prints_scheduler_aggregates(
    tmp_path: Path,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="dummy-profile",
        query=_metadata_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud="SYNTHETIC-SCHEDULER-REQUEST-0001",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat metadata-request-smoke",
        permit_ref=None,
        now=datetime.now(timezone.utc) - timedelta(minutes=5),
    )

    result = CliRunner().invoke(
        app,
        ["download", "status", "--profile", "dummy-profile"],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "metadata-verify-scheduler"
    assert lines["pending_verify_count"] == "1"
    assert lines["due_verify_count"] == "1"
    assert lines["package_ready_count"] == "0"
    assert lines["redacted"] == "true"
    assert "SYNTHETIC-SCHEDULER-REQUEST-0001" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_metadata_verify_smoke_resolves_request_ref_without_new_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    full_request_id = "648a0000-1111-2222-3333-444444447b27"
    record = persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="dummy-profile",
        query=_metadata_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud=full_request_id,
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat metadata-request-smoke",
        permit_ref=None,
    )
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=True, doctor_ok=True)
    seen: dict[str, str] = {}

    def fake_verify(profile_id: str, request_id: str, *, live_permit_verified: bool = False) -> common_cli.LiveSmokeCliResult:
        seen["profile_id"] = profile_id
        seen["request_id"] = request_id
        seen["live_permit_verified"] = str(live_permit_verified)
        return common_cli.LiveSmokeCliResult(
            result="metadata-verify-ok",
            auth="authenticated",
            request="not_run",
            verification="in_progress",
            operation="VerificaSolicitudDescarga",
            id_solicitud_redacted="648a...7b27",
            sat_state="in_process",
            package_count=0,
        )

    monkeypatch.setattr(sat_verify_cli, "_run_live_metadata_verify_smoke", fake_verify)

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "metadata-verify-smoke",
            "--profile",
            "dummy-profile",
            "--request-ref",
            record.request_ref,
            "--manual-real-sat",
        ],
        env=_live_smoke_env(appdata_root, {}),
        input=f"{common_cli.LIVE_SMOKE_CONFIRMATION}\n",
    )

    assert result.exit_code == 0, result.output
    assert seen == {"profile_id": "dummy-profile", "request_id": full_request_id, "live_permit_verified": "False"}
    lines = _key_value_lines(result.output)
    assert lines["request"] == "not_run"
    assert lines["verification"] == "in_progress"
    assert lines["package_count"] == "0"
    assert "648a...7b27" in result.output
    assert full_request_id not in result.output


def test_sat_metadata_verify_smoke_missing_request_ref_aborts_before_live_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    calls: list[str] = []
    monkeypatch.setattr(sat_verify_cli, "_validate_live_smoke_guard", lambda **_kwargs: calls.append("guard"))
    monkeypatch.setattr(sat_verify_cli, "_run_live_metadata_verify_smoke", lambda *_args, **_kwargs: calls.append("verify"))

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "metadata-verify-smoke",
            "--profile",
            "dummy-profile",
            "--request-ref",
            "req-missing",
            "--manual-real-sat",
        ],
        env=_live_smoke_env(appdata_root, {}),
    )

    assert result.exit_code == 1
    assert "error=request_state_not_found" in result.output
    assert "reason=request-state-not-found" in result.output
    assert calls == []


def test_sat_metadata_verify_smoke_profile_mismatch_aborts_before_live_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_ready_setup_profile(appdata_root)
    record = persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="other-profile",
        query=_metadata_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud="648a0000-1111-2222-3333-444444447b27",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat metadata-request-smoke",
        permit_ref=None,
    )
    calls: list[str] = []
    monkeypatch.setattr(sat_verify_cli, "_validate_live_smoke_guard", lambda **_kwargs: calls.append("guard"))
    monkeypatch.setattr(sat_verify_cli, "_run_live_metadata_verify_smoke", lambda *_args, **_kwargs: calls.append("verify"))

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "metadata-verify-smoke",
            "--profile",
            "dummy-profile",
            "--request-ref",
            record.request_ref,
            "--manual-real-sat",
        ],
        env=_live_smoke_env(appdata_root, {}),
    )

    assert result.exit_code == 1
    assert "error=request_state_profile_mismatch" in result.output
    assert "648a0000-1111-2222-3333-444444447b27" not in result.output
    assert calls == []


def test_live_smoke_rejects_range_shorter_than_two_seconds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=True, doctor_ok=True)
    calls: list[str] = []
    monkeypatch.setattr(sat_metadata_cli, "_run_live_metadata_request_smoke", lambda profile_id, query, **_kwargs: calls.append(profile_id))

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "metadata-request-smoke",
            "--profile",
            "dummy-profile",
            "--from",
            "2024-01-01T00:00:00",
            "--to",
            "2024-01-01T00:00:01",
            "--direction",
            "received",
            "--manual-real-sat",
        ],
        env=_live_smoke_env(appdata_root, {}),
        input=f"{common_cli.LIVE_SMOKE_CONFIRMATION}\n",
    )

    assert result.exit_code == 1
    assert "error=live_sat_guard_denied" in result.output
    assert "reason=range-too-wide" in result.output
    assert calls == []


def test_download_live_smoke_adapter_failure_prints_redacted_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=True, doctor_ok=True)

    def fail_live_smoke(_profile_id: str, _query: object) -> None:
        raise common_cli.SatLiveSmokeError(
            "raw adapter detail must stay hidden",
            stage="auth_transport",
            error_kind="http_status_error",
            safe_hint="check SOAPAction, content-type, logical endpoint, TLS, and SAT service availability",
            endpoint="auth",
            http_status=500,
            payload_size=123,
            envelope_sha256="a" * 64,
            exception_class="SSLError",
            transport_layer="tls",
            duration_ms=7,
            correlation_id="diag-synthetic",
            request_body_bytes_len=2048,
            soap_action='"http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica"',
            content_type="text/xml; charset=utf-8",
            timestamp_window_seconds=300,
            has_ws_security=True,
            has_bst=True,
            cert_der_bytes_len=700,
            signature_method="http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            digest_method="http://www.w3.org/2000/09/xmldsig#sha1",
            signed_reference_count=1,
            signed_reference_targets_exist=True,
            has_header_action=True,
            header_action_value_ok=True,
            header_action_must_understand=True,
            header_action_order="action_before_security",
            security_must_understand=True,
        )

    monkeypatch.setattr(download_cli, "_run_live_metadata_smoke", fail_live_smoke)

    result = CliRunner().invoke(
        app,
        _live_smoke_args(["--manual-real-sat"]),
        env=_live_smoke_env(appdata_root, {}),
        input=f"{common_cli.LIVE_SMOKE_CONFIRMATION}\n",
    )

    assert result.exit_code == 1
    lines = _key_value_lines(result.output)
    assert lines["error"] == "live_adapter_failed"
    assert lines["failed_stage"] == "auth_transport"
    assert lines["error_kind"] == "http_status_error"
    assert lines["endpoint"] == "auth"
    assert lines["http_status"] == "500"
    assert lines["payload_size"] == "123"
    assert lines["exception_class"] == "SSLError"
    assert lines["transport_layer"] == "tls"
    assert lines["correlation_id"] == "diag-synthetic"
    assert lines["request_body_bytes_len"] == "2048"
    assert lines["soap_action"] == '"http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica"'
    assert lines["content_type"] == "text/xml; charset=utf-8"
    assert lines["timestamp_window_seconds"] == "300"
    assert lines["has_ws_security"] == "yes"
    assert lines["has_binary_security_token"] == "yes"
    assert lines["cert_der_bytes_len"] == "700"
    assert lines["signature_method"] == "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    assert lines["digest_method"] == "http://www.w3.org/2000/09/xmldsig#sha1"
    assert lines["signed_reference_count"] == "1"
    assert lines["signed_reference_targets_exist"] == "yes"
    assert lines["has_header_action"] == "yes"
    assert lines["header_action_value_ok"] == "yes"
    assert lines["header_action_must_understand"] == "yes"
    assert lines["header_action_order"] == "action_before_security"
    assert lines["security_must_understand"] == "yes"
    assert "raw adapter detail" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_diagnose_live_fake_adapter_happy_path_is_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=True, doctor_ok=True)
    monkeypatch.setattr(
        sat_metadata_cli,
        "_run_live_diagnose",
        lambda profile_id, query: common_cli.LiveSmokeCliResult(
            result="synthetic-diagnostic-ok",
            auth="authenticated",
            request="accepted",
            verification="in_progress",
        ),
    )

    result = CliRunner().invoke(
        app,
        _diagnose_live_args(["--manual-real-sat"]),
        env=_live_smoke_env(appdata_root, {}),
        input=f"{common_cli.LIVE_SMOKE_CONFIRMATION}\n",
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "diagnose-live"
    assert lines["diagnostic_status"] == "ok"
    assert lines["result"] == "synthetic-diagnostic-ok"
    assert "preflight:ok" in lines["stages"]
    assert "package_download:skipped" in lines["stages"]
    assert lines["xml_downloaded"] == "no"
    assert lines["package_downloaded"] == "no"
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_diagnose_live_adapter_failure_prints_stage_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=True, doctor_ok=True)

    def fail_diagnose(_profile_id: str, _query: object) -> None:
        raise common_cli.SatLiveSmokeError(
            "raw diagnostic detail must stay hidden",
            stage="metadata_request_transport",
            error_kind="transport_timeout",
            safe_hint="check SOAPAction, content-type, logical endpoint, TLS, and SAT service availability",
            endpoint="metadata_request",
            duration_ms=9,
            correlation_id="diag-timeout",
        )

    monkeypatch.setattr(sat_metadata_cli, "_run_live_diagnose", fail_diagnose)

    result = CliRunner().invoke(
        app,
        _diagnose_live_args(["--manual-real-sat"]),
        env=_live_smoke_env(appdata_root, {}),
        input=f"{common_cli.LIVE_SMOKE_CONFIRMATION}\n",
    )

    assert result.exit_code == 1
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "diagnose-live"
    assert lines["diagnostic_status"] == "failed"
    assert "metadata_request_transport:failed" in lines["stages"]
    assert lines["failed_stage"] == "metadata_request_transport"
    assert lines["error_kind"] == "transport_timeout"
    assert lines["endpoint"] == "metadata_request"
    assert lines["correlation_id"] == "diag-timeout"
    assert "raw diagnostic detail" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_diagnose_live_aborts_before_adapter_without_manual_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=True, doctor_ok=True)
    calls: list[str] = []
    monkeypatch.setattr(sat_metadata_cli, "_run_live_diagnose", lambda profile_id, query: calls.append(profile_id))

    result = CliRunner().invoke(app, _diagnose_live_args([]), env=_live_smoke_env(appdata_root, {}))

    assert result.exit_code == 1
    assert "error=live_sat_guard_denied" in result.output
    assert "reason=missing-manual-real-sat-flag" in result.output
    assert calls == []
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_auth_smoke_requires_same_manual_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=True, doctor_ok=True)
    seen: dict[str, object] = {}

    def fake_auth_smoke(
        profile_id: str,
        *,
        live_permit_verified: bool = False,
        auth_envelope_variant: str = AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
        wcf_action_header_enabled: bool = True,
    ) -> common_cli.LiveSmokeCliResult:
        seen["profile_id"] = profile_id
        seen["live_permit_verified"] = live_permit_verified
        seen["auth_envelope_variant"] = auth_envelope_variant
        seen["wcf_action_header_enabled"] = wcf_action_header_enabled
        return common_cli.LiveSmokeCliResult(result="synthetic-auth-ok", auth="attempted")

    monkeypatch.setattr(sat_auth_cli, "_run_live_auth_smoke", fake_auth_smoke)

    result = CliRunner().invoke(
        app,
        ["sat", "auth-smoke", "--profile", "dummy-profile", "--manual-real-sat"],
        env=_live_smoke_env(appdata_root, {}),
        input=f"{common_cli.LIVE_SMOKE_CONFIRMATION}\n",
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "live-smoke"
    assert lines["kind"] == "auth"
    assert lines["result"] == "synthetic-auth-ok"
    assert seen == {
        "profile_id": "dummy-profile",
        "live_permit_verified": False,
        "auth_envelope_variant": AUTH_ENVELOPE_VARIANT_SECURITY_ONLY,
        "wcf_action_header_enabled": False,
    }
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_auth_smoke_permit_replaces_interactive_prompt_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=False, doctor_ok=True)
    permit = create_live_execution_permit(
        LivePermitRequest(
            scope="auth_live_smoke",
            profile_id="dummy-profile",
            kind="metadata",
            direction="received",
            date_from="2024-01-01",
            date_to="2024-01-01",
            reason="Carlos authorized SAT auth compatibility smoke",
            auth_envelope_variant=AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION,
        ),
        env={"LOCALAPPDATA": str(appdata_root)},
    )
    calls: list[str] = []
    seen: dict[str, object] = {}

    def fake_auth_smoke(
        profile_id: str,
        *,
        live_permit_verified: bool = False,
        auth_envelope_variant: str = AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
        wcf_action_header_enabled: bool = True,
    ) -> common_cli.LiveSmokeCliResult:
        calls.append(profile_id)
        seen["live_permit_verified"] = live_permit_verified
        seen["auth_envelope_variant"] = auth_envelope_variant
        seen["wcf_action_header_enabled"] = wcf_action_header_enabled
        return common_cli.LiveSmokeCliResult(result="synthetic-auth-ok", auth="attempted")

    monkeypatch.setattr(sat_auth_cli, "_run_live_auth_smoke", fake_auth_smoke)

    result = CliRunner().invoke(
        app,
        ["sat", "auth-smoke", "--profile", "dummy-profile", "--manual-real-sat", "--permit", permit.permit_id],
        env=_live_smoke_env(
            appdata_root,
            {
                "CFDI_VAULT_ALLOW_REAL_SAT": None,
                "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": None,
            },
        ),
    )

    assert result.exit_code == 0, result.output
    assert calls == ["dummy-profile"]
    assert seen["live_permit_verified"] is True
    assert seen["auth_envelope_variant"] == AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION
    assert seen["wcf_action_header_enabled"] is True
    assert "Type \"SAT REAL METADATA SMOKE\"" not in result.output
    assert "xml_downloaded=no" in result.output
    assert "zip_downloaded=no" in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)

    second = CliRunner().invoke(
        app,
        ["sat", "auth-smoke", "--profile", "dummy-profile", "--manual-real-sat", "--permit", permit.permit_id],
        env=_live_smoke_env(
            appdata_root,
            {
                "CFDI_VAULT_ALLOW_REAL_SAT": None,
                "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": None,
            },
        ),
    )

    assert second.exit_code == 1
    assert "error=live_permit_denied" in second.output
    assert "reason=permit-already-consumed" in second.output
    assert calls == ["dummy-profile"]


def test_live_smoke_checkout_guard_fails_closed_outside_git_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    assert common_cli._checkout_guard_status() == (False, False)


def _write_setup_profile(
    appdata_root: Path,
    *,
    profile_id: str = "dummy-profile",
    phrase_ref: str | None = None,
) -> setup_flow.AppDataPaths:
    paths = setup_flow.build_profile_paths(profile_id, env={"LOCALAPPDATA": str(appdata_root)})
    profile = setup_flow.LocalProfile(
        profile_id=profile_id,
        rfc="XAXX010101000",
        storage_root=paths.storage_root,
        credential_mode=setup_flow.CredentialMode.COPIED,
        certificate_path=paths.credentials_dir / "certificate.cer",
        private_key_path=paths.credentials_dir / "private-key.key",
        phrase_ref=phrase_ref or setup_flow.default_phrase_reference(profile_id),
        status=setup_flow.LocalProfileStatus.READY,
        certificate_fingerprint="a" * 64,
    )
    setup_flow.write_profile(profile, paths.profile_json)
    return paths


def _write_ready_setup_profile(appdata_root: Path, *, profile_id: str = "dummy-profile") -> setup_flow.AppDataPaths:
    paths = _write_setup_profile(appdata_root, profile_id=profile_id, phrase_ref=_dummy_phrase_ref(profile_id))
    paths.credentials_dir.mkdir(parents=True, exist_ok=True)
    paths.storage_root.mkdir(parents=True, exist_ok=True)
    paths.credentials_dir.joinpath("certificate.cer").write_text("synthetic certificate", encoding="utf-8")
    paths.credentials_dir.joinpath("private-key.key").write_text("synthetic private key", encoding="utf-8")
    return paths


def _patch_live_smoke_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    *,
    checkout: tuple[bool, bool],
    interactive: bool,
    doctor_ok: bool,
) -> None:
    provider_factory = lambda profile_id: DummySecretProvider({_dummy_phrase_ref(profile_id): "synthetic phrase"})
    monkeypatch.setattr(common_cli, "_checkout_guard_status", lambda: checkout)
    monkeypatch.setattr(common_cli, "_terminal_is_interactive", lambda: interactive)
    monkeypatch.setattr(common_cli, "_live_smoke_doctor_ok", lambda profile: doctor_ok)
    monkeypatch.setattr(common_cli, "_setup_provider", provider_factory)
    for module in (download_cli, sat_auth_cli, sat_common_cli, sat_metadata_cli, sat_verify_cli):
        monkeypatch.setattr(module, "_setup_provider", provider_factory, raising=False)


def _live_smoke_args(overrides: list[str]) -> list[str]:
    args = [
        "download",
        "live-smoke",
        "--profile",
        "dummy-profile",
        "--from",
        "2024-01-01",
        "--to",
        "2024-01-01",
        "--kind",
        "metadata",
        "--direction",
        "received",
    ]
    for option in ("--kind", "--to"):
        if option in overrides:
            index = args.index(option)
            del args[index : index + 2]
    return args + overrides


def _diagnose_live_args(overrides: list[str]) -> list[str]:
    return ["sat", "diagnose-live", *_live_smoke_args(overrides)[2:]]


def _live_smoke_env(appdata_root: Path, overrides: dict[str, str | None]) -> dict[str, str]:
    env = {
        "LOCALAPPDATA": str(appdata_root),
        "CI": "",
        "CFDI_VAULT_ALLOW_REAL_SAT": "1",
        "CFDI_VAULT_ALLOW_REAL_CREDENTIALS": "1",
    }
    for key, value in overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


def _dummy_phrase_ref(profile_id: str) -> str:
    return f"local-dev-dummy://cfdi-vault/setup/{profile_id}/private-key-phrase"


def _metadata_query() -> common_cli.DownloadQuery:
    return common_cli.DownloadQuery(
        "dummy-profile",
        "XAXX010101000",
        common_cli.DownloadDirection.RECEIVED,
        common_cli.RequestType.METADATA,
        common_cli.DateTimePeriod(
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            datetime(2024, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
        ),
    )


def _weekly_metadata_query() -> common_cli.DownloadQuery:
    return common_cli.DownloadQuery(
        "dummy-profile",
        "XAXX010101000",
        common_cli.DownloadDirection.RECEIVED,
        common_cli.RequestType.METADATA,
        common_cli.DateTimePeriod(
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            datetime(2024, 1, 7, 23, 59, 59, tzinfo=timezone.utc),
        ),
    )


def _metadata_txt_zip() -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as package:
        package.writestr(
            "metadata.txt",
            "\n".join(
                [
                    "uuid~rfcEmisor~nombreEmisor~rfcReceptor~nombreReceptor~fechaEmision~montoTotal~estadoComprobante~tipoComprobante",
                    "00000000-0000-4000-8000-000000000099~AAA010101AAA~Synthetic Issuer~BBB010101BBB~Synthetic Receiver~2024-01-15T10:30:00Z~123.45~Vigente~I",
                ]
            ).encode("utf-8"),
        )
    return buffer.getvalue()


def _key_value_lines(output: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def _assert_no_profile_secrets_or_paths(output: str, appdata_root: Path) -> None:
    assert "XAXX010101000" not in output
    assert str(appdata_root) not in output
    assert "certificate.cer" not in output
    assert "private-key.key" not in output
    assert "windows-credential-manager://" not in output
    assert "local-dev-dummy://" not in output


def _assert_no_download_status_leaks(output: str, appdata_root: Path) -> None:
    _assert_no_profile_secrets_or_paths(output, appdata_root)
    assert "PKG-" not in output
    assert ".zip" not in output
    assert ".xml" not in output
