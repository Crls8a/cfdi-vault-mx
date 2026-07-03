from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cfdi_vault import cli as cli_module
from cfdi_vault import setup as setup_flow
from cfdi_vault.cli import app
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


def test_download_sync_cfdi_runs_fake_pipeline_without_sensitive_output(tmp_path: Path) -> None:
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
    assert paths.storage_root.joinpath("db", "recovery.sqlite3").is_file()
    assert len(list(paths.storage_root.glob("*/xml/2024/01/*.xml"))) == 2
    assert "PKG-" not in result.output
    assert ".zip" not in result.output
    assert ".xml" not in result.output
    assert "recovery.sqlite3" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_download_status_reads_persisted_fake_sync_aggregates_safely(tmp_path: Path) -> None:
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


def test_download_status_missing_db_or_unknown_job_fails_safely(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_setup_profile(appdata_root)
    runner = CliRunner()

    missing_db = runner.invoke(
        app,
        ["download", "status", "--profile", "dummy-profile", "--job-id", "missing-job"],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert missing_db.exit_code == 1
    assert "error=status_not_found" in missing_db.output
    assert not paths.storage_root.joinpath("db", "recovery.sqlite3").exists()
    _assert_no_download_status_leaks(missing_db.output, appdata_root)

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


def test_download_sync_replay_same_criteria_returns_stable_result(tmp_path: Path) -> None:
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
    assert not paths.storage_root.joinpath("db", "recovery.sqlite3").exists()


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
    monkeypatch.setattr(cli_module, "_run_live_metadata_smoke", lambda profile_id, query: calls.append(profile_id))

    result = CliRunner().invoke(
        app,
        _live_smoke_args(args),
        env=_live_smoke_env(appdata_root, env_overrides),
        input=f"{cli_module.LIVE_SMOKE_CONFIRMATION}\n",
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
        cli_module,
        "_run_live_metadata_smoke",
        lambda profile_id, query: cli_module.LiveSmokeCliResult(
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
        input=f"{cli_module.LIVE_SMOKE_CONFIRMATION}\n",
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


def test_download_live_smoke_adapter_failure_prints_redacted_diagnostic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_ready_setup_profile(appdata_root)
    _patch_live_smoke_dependencies(monkeypatch, checkout=(True, True), interactive=True, doctor_ok=True)

    def fail_live_smoke(_profile_id: str, _query: object) -> None:
        raise cli_module.SatLiveSmokeError(
            "raw adapter detail must stay hidden",
            stage="auth_transport",
            error_kind="transport_http_error",
            safe_hint="check SOAPAction, content-type, logical endpoint, TLS, and SAT service availability",
            endpoint="auth",
            http_status=500,
            payload_size=123,
            envelope_sha256="a" * 64,
            duration_ms=7,
            correlation_id="diag-synthetic",
        )

    monkeypatch.setattr(cli_module, "_run_live_metadata_smoke", fail_live_smoke)

    result = CliRunner().invoke(
        app,
        _live_smoke_args(["--manual-real-sat"]),
        env=_live_smoke_env(appdata_root, {}),
        input=f"{cli_module.LIVE_SMOKE_CONFIRMATION}\n",
    )

    assert result.exit_code == 1
    lines = _key_value_lines(result.output)
    assert lines["error"] == "live_adapter_failed"
    assert lines["failed_stage"] == "auth_transport"
    assert lines["error_kind"] == "transport_http_error"
    assert lines["endpoint"] == "auth"
    assert lines["http_status"] == "500"
    assert lines["payload_size"] == "123"
    assert lines["correlation_id"] == "diag-synthetic"
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
        cli_module,
        "_run_live_diagnose",
        lambda profile_id, query: cli_module.LiveSmokeCliResult(
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
        input=f"{cli_module.LIVE_SMOKE_CONFIRMATION}\n",
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
        raise cli_module.SatLiveSmokeError(
            "raw diagnostic detail must stay hidden",
            stage="metadata_request_transport",
            error_kind="transport_timeout",
            safe_hint="check SOAPAction, content-type, logical endpoint, TLS, and SAT service availability",
            endpoint="metadata_request",
            duration_ms=9,
            correlation_id="diag-timeout",
        )

    monkeypatch.setattr(cli_module, "_run_live_diagnose", fail_diagnose)

    result = CliRunner().invoke(
        app,
        _diagnose_live_args(["--manual-real-sat"]),
        env=_live_smoke_env(appdata_root, {}),
        input=f"{cli_module.LIVE_SMOKE_CONFIRMATION}\n",
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
    monkeypatch.setattr(cli_module, "_run_live_diagnose", lambda profile_id, query: calls.append(profile_id))

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
    monkeypatch.setattr(
        cli_module,
        "_run_live_auth_smoke",
        lambda profile_id: cli_module.LiveSmokeCliResult(result="synthetic-auth-ok", auth="attempted"),
    )

    result = CliRunner().invoke(
        app,
        ["sat", "auth-smoke", "--profile", "dummy-profile", "--manual-real-sat"],
        env=_live_smoke_env(appdata_root, {}),
        input=f"{cli_module.LIVE_SMOKE_CONFIRMATION}\n",
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["mode"] == "live-smoke"
    assert lines["kind"] == "auth"
    assert lines["result"] == "synthetic-auth-ok"
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_live_smoke_checkout_guard_fails_closed_outside_git_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    assert cli_module._checkout_guard_status() == (False, False)


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
    monkeypatch.setattr(cli_module, "_checkout_guard_status", lambda: checkout)
    monkeypatch.setattr(cli_module, "_terminal_is_interactive", lambda: interactive)
    monkeypatch.setattr(cli_module, "_live_smoke_doctor_ok", lambda profile: doctor_ok)
    monkeypatch.setattr(
        cli_module,
        "_setup_provider",
        lambda profile_id: DummySecretProvider({_dummy_phrase_ref(profile_id): "synthetic phrase"}),
    )


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
    assert "recovery.sqlite3" not in output
