"""Offline download helper behaviour.

``download plan/request/sync/status`` are no longer Typer commands, so these
tests drive the underlying functions directly.  Each one still asserts the
redaction and pipeline behaviour it asserted through ``CliRunner`` before.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import typer

from cfdi_vault import setup as setup_flow
from cfdi_vault.adapters.cli.download import (
    download_plan,
    download_request,
    download_status,
    download_sync,
)


def test_download_plan_prints_safe_plan_and_criteria_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)
    monkeypatch.setenv("LOCALAPPDATA", str(appdata_root))

    download_plan(
        profile="dummy-profile",
        from_date="2024-01-01",
        to_date="2024-01-31",
        kind="metadata",
        direction="received",
    )

    output = _output(capsys)
    lines = _key_value_lines(output)
    assert lines["mode"] == "fake"
    assert lines["profile"] == "dummy-profile"
    assert lines["kind"] == "metadata"
    assert lines["direction"] == "received"
    assert lines["from"] == "2024-01-01T00:00:00+00:00"
    assert lines["to"] == "2024-01-31T23:59:59.999999+00:00"
    assert lines["will_submit"] == "false"
    assert re.fullmatch(r"[0-9a-f]{64}", lines["criteria_hash"])
    assert "request_id" not in lines
    _assert_no_profile_secrets_or_paths(output, appdata_root)


def test_download_request_prints_synthetic_accepted_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)
    monkeypatch.setenv("LOCALAPPDATA", str(appdata_root))

    download_request(
        profile="dummy-profile",
        from_date="2024-02-01",
        to_date="2024-02-29",
        kind="cfdi",
        direction="issued",
    )

    output = _output(capsys)
    lines = _key_value_lines(output)
    assert lines["mode"] == "fake"
    assert lines["profile"] == "dummy-profile"
    assert lines["kind"] == "cfdi"
    assert lines["direction"] == "issued"
    assert lines["will_submit"] == "true"
    assert lines["request_id"] == f"SYN-REQ-{lines['criteria_hash'][:12].upper()}"
    assert lines["action"] == "accepted"
    assert lines["sat_code"] == "5000"
    assert lines["message"] == "Synthetic request accepted"
    _assert_no_profile_secrets_or_paths(output, appdata_root)


@pytest.mark.integration
def test_download_sync_cfdi_runs_fake_pipeline_without_sensitive_output(
    tmp_path: Path,
    reset_postgres_database: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_setup_profile(appdata_root)
    monkeypatch.setenv("LOCALAPPDATA", str(appdata_root))

    download_sync(
        profile="dummy-profile",
        from_date="2024-01-01",
        to_date="2024-01-31",
        kind="cfdi",
        direction="received",
        database_url=None,
    )

    output = _output(capsys)
    lines = _key_value_lines(output)
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
    assert "PKG-" not in output
    assert ".zip" not in output
    assert ".xml" not in output
    _assert_no_profile_secrets_or_paths(output, appdata_root)


@pytest.mark.integration
def test_download_status_reads_persisted_fake_sync_aggregates_safely(
    tmp_path: Path,
    reset_postgres_database: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)
    monkeypatch.setenv("LOCALAPPDATA", str(appdata_root))

    download_sync(
        profile="dummy-profile",
        from_date="2024-01-01",
        to_date="2024-01-31",
        kind="cfdi",
        direction="received",
        database_url=None,
    )
    sync_lines = _key_value_lines(_output(capsys))

    download_status(profile="dummy-profile", job_id=sync_lines["job_id"], database_url=None)

    output = _output(capsys)
    lines = _key_value_lines(output)
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
    _assert_no_download_status_leaks(output, appdata_root)


@pytest.mark.integration
def test_download_status_missing_or_unknown_job_fails_safely(
    tmp_path: Path,
    reset_postgres_database: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)
    monkeypatch.setenv("LOCALAPPDATA", str(appdata_root))

    with pytest.raises(typer.Exit) as missing_job:
        download_status(profile="dummy-profile", job_id="missing-job", database_url=None)

    assert missing_job.value.exit_code == 1
    missing_output = _output(capsys)
    assert "error=status_not_found" in missing_output
    _assert_no_download_status_leaks(missing_output, appdata_root)

    download_sync(
        profile="dummy-profile",
        from_date="2024-01-01",
        to_date="2024-01-31",
        kind="cfdi",
        direction="received",
        database_url=None,
    )
    capsys.readouterr()

    with pytest.raises(typer.Exit) as unknown_job:
        download_status(profile="dummy-profile", job_id="unknown-job", database_url=None)

    assert unknown_job.value.exit_code == 1
    unknown_output = _output(capsys)
    assert "error=status_not_found" in unknown_output
    _assert_no_download_status_leaks(unknown_output, appdata_root)


@pytest.mark.integration
def test_download_sync_replay_same_criteria_returns_stable_result(
    tmp_path: Path,
    reset_postgres_database: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)
    monkeypatch.setenv("LOCALAPPDATA", str(appdata_root))
    arguments = {
        "profile": "dummy-profile",
        "from_date": "2024-02-01",
        "to_date": "2024-02-29",
        "kind": "metadata",
        "direction": "issued",
        "database_url": None,
    }

    download_sync(**arguments)
    first_output = _output(capsys)
    download_sync(**arguments)
    replay_output = _output(capsys)

    first_lines = _key_value_lines(first_output)
    replay_lines = _key_value_lines(replay_output)
    assert replay_lines["criteria_hash"] == first_lines["criteria_hash"]
    assert replay_lines["job_id"] == first_lines["job_id"]
    assert replay_lines["request_id"] == first_lines["request_id"]
    assert replay_lines["status"] == first_lines["status"] == "succeeded"
    assert replay_lines["metadata_count"] == first_lines["metadata_count"] == "2"
    _assert_no_profile_secrets_or_paths(first_output, appdata_root)
    _assert_no_profile_secrets_or_paths(replay_output, appdata_root)


def test_download_rejects_invalid_direction_folio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)
    monkeypatch.setenv("LOCALAPPDATA", str(appdata_root))

    with pytest.raises(typer.BadParameter) as raised:
        download_plan(
            profile="dummy-profile",
            from_date="2024-01-01",
            to_date="2024-01-31",
            kind="metadata",
            direction="folio",
        )

    assert "direction must be received or issued" in str(raised.value)


def test_download_rejects_from_after_to(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)
    monkeypatch.setenv("LOCALAPPDATA", str(appdata_root))

    with pytest.raises(typer.Exit) as raised:
        download_plan(
            profile="dummy-profile",
            from_date="2024-02-01",
            to_date="2024-01-31",
            kind="metadata",
            direction="received",
        )

    assert raised.value.exit_code == 1
    output = _output(capsys)
    assert "error=invalid_date_range" in output
    assert "detail=--from must be before or equal to --to" in output


def test_download_missing_profile_fails_without_absolute_path_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    appdata_root = tmp_path / "appdata"
    monkeypatch.setenv("LOCALAPPDATA", str(appdata_root))

    with pytest.raises(typer.Exit) as raised:
        download_plan(
            profile="missing-profile",
            from_date="2024-01-01",
            to_date="2024-01-31",
            kind="metadata",
            direction="received",
        )

    assert raised.value.exit_code == 1
    output = _output(capsys)
    assert "profile=missing-profile" in output
    assert "error=profile_not_configured" in output
    assert str(appdata_root) not in output


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


def _output(capsys: pytest.CaptureFixture[str]) -> str:
    """Return the merged stream the CliRunner used to expose as ``output``."""

    captured = capsys.readouterr()
    return captured.out + captured.err


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
