from __future__ import annotations

import re
from pathlib import Path

from typer.testing import CliRunner

from cfdi_vault import setup as setup_flow
from cfdi_vault.cli import app


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

    assert result.exit_code != 0
    assert "--live" in result.output


def _write_setup_profile(appdata_root: Path, *, profile_id: str = "dummy-profile") -> None:
    paths = setup_flow.build_profile_paths(profile_id, env={"LOCALAPPDATA": str(appdata_root)})
    profile = setup_flow.LocalProfile(
        profile_id=profile_id,
        rfc="XAXX010101000",
        storage_root=paths.storage_root,
        credential_mode=setup_flow.CredentialMode.COPIED,
        certificate_path=paths.credentials_dir / "certificate.cer",
        private_key_path=paths.credentials_dir / "private-key.key",
        phrase_ref=setup_flow.default_phrase_reference(profile_id),
        status=setup_flow.LocalProfileStatus.READY,
        certificate_fingerprint="a" * 64,
    )
    setup_flow.write_profile(profile, paths.profile_json)


def _key_value_lines(output: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def _assert_no_profile_secrets_or_paths(output: str, appdata_root: Path) -> None:
    assert "XAXX010101000" not in output
    assert str(appdata_root) not in output
    assert "certificate.cer" not in output
    assert "private-key.key" not in output
    assert "windows-credential-manager://" not in output
