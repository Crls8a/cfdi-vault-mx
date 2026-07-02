from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cfdi_vault import cli
from cfdi_vault.cli import app
from cfdi_vault.windows_secrets import InMemoryWindowsCredentialBackend, WindowsCredentialManagerSecretProvider


def test_setup_cli_imports_credentials_with_hidden_phrase(monkeypatch, tmp_path: Path) -> None:
    source_folder = _write_synthetic_credentials(tmp_path / "external")
    appdata_root = tmp_path / "appdata"
    provider = WindowsCredentialManagerSecretProvider(InMemoryWindowsCredentialBackend())
    monkeypatch.setattr(cli, "_provider_for_reference", lambda _reference: provider)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    phrase_value = "SYNTHETIC-CLI-PHRASE"

    result = CliRunner().invoke(
        app,
        [
            "setup",
            "--source-folder",
            str(source_folder),
            "--profile-id",
            "dummy-profile",
            "--rfc",
            "XAXX010101000",
        ],
        input=f"{phrase_value}\n{phrase_value}\n",
        env={"LOCALAPPDATA": str(appdata_root), "CI": "0", "GITHUB_ACTIONS": "0", "TF_BUILD": "0"},
    )

    assert result.exit_code == 0, result.output
    assert "Setup complete" in result.output
    assert "dummy sign/verify passed" in result.output
    assert phrase_value not in result.output
    assert "XAXX010101000" not in result.output

    profile_json = appdata_root / "cfdi-vault-mx" / "profiles" / "dummy-profile" / "profile.json"
    profile_data = json.loads(profile_json.read_text(encoding="utf-8"))
    assert profile_data["profileId"] == "dummy-profile"
    assert profile_data["credentialMode"] == "copied"
    assert phrase_value not in profile_json.read_text(encoding="utf-8")


def test_setup_cli_accepts_no_smoke_without_dual_flag_type_errors(monkeypatch, tmp_path: Path) -> None:
    source_folder = _write_synthetic_credentials(tmp_path / "external")
    appdata_root = tmp_path / "appdata"
    provider = WindowsCredentialManagerSecretProvider(InMemoryWindowsCredentialBackend())
    monkeypatch.setattr(cli, "_provider_for_reference", lambda _reference: provider)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    phrase_value = "SYNTHETIC-CLI-PHRASE"

    result = CliRunner().invoke(
        app,
        [
            "setup",
            "--source-folder",
            str(source_folder),
            "--profile-id",
            "dummy-profile",
            "--rfc",
            "XAXX010101000",
            "--no-smoke",
        ],
        input=f"{phrase_value}\n{phrase_value}\n",
        env={"LOCALAPPDATA": str(appdata_root), "CI": "0", "GITHUB_ACTIONS": "0", "TF_BUILD": "0"},
    )

    assert result.exit_code == 0, result.output
    assert "Setup complete" in result.output
    assert "dummy sign/verify passed" not in result.output
    assert result.exception is None


def test_status_cli_reports_missing_profile_with_redaction(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"

    result = CliRunner().invoke(
        app,
        ["status", "--profile-id", "dummy-profile"],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 1
    assert "Setup profile: dummy-profile" in result.output
    assert "Status: missing" in result.output
    assert str(appdata_root) not in result.output


def test_doctor_includes_setup_status_without_failing_on_missing_profile(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    storage_root = tmp_path / "storage"
    recovery_db = tmp_path / "recovery.sqlite3"

    result = CliRunner().invoke(
        app,
        ["doctor", "--recovery-db", str(recovery_db), "--profile-id", "dummy-profile"],
        env={"LOCALAPPDATA": str(appdata_root), "CFDI_STORAGE_ROOT": str(storage_root)},
    )

    assert result.exit_code == 0, result.output
    assert "OK storage" in result.output
    assert "Setup profile: dummy-profile" in result.output
    assert "Status: missing" in result.output
    assert str(appdata_root) not in result.output


def _write_synthetic_credentials(source_folder: Path) -> Path:
    source_folder.mkdir(parents=True, exist_ok=True)
    (source_folder / "dummy.cer").write_bytes(b"\x30\x82SYNTHETIC-CERTIFICATE")
    (source_folder / "dummy.key").write_bytes(b"\x30\x82SYNTHETIC-KEY")
    return source_folder
