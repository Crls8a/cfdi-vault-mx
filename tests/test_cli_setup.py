from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cfdi_vault import setup as setup_flow
from cfdi_vault.adapters.cli import setup as setup_cli
from cfdi_vault.cli import app
from cfdi_vault.secrets import CredentialKind, CredentialReference
from cfdi_vault.windows_secrets import InMemoryWindowsCredentialBackend, WindowsCredentialManagerSecretProvider


def test_setup_cli_imports_credentials_with_hidden_phrase(monkeypatch, tmp_path: Path) -> None:
    source_folder = _write_synthetic_credentials(tmp_path / "external")
    appdata_root = tmp_path / "appdata"
    provider = WindowsCredentialManagerSecretProvider(InMemoryWindowsCredentialBackend())
    monkeypatch.setattr(setup_cli, "_setup_provider", lambda _profile_id: provider)
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
    assert "Credential check:" in result.output
    assert "Smoke:" not in result.output
    assert "dummy sign/verify passed" in result.output
    assert phrase_value not in result.output
    assert "XAXX010101000" not in result.output

    profile_json = appdata_root / "cfdi-vault-mx" / "profiles" / "dummy-profile" / "profile.json"
    profile_data = json.loads(profile_json.read_text(encoding="utf-8"))
    assert profile_data["profileId"] == "dummy-profile"
    assert profile_data["credentialMode"] == "copied"
    assert phrase_value not in profile_json.read_text(encoding="utf-8")


def test_setup_cli_accepts_skip_credential_check(monkeypatch, tmp_path: Path) -> None:
    source_folder = _write_synthetic_credentials(tmp_path / "external")
    appdata_root = tmp_path / "appdata"
    provider = WindowsCredentialManagerSecretProvider(InMemoryWindowsCredentialBackend())
    monkeypatch.setattr(setup_cli, "_setup_provider", lambda _profile_id: provider)
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
            "--skip-credential-check",
        ],
        input=f"{phrase_value}\n{phrase_value}\n",
        env={"LOCALAPPDATA": str(appdata_root), "CI": "0", "GITHUB_ACTIONS": "0", "TF_BUILD": "0"},
    )

    assert result.exit_code == 0, result.output
    assert "Setup complete" in result.output
    assert "dummy sign/verify passed" not in result.output
    assert result.exception is None


def test_setup_cli_rejects_retired_no_smoke_option() -> None:
    result = CliRunner().invoke(app, ["setup", "--no-smoke"])

    assert result.exit_code != 0
    assert "No such option: --no-smoke" in result.output


def test_setup_masked_phrase_reader_shows_feedback_without_secret() -> None:
    chars = iter(["p", "a", "s", "x", "\b", "s", "\r"])
    writes: list[str] = []

    value = setup_cli._read_masked_line("Private-key phrase: ", read_char=lambda: next(chars), write_text=writes.append)

    output = "".join(writes)
    assert value == "pass"
    assert "pass" not in output
    assert "*" in output
    assert "\b \b" in output


def test_setup_masked_phrase_confirmation_retries_without_printing_value(monkeypatch, capsys) -> None:
    phrase_value = "SYNTHETIC-CLI-PHRASE"
    responses = iter([phrase_value, "mismatch", phrase_value, phrase_value])
    monkeypatch.setattr(setup_cli, "_read_masked_line", lambda _prompt: next(responses))

    value = setup_cli._prompt_masked_with_confirmation("Private-key phrase")

    captured = capsys.readouterr()
    assert value == phrase_value
    assert phrase_value not in captured.out
    assert phrase_value not in captured.err
    assert "do not match" in captured.err


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


def test_preflight_cli_reports_only_sanitized_local_checks(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    appdata_root = tmp_path / "appdata"
    paths = setup_flow.build_profile_paths("dummy-profile", env={"LOCALAPPDATA": str(appdata_root)}, platform="win32")
    setup_flow.ensure_profile_layout(paths)
    certificate = paths.credentials_dir / "certificate.cer"
    private_key = paths.credentials_dir / "private-key.key"
    certificate.write_bytes(b"SYNTHETIC-CERTIFICATE")
    private_key.write_bytes(b"SYNTHETIC-KEY")
    profile = setup_flow.LocalProfile(
        profile_id="dummy-profile",
        rfc="XAXX010101000",
        storage_root=paths.storage_root,
        credential_mode=setup_flow.CredentialMode.COPIED,
        certificate_path=certificate,
        private_key_path=private_key,
        phrase_ref=setup_flow.default_phrase_reference("dummy-profile", platform="win32"),
        status=setup_flow.LocalProfileStatus.READY,
        certificate_fingerprint="a" * 64,
    )
    setup_flow.write_profile(profile, paths.profile_json)
    provider = WindowsCredentialManagerSecretProvider(InMemoryWindowsCredentialBackend())
    provider.store(
        CredentialReference(profile.phrase_ref, CredentialKind.PHRASE),
        "SYNTHETIC-PHRASE",
        purpose="test",
    )
    monkeypatch.setattr(setup_cli, "_setup_provider", lambda _profile_id: provider)
    monkeypatch.setattr(
        setup_cli,
        "default_local_probes",
        lambda _settings: {name: (lambda: True) for name in ("postgresql", "flyway", "rabbitmq", "redis")},
    )

    result = CliRunner().invoke(
        app,
        ["preflight", "--profile-id", "dummy-profile", "--storage", str(paths.storage_root)],
        env={
            "LOCALAPPDATA": str(appdata_root),
            "DATABASE_URL": "postgresql+psycopg://user:password@localhost:5432/vault",
            "RABBITMQ_URL": "amqp://localhost:5672/",
            "REDIS_URL": "redis://localhost:6379/0",
            "CFDI_VAULT_COMMIT_REF": "synthetic-commit",
        },
    )

    assert result.exit_code == 0, result.output
    assert "ready=true" in result.output
    assert str(tmp_path) not in result.output
    assert "SYNTHETIC-PHRASE" not in result.output
    assert "password" not in result.output


@pytest.mark.integration
def test_doctor_includes_setup_status_without_failing_on_missing_profile(tmp_path: Path, reset_postgres_database: str) -> None:
    appdata_root = tmp_path / "appdata"
    storage_root = tmp_path / "storage"

    result = CliRunner().invoke(
        app,
        ["doctor", "--profile-id", "dummy-profile"],
        env={"LOCALAPPDATA": str(appdata_root), "CFDI_STORAGE_ROOT": str(storage_root), "DATABASE_URL": reset_postgres_database},
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
