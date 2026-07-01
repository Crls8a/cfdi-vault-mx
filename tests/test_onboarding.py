from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cfdi_vault.cli import app
from cfdi_vault.onboarding import OnboardingError, validate_local_credential_files


def test_onboard_writes_safe_profile_config_and_storage_layout(tmp_path: Path) -> None:
    certificate_bytes = b"\x30\x82\x00\x06DUMMY-CERTIFICATE"
    key_bytes = b"\x30\x82\x00\x03DUMMY-KEY"
    certificate_path = tmp_path / "dummy.cer"
    key_path = tmp_path / "dummy.key"
    certificate_path.write_bytes(certificate_bytes)
    key_path.write_bytes(key_bytes)

    config_path = tmp_path / "local.config.json"
    storage_root = tmp_path / "vault-storage"
    cli_input = "DUMMY-LOCAL-PHRASE\nDUMMY-LOCAL-PHRASE\n"

    result = CliRunner().invoke(
        app,
        [
            "onboard",
            "--config",
            str(config_path),
            "--profile-id",
            "dummy-profile",
            "--rfc",
            "XAXX010101000",
            "--storage-root",
            str(storage_root),
            "--download-mode",
            "both",
            "--start-date",
            "2024-01-01",
            "--end-date",
            "2024-01-31",
            "--periodicity",
            "interval",
            "--interval-minutes",
            "360",
            "--max-concurrency",
            "2",
            "--cer",
            str(certificate_path),
            "--key",
            str(key_path),
        ],
        input=cli_input,
    )

    assert result.exit_code == 0, result.output
    assert "Onboarding complete" in result.output
    assert storage_root.joinpath("XAXX010101000", "metadata", "2024", "01").is_dir()
    assert storage_root.joinpath("XAXX010101000", "packages", "2024", "01").is_dir()
    assert storage_root.joinpath("XAXX010101000", "xml", "2024", "01").is_dir()

    raw_config = config_path.read_text(encoding="utf-8")
    assert "DUMMY-LOCAL-PHRASE" not in raw_config
    assert str(certificate_path) not in raw_config
    assert str(key_path) not in raw_config

    data = json.loads(raw_config)
    profile = data["profiles"][0]
    assert profile["profileId"] == "dummy-profile"
    assert profile["rfc"] == "XAXX010101000"
    assert profile["storageRoot"] == str(storage_root)
    assert profile["download"] == {"issued": True, "received": True, "metadataFirst": True}
    assert profile["initialRange"] == {"startDate": "2024-01-01", "endDate": "2024-01-31"}
    assert profile["schedule"]["intervalMinutes"] == 360
    assert profile["certificateFingerprint"] == hashlib.sha256(certificate_bytes).hexdigest()
    assert profile["credentialRefs"]["certificateRef"].startswith("windows-credential-manager://")
    assert profile["credentialRefs"]["privateKeyRef"].startswith("windows-credential-manager://")
    assert profile["credentialRefs"]["passphraseRef"].startswith("windows-credential-manager://")


def test_onboard_rejects_duplicate_profile_without_replace(tmp_path: Path) -> None:
    certificate_path = tmp_path / "dummy.cer"
    key_path = tmp_path / "dummy.key"
    certificate_path.write_bytes(b"\x30\x82\x00\x06DUMMY-CERTIFICATE")
    key_path.write_bytes(b"\x30\x82\x00\x03DUMMY-KEY")
    config_path = tmp_path / "local.config.json"
    config_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "profiles": [
                    {
                        "profileId": "dummy-profile",
                        "rfc": "XAXX010101000",
                        "storageRoot": str(tmp_path / "old-storage"),
                        "download": {"issued": False, "received": True, "metadataFirst": True},
                        "initialRange": {"startDate": "2024-01-01"},
                        "maxConcurrency": 1,
                        "schedule": {"enabled": False, "timezone": "America/Mexico_City"},
                        "certificateFingerprint": "0" * 64,
                        "credentialRefs": {
                            "certificateRef": "local-dev-dummy://cfdi-vault/tests/dummy-certificate",
                            "privateKeyRef": "local-dev-dummy://cfdi-vault/tests/dummy-private-key",
                            "passphraseRef": "local-dev-dummy://cfdi-vault/tests/dummy-passphrase",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "onboard",
            "--config",
            str(config_path),
            "--profile-id",
            "dummy-profile",
            "--rfc",
            "XAXX010101000",
            "--storage-root",
            str(tmp_path / "vault-storage"),
            "--download-mode",
            "received",
            "--start-date",
            "2024-01-01",
            "--end-date",
            "2024-01-01",
            "--periodicity",
            "disabled",
            "--max-concurrency",
            "1",
            "--cer",
            str(certificate_path),
            "--key",
            str(key_path),
        ],
        input="DUMMY-LOCAL-PHRASE\nDUMMY-LOCAL-PHRASE\n",
    )

    assert result.exit_code == 1
    assert "already exists" in result.output


def test_onboard_rejects_credential_ref_prefix_that_looks_like_credential_path(tmp_path: Path) -> None:
    certificate_path = tmp_path / "dummy.cer"
    key_path = tmp_path / "dummy.key"
    certificate_path.write_bytes(b"\x30\x82\x00\x06DUMMY-CERTIFICATE")
    key_path.write_bytes(b"\x30\x82\x00\x03DUMMY-KEY")

    result = CliRunner().invoke(
        app,
        [
            "onboard",
            "--config",
            str(tmp_path / "local.config.json"),
            "--profile-id",
            "dummy-profile",
            "--rfc",
            "XAXX010101000",
            "--storage-root",
            str(tmp_path / "vault-storage"),
            "--download-mode",
            "received",
            "--start-date",
            "2024-01-01",
            "--end-date",
            "2024-01-01",
            "--periodicity",
            "disabled",
            "--max-concurrency",
            "1",
            "--cer",
            str(certificate_path),
            "--key",
            str(key_path),
            "--credential-ref-prefix",
            "windows-credential-manager://cfdi-vault/example.cer",
        ],
        input="DUMMY-LOCAL-PHRASE\nDUMMY-LOCAL-PHRASE\n",
    )

    assert result.exit_code == 1
    assert "not a credential file path" in result.output


def test_validate_local_credential_files_rejects_unexpected_extension(tmp_path: Path) -> None:
    certificate_path = tmp_path / "dummy.txt"
    key_path = tmp_path / "dummy.key"
    certificate_path.write_bytes(b"\x30\x82\x00\x06DUMMY-CERTIFICATE")
    key_path.write_bytes(b"\x30\x82\x00\x03DUMMY-KEY")

    with pytest.raises(OnboardingError) as exc_info:
        validate_local_credential_files(certificate_path, key_path)

    assert ".cer extension" in str(exc_info.value)
