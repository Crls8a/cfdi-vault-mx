from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cfdi_vault.cli import app
from cfdi_vault.config import ConfigValidationError, validate_config


EXAMPLE_CONFIG = {
    "schemaVersion": 1,
    "profiles": [
        {
            "profileId": "dummy-received-lookback",
            "rfc": "XAXX010101000",
            "storageRoot": "C:/CFDI-Vault-Dummy/storage/dummy-received-lookback",
            "download": {"issued": False, "received": True, "metadataFirst": True},
            "lookbackDays": 30,
            "maxConcurrency": 2,
            "schedule": {"enabled": True, "intervalMinutes": 360, "timezone": "America/Mexico_City"},
            "certificateFingerprint": "0" * 64,
            "credentialRefs": {
                "certificateRef": "local-dev-dummy://cfdi-vault/tests/dummy-certificate",
                "privateKeyRef": "local-dev-dummy://cfdi-vault/tests/dummy-private-key",
                "passphraseRef": "local-dev-dummy://cfdi-vault/tests/dummy-passphrase",
            },
        },
        {
            "profileId": "dummy-issued-initial-range",
            "rfc": "XAXX010101000",
            "storageRoot": "C:/CFDI-Vault-Dummy/storage/dummy-issued-initial-range",
            "download": {"issued": True, "received": False, "metadataFirst": True},
            "initialRange": {"startDate": "2024-01-01", "endDate": "2024-01-31"},
            "maxConcurrency": 1,
            "schedule": {"enabled": False, "timezone": "America/Mexico_City"},
            "certificateFingerprint": "1" * 64,
            "credentialRefs": {
                "certificateRef": "local-dev-dummy://cfdi-vault/tests/dummy-issued-certificate",
                "privateKeyRef": "local-dev-dummy://cfdi-vault/tests/dummy-issued-private-key",
                "passphraseRef": "local-dev-dummy://cfdi-vault/tests/dummy-issued-passphrase",
            },
        },
    ],
}


def test_config_accepts_multiple_profiles_with_references() -> None:
    config = validate_config(EXAMPLE_CONFIG)

    assert len(config.profiles) == 2
    assert config.get_profile("dummy-received-lookback").rfc == "XAXX010101000"
    assert config.get_profile("dummy-received-lookback").lookback_days == 30
    assert config.get_profile("dummy-issued-initial-range").initial_range is not None


def test_config_rejects_raw_credential_field() -> None:
    config_data = copy.deepcopy(EXAMPLE_CONFIG)
    raw_field_name = "pass" + "word"
    config_data["profiles"][0][raw_field_name] = "DUMMY"

    with pytest.raises(ConfigValidationError) as exc_info:
        validate_config(config_data)

    assert "must be a credential reference" in str(exc_info.value)


def test_config_rejects_private_key_material_under_neutral_field() -> None:
    config_data = copy.deepcopy(EXAMPLE_CONFIG)
    config_data["profiles"][0]["notes"] = "-----BEGIN " + "PRIVATE KEY-----"

    with pytest.raises(ConfigValidationError) as exc_info:
        validate_config(config_data)

    assert "private key or certificate-like material" in str(exc_info.value)


@pytest.mark.parametrize(
    ("field_name", "field_value"),
    [
        ("apiKey", "DUMMY"),
        ("satCredential", "DUMMY"),
        ("certificate", "C:/dummy/sat/example.cer"),
        ("keyFile", "C:/dummy/sat/example.key"),
    ],
)
def test_config_rejects_unknown_credential_like_fields(
    field_name: str, field_value: str
) -> None:
    config_data = copy.deepcopy(EXAMPLE_CONFIG)
    config_data["profiles"][0][field_name] = field_value

    with pytest.raises(ConfigValidationError) as exc_info:
        validate_config(config_data)

    assert "is not allowed by the safe config schema" in str(exc_info.value)


def test_config_rejects_unapproved_reference_scheme() -> None:
    config_data = copy.deepcopy(EXAMPLE_CONFIG)
    phrase_ref_name = "passphrase" + "Ref"
    config_data["profiles"][0]["credentialRefs"][phrase_ref_name] = "local-file://cfdi-vault/tests/dummy-phrase"

    with pytest.raises(ConfigValidationError) as exc_info:
        validate_config(config_data)

    assert "reference schemes" in str(exc_info.value)


@pytest.mark.parametrize(
    "reference_value",
    [
        "windows-credential-manager://cfdi-vault/C:/dummy/sat/example.cer",
        "windows-credential-manager://cfdi-vault/C:/dummy/sat/example.cer/certificate",
        "vault://cfdi-vault/secrets/example.key",
        "vault://cfdi-vault/secrets/example.key/private-key",
        "local-dev-dummy://cfdi-vault/example.pem",
    ],
)
def test_config_rejects_credential_refs_that_look_like_file_paths(reference_value: str) -> None:
    config_data = copy.deepcopy(EXAMPLE_CONFIG)
    config_data["profiles"][0]["credentialRefs"]["certificateRef"] = reference_value

    with pytest.raises(ConfigValidationError) as exc_info:
        validate_config(config_data)

    assert "not a credential file path" in str(exc_info.value)


def test_config_requires_range_or_lookback_but_not_both() -> None:
    config_data = copy.deepcopy(EXAMPLE_CONFIG)
    config_data["profiles"][0]["initialRange"] = {"startDate": "2024-01-01"}

    with pytest.raises(ConfigValidationError) as exc_info:
        validate_config(config_data)

    assert "must not define both initialRange and lookbackDays" in str(exc_info.value)


def test_cli_config_validate_accepts_dummy_example(tmp_path: Path) -> None:
    config_path = tmp_path / "dummy-config.json"
    config_path.write_text(json.dumps(EXAMPLE_CONFIG), encoding="utf-8")

    result = CliRunner().invoke(app, ["config", "validate", str(config_path)])

    assert result.exit_code == 0
    assert "Config OK" in result.output
    assert "profiles=2" in result.output


def test_cli_config_validate_rejects_private_key_material(tmp_path: Path) -> None:
    config_data = copy.deepcopy(EXAMPLE_CONFIG)
    config_data["profiles"][0]["notes"] = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    config_path = tmp_path / "bad-config.json"
    config_path.write_text(json.dumps(config_data), encoding="utf-8")

    result = CliRunner().invoke(app, ["config", "validate", str(config_path)])

    assert result.exit_code != 0
    assert "private key or certificate-like material" in result.output


def test_cli_config_validate_rejects_unknown_key_file_field(tmp_path: Path) -> None:
    config_data = copy.deepcopy(EXAMPLE_CONFIG)
    config_data["profiles"][0]["keyFile"] = "C:/dummy/sat/example.key"
    config_path = tmp_path / "bad-config.json"
    config_path.write_text(json.dumps(config_data), encoding="utf-8")

    result = CliRunner().invoke(app, ["config", "validate", str(config_path)])

    assert result.exit_code != 0
    assert "is not allowed by the safe config schema" in result.output
