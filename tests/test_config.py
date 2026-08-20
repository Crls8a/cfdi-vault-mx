from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cfdi_vault.adapters.webapi import app as webapi
from cfdi_vault.adapters.webapi.config import WebApiSettings
from cfdi_vault.config import ConfigValidationError, validate_config

ALLOWED_ORIGIN = "http://127.0.0.1:3000"


def _validate_config_file(tmp_path: Path, config_path: Path):
    """Validate one config file through ``POST /api/config/validate``.

    The retired ``cfdi-vault config validate`` command is gone; the panel
    endpoint calls the same ``load_config``, so these tests assert the same
    schema rules through the surface that still exists.
    """

    settings = WebApiSettings.resolve(
        environment={
            "DATABASE_URL": "postgresql://synthetic:synthetic@localhost/synthetic",
            "CFDI_STORAGE_ROOT": str(tmp_path / "panel-storage"),
        },
        repository_root=tmp_path / "repo",
    )
    client = TestClient(webapi.create_app(settings))
    return client.post(
        "/api/config/validate",
        json={"config_path": str(config_path)},
        headers={"origin": ALLOWED_ORIGIN},
    )

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


@pytest.mark.parametrize("scheme", ["macos-keychain", "linux-secret-service", "linux-kwallet"])
def test_config_accepts_native_cross_platform_reference_schemes(scheme: str) -> None:
    config_data = copy.deepcopy(EXAMPLE_CONFIG)
    config_data["profiles"][0]["credentialRefs"]["passphraseRef"] = f"{scheme}://cfdi-vault/tests/phrase"
    config = validate_config(config_data)
    assert config.get_profile("dummy-received-lookback").credential_refs.phrase_ref.startswith(f"{scheme}://")


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


def test_config_validate_endpoint_accepts_dummy_example(tmp_path: Path) -> None:
    config_path = tmp_path / "dummy-config.json"
    config_path.write_text(json.dumps(EXAMPLE_CONFIG), encoding="utf-8")

    response = _validate_config_file(tmp_path, config_path)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["schema_version"] == 1
    assert len(payload["profiles"]) == 2


def test_config_validate_endpoint_rejects_private_key_material(tmp_path: Path) -> None:
    config_data = copy.deepcopy(EXAMPLE_CONFIG)
    config_data["profiles"][0]["notes"] = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    config_path = tmp_path / "bad-config.json"
    config_path.write_text(json.dumps(config_data), encoding="utf-8")

    response = _validate_config_file(tmp_path, config_path)

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["reason"] == "config-invalid"
    assert any("private key or certificate-like material" in error for error in detail["errors"])


def test_config_validate_endpoint_rejects_unknown_key_file_field(tmp_path: Path) -> None:
    config_data = copy.deepcopy(EXAMPLE_CONFIG)
    config_data["profiles"][0]["keyFile"] = "C:/dummy/sat/example.key"
    config_path = tmp_path / "bad-config.json"
    config_path.write_text(json.dumps(config_data), encoding="utf-8")

    response = _validate_config_file(tmp_path, config_path)

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["reason"] == "config-invalid"
    assert any("is not allowed by the safe config schema" in error for error in detail["errors"])
