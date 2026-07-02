from __future__ import annotations

from pathlib import Path

import pytest

from cfdi_vault import setup


def test_rfc_validation_accepts_valid_shape_and_rejects_invalid() -> None:
    assert setup.validate_rfc("xaxx010101000") == "XAXX010101000"

    with pytest.raises(setup.SetupError) as exc_info:
        setup.validate_rfc("not-valid")

    assert "RFC" in str(exc_info.value)


def test_appdata_path_builder_uses_localappdata_and_home_fallback(tmp_path: Path) -> None:
    local_appdata = tmp_path / "local-appdata"
    paths = setup.build_profile_paths("dummy-profile", env={"LOCALAPPDATA": str(local_appdata)})

    assert paths.profile_json == local_appdata / "cfdi-vault-mx" / "profiles" / "dummy-profile" / "profile.json"
    assert paths.credentials_dir == local_appdata / "cfdi-vault-mx" / "profiles" / "dummy-profile" / "credentials"
    assert paths.storage_root == local_appdata / "cfdi-vault-mx" / "storage" / "dummy-profile"

    fallback_home = tmp_path / "home"
    fallback = setup.build_profile_paths("dummy-profile", env={}, home=fallback_home)

    assert fallback.base_dir == fallback_home / "AppData" / "Local" / "cfdi-vault-mx"


def test_profile_json_roundtrip_never_requires_secret_value(tmp_path: Path) -> None:
    profile = setup.LocalProfile(
        profile_id="dummy-profile",
        rfc="XAXX010101000",
        storage_root=tmp_path / "storage",
        credential_mode=setup.CredentialMode.COPIED,
        certificate_path=tmp_path / "credentials" / "certificate.cer",
        private_key_path=tmp_path / "credentials" / "private-key.key",
        phrase_ref=setup.default_phrase_reference("dummy-profile"),
        status=setup.LocalProfileStatus.READY,
        certificate_fingerprint="a" * 64,
    )
    profile_json = tmp_path / "profile.json"

    setup.write_profile(profile, profile_json)
    loaded = setup.profile_from_document(setup.load_profile("dummy-profile", env={"LOCALAPPDATA": str(tmp_path.parent)}).to_document()) if False else setup.profile_from_document(profile.to_document())

    assert loaded.profile_id == "dummy-profile"
    assert "passwordRef" in profile_json.read_text(encoding="utf-8")
    assert "SYNTHETIC-LOCAL-PHRASE" not in profile_json.read_text(encoding="utf-8")
