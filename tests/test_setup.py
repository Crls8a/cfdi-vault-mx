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
    loaded = setup.profile_from_document(profile.to_document())

    assert loaded.profile_id == "dummy-profile"
    assert "passwordRef" in profile_json.read_text(encoding="utf-8")
    assert "SYNTHETIC-LOCAL-PHRASE" not in profile_json.read_text(encoding="utf-8")


def test_discovery_rejects_ambiguous_candidates_without_explicit_selection(tmp_path: Path) -> None:
    source_folder = tmp_path / "external"
    source_folder.mkdir()
    first_certificate = source_folder / "first.cer"
    second_certificate = source_folder / "second.cer"
    private_key = source_folder / "dummy.key"
    first_certificate.write_bytes(b"\x30\x82SYNTHETIC-CERTIFICATE-ONE")
    second_certificate.write_bytes(b"\x30\x82SYNTHETIC-CERTIFICATE-TWO")
    private_key.write_bytes(b"\x30\x82SYNTHETIC-KEY")

    with pytest.raises(setup.SetupError) as exc_info:
        setup.discover_credentials(source_folder)

    assert "ambiguous certificate" in str(exc_info.value)

    selection = setup.discover_credentials(source_folder, certificate_path=first_certificate)

    assert selection.certificate_path == first_certificate
    assert selection.private_key_path == private_key


def test_intake_guards_reject_ci_direct_env_vars_and_repo_paths(tmp_path: Path) -> None:
    repo_root = _repo_root(tmp_path / "repo")
    source_folder = repo_root / "runtime-input"
    source_folder.mkdir()

    with pytest.raises(setup.SetupError) as repo_exc:
        setup.guard_credential_intake(
            source_folder=source_folder,
            destination_root=tmp_path / "appdata",
            env={"LOCALAPPDATA": str(tmp_path / "appdata")},
            repo_root=repo_root,
        )
    assert "source folder must be outside the repository" in str(repo_exc.value)

    with pytest.raises(setup.SetupError) as ci_exc:
        setup.guard_credential_intake(
            source_folder=tmp_path / "external",
            destination_root=tmp_path / "appdata",
            env={"LOCALAPPDATA": str(tmp_path / "appdata"), "CI": "true"},
            repo_root=repo_root,
        )
    assert "CI" in str(ci_exc.value)

    with pytest.raises(setup.SetupError) as env_exc:
        setup.guard_credential_intake(
            source_folder=tmp_path / "external",
            destination_root=tmp_path / "appdata",
            env={"LOCALAPPDATA": str(tmp_path / "appdata"), "CFDI_VAULT_EFIRMA_PASSWORD": "SYNTHETIC"},
            repo_root=repo_root,
        )
    assert "direct credential environment variables" in str(env_exc.value)


def test_staged_import_copies_synthetic_credentials_to_appdata(tmp_path: Path) -> None:
    source_folder = _write_synthetic_credentials(tmp_path / "external")
    paths = setup.build_profile_paths("dummy-profile", env={"LOCALAPPDATA": str(tmp_path / "appdata")})
    selection = setup.discover_credentials(source_folder)

    imported = setup.import_credentials_to_appdata(selection, paths)

    assert imported.certificate_path == paths.credentials_dir / "certificate.cer"
    assert imported.private_key_path == paths.credentials_dir / "private-key.key"
    assert imported.certificate_path.read_bytes() == b"\x30\x82SYNTHETIC-CERTIFICATE"
    assert imported.private_key_path.read_bytes() == b"\x30\x82SYNTHETIC-KEY"


def _write_synthetic_credentials(source_folder: Path) -> Path:
    source_folder.mkdir(parents=True, exist_ok=True)
    (source_folder / "dummy.cer").write_bytes(b"\x30\x82SYNTHETIC-CERTIFICATE")
    (source_folder / "dummy.key").write_bytes(b"\x30\x82SYNTHETIC-KEY")
    return source_folder


def _repo_root(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / ".git").mkdir()
    return path
