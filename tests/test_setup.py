from __future__ import annotations

import os
from pathlib import Path

import pytest

from cfdi_vault import setup, setup_intake, setup_service
from cfdi_vault.secrets import CredentialProviderError, CredentialReference, SecretValue
from cfdi_vault.windows_secrets import InMemoryWindowsCredentialBackend, WindowsCredentialManagerSecretProvider


def test_rfc_validation_accepts_valid_shape_and_rejects_invalid() -> None:
    assert setup.validate_rfc("xaxx010101000") == "XAXX010101000"
    with pytest.raises(setup.SetupError):
        setup.validate_rfc("not-valid")


def test_appdata_path_builder_uses_localappdata_and_home_fallback(tmp_path: Path) -> None:
    local_appdata = tmp_path / "local-appdata"
    paths = setup.build_profile_paths("dummy-profile", env={"LOCALAPPDATA": str(local_appdata)})
    assert paths.profile_json == local_appdata / "cfdi-vault-mx" / "profiles" / "dummy-profile" / "profile.json"
    assert paths.credentials_dir == local_appdata / "cfdi-vault-mx" / "profiles" / "dummy-profile" / "credentials"
    assert paths.storage_root == local_appdata / "cfdi-vault-mx" / "storage" / "dummy-profile"
    assert setup.build_profile_paths("dummy-profile", env={}, home=tmp_path / "home").base_dir == tmp_path / "home" / "AppData" / "Local" / "cfdi-vault-mx"


def test_profile_json_roundtrip_never_requires_secret_value(tmp_path: Path) -> None:
    profile = _profile(tmp_path)
    profile_json = tmp_path / "profile.json"
    setup.write_profile(profile, profile_json)
    assert setup.profile_from_document(profile.to_document()).profile_id == "dummy-profile"
    assert "passwordRef" in profile_json.read_text(encoding="utf-8")
    assert "SYNTHETIC-LOCAL-PHRASE" not in profile_json.read_text(encoding="utf-8")


def test_discovery_rejects_ambiguous_candidates_without_explicit_selection(tmp_path: Path) -> None:
    source_folder = tmp_path / "external"
    source_folder.mkdir()
    first_certificate = source_folder / "first.cer"
    first_certificate.write_bytes(b"\x30\x82SYNTHETIC-CERTIFICATE-ONE")
    (source_folder / "second.cer").write_bytes(b"\x30\x82SYNTHETIC-CERTIFICATE-TWO")
    (source_folder / "dummy.key").write_bytes(b"\x30\x82SYNTHETIC-KEY")
    with pytest.raises(setup.SetupError):
        setup.discover_credentials(source_folder)
    assert setup.discover_credentials(source_folder, certificate_path=first_certificate).certificate_path == first_certificate


def test_intake_guards_reject_ci_direct_env_vars_and_repo_paths(tmp_path: Path) -> None:
    repo_root = _repo_root(tmp_path / "repo")
    with pytest.raises(setup.SetupError):
        setup.guard_credential_intake(source_folder=repo_root / "runtime-input", destination_root=tmp_path / "appdata", env={}, repo_root=repo_root)
    with pytest.raises(setup.SetupError):
        setup.guard_credential_intake(source_folder=tmp_path / "external", destination_root=tmp_path / "appdata", env={"CI": "true"}, repo_root=repo_root)
    with pytest.raises(setup.SetupError):
        setup.guard_credential_intake(source_folder=tmp_path / "external", destination_root=tmp_path / "appdata", env={"CFDI_VAULT_EFIRMA_PASSWORD": "SYNTHETIC"}, repo_root=repo_root)


def test_staged_import_copies_synthetic_credentials_to_appdata(tmp_path: Path) -> None:
    paths = setup.build_profile_paths("dummy-profile", env={"LOCALAPPDATA": str(tmp_path / "appdata")})
    imported = setup.import_credentials_to_appdata(setup.discover_credentials(_write_synthetic_credentials(tmp_path / "external")), paths)
    assert imported.certificate_path.read_bytes() == b"\x30\x82SYNTHETIC-CERTIFICATE"
    assert imported.private_key_path.read_bytes() == b"\x30\x82SYNTHETIC-KEY"


def test_run_setup_imports_credentials_and_never_persists_phrase(tmp_path: Path) -> None:
    phrase = "SYNTHETIC-LOCAL-PHRASE"
    result = _run_setup(tmp_path, phrase=phrase)
    raw_profile = result.paths.profile_json.read_text(encoding="utf-8")
    assert result.profile.status == setup.LocalProfileStatus.READY
    assert result.profile.certificate_path.parent == result.paths.credentials_dir
    assert result.profile.private_key_path.parent == result.paths.credentials_dir
    assert result.paths.storage_root.is_dir()
    assert phrase not in raw_profile
    assert len(result.profile.certificate_fingerprint) == 64


def test_run_setup_rolls_back_new_profile_when_secret_store_fails(tmp_path: Path) -> None:
    with pytest.raises(CredentialProviderError):
        _run_setup(tmp_path, provider=FailingStoreProvider())
    paths = setup.build_profile_paths("dummy-profile", env={"LOCALAPPDATA": str(tmp_path / "appdata")})
    assert not paths.profile_json.exists()
    assert not (paths.credentials_dir / "certificate.cer").exists()
    assert not (paths.credentials_dir / ".incoming").exists()


def test_rerun_preserves_existing_profile_files_and_phrase_on_late_failures(monkeypatch, tmp_path: Path) -> None:
    old_phrase = "SYNTHETIC-OLD-PHRASE"
    provider = _provider()
    first = _run_setup(tmp_path, provider=provider, phrase=old_phrase, certificate_content=b"\x30\x82SYNTHETIC-CERTIFICATE-OLD", key_content=b"\x30\x82SYNTHETIC-KEY-OLD")
    old_profile = first.paths.profile_json.read_text(encoding="utf-8")
    phrase_ref = setup.CredentialReference(uri=first.profile.phrase_ref, kind=setup.CredentialKind.PHRASE)

    def fail_profile_replace(source: Path | str, destination: Path | str) -> None:
        if Path(destination).name == "profile.json":
            raise OSError("synthetic profile replace failure")
        original_replace(source, destination)

    original_replace = os.replace
    monkeypatch.setattr(setup_service.os, "replace", fail_profile_replace)
    with pytest.raises(OSError):
        _run_setup(tmp_path, provider=provider, phrase="SYNTHETIC-NEW-PHRASE", source_name="second-external", certificate_content=b"\x30\x82SYNTHETIC-CERTIFICATE-NEW", key_content=b"\x30\x82SYNTHETIC-KEY-NEW")
    assert first.paths.profile_json.read_text(encoding="utf-8") == old_profile
    assert first.profile.certificate_path.read_bytes() == b"\x30\x82SYNTHETIC-CERTIFICATE-OLD"
    assert provider.resolve(phrase_ref, purpose="test-rollback").reveal() == old_phrase

    monkeypatch.setattr(setup_service.os, "replace", original_replace)

    def fail_private_key_replace(source: Path | str, destination: Path | str) -> None:
        if Path(destination).name == "private-key.key":
            raise OSError("synthetic credential commit failure")
        original_replace(source, destination)

    monkeypatch.setattr(setup_intake.os, "replace", fail_private_key_replace)
    with pytest.raises(OSError):
        _run_setup(tmp_path, provider=provider, phrase="SYNTHETIC-NEW-PHRASE", source_name="third-external", certificate_content=b"\x30\x82SYNTHETIC-CERTIFICATE-NEW", key_content=b"\x30\x82SYNTHETIC-KEY-NEW")
    assert first.profile.certificate_path.read_bytes() == b"\x30\x82SYNTHETIC-CERTIFICATE-OLD"
    assert first.profile.private_key_path.read_bytes() == b"\x30\x82SYNTHETIC-KEY-OLD"
    assert provider.resolve(phrase_ref, purpose="test-rollback").reveal() == old_phrase


def _run_setup(
    tmp_path: Path,
    *,
    provider: object | None = None,
    phrase: str = "SYNTHETIC-LOCAL-PHRASE",
    source_name: str = "external",
    certificate_content: bytes = b"\x30\x82SYNTHETIC-CERTIFICATE",
    key_content: bytes = b"\x30\x82SYNTHETIC-KEY",
) -> setup.SetupResult:
    return setup.run_setup(
        profile_id="dummy-profile",
        rfc="XAXX010101000",
        source_folder=_write_synthetic_credentials(tmp_path / source_name, certificate_content=certificate_content, key_content=key_content),
        phrase_value=phrase,
        provider=provider or _provider(),
        env={"LOCALAPPDATA": str(tmp_path / "appdata")},
        repo_root=_repo_root(tmp_path / "repo"),
    )


def _profile(tmp_path: Path) -> setup.LocalProfile:
    return setup.LocalProfile(
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


def _write_synthetic_credentials(source_folder: Path, *, certificate_content: bytes = b"\x30\x82SYNTHETIC-CERTIFICATE", key_content: bytes = b"\x30\x82SYNTHETIC-KEY") -> Path:
    source_folder.mkdir(parents=True, exist_ok=True)
    (source_folder / "dummy.cer").write_bytes(certificate_content)
    (source_folder / "dummy.key").write_bytes(key_content)
    return source_folder


def _repo_root(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / ".git").mkdir()
    return path


def _provider() -> WindowsCredentialManagerSecretProvider:
    return WindowsCredentialManagerSecretProvider(InMemoryWindowsCredentialBackend())


class FailingStoreProvider:
    def store(self, reference: CredentialReference, value: str, *, purpose: str) -> None:
        raise CredentialProviderError("synthetic store failure")

    def exists(self, reference: CredentialReference, *, purpose: str) -> bool:
        return False

    def resolve(self, reference: CredentialReference, *, purpose: str) -> SecretValue:
        raise CredentialProviderError("synthetic missing reference")


def test_status_report_redacts_rfc_fingerprint_and_paths(tmp_path: Path) -> None:
    provider = _provider()
    result = _run_setup(tmp_path, provider=provider)
    output = setup.format_profile_status(setup.inspect_profile("dummy-profile", provider=provider, env={"LOCALAPPDATA": str(tmp_path / "appdata")}))

    assert "Status: ready" in output
    assert "XAXX010101000" not in output
    assert str(tmp_path / "appdata") not in output
    assert result.profile.certificate_fingerprint not in output
    assert "<redacted-path>" in output


def test_missing_and_invalid_status_never_print_paths(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    missing = setup.format_profile_status(setup.inspect_profile("dummy-profile", env={"LOCALAPPDATA": str(appdata_root)}))
    assert "Status: missing" in missing
    assert str(appdata_root) not in missing

    paths = setup.build_profile_paths("dummy-profile", env={"LOCALAPPDATA": str(appdata_root)})
    paths.profile_json.parent.mkdir(parents=True)
    paths.profile_json.write_text("{not-json", encoding="utf-8")
    invalid = setup.format_profile_status(setup.inspect_profile("dummy-profile", env={"LOCALAPPDATA": str(appdata_root)}))
    assert "Status: insecure" in invalid
    assert str(appdata_root) not in invalid


def test_dummy_smoke_signs_and_verifies_without_exposing_phrase(tmp_path: Path) -> None:
    provider = _provider()
    phrase = "SYNTHETIC-LOCAL-PHRASE"
    result = _run_setup(tmp_path, provider=provider, phrase=phrase)

    smoke = setup.run_dummy_smoke(result.profile, provider)

    assert smoke.ok is True
    assert smoke.detail == "dummy sign/verify passed"
    assert phrase not in smoke.detail
    assert phrase not in smoke.backend


def test_reference_mode_keeps_external_paths_but_creates_appdata_layout(tmp_path: Path) -> None:
    source_folder = _write_synthetic_credentials(tmp_path / "reference-external")
    result = setup.run_setup(
        profile_id="dummy-profile",
        rfc="XAXX010101000",
        source_folder=source_folder,
        phrase_value="SYNTHETIC-LOCAL-PHRASE",
        provider=_provider(),
        mode=setup.CredentialMode.REFERENCED,
        env={"LOCALAPPDATA": str(tmp_path / "appdata")},
        repo_root=_repo_root(tmp_path / "repo"),
    )

    assert result.profile.credential_mode == setup.CredentialMode.REFERENCED
    assert result.profile.certificate_path == (source_folder / "dummy.cer").resolve()
    assert result.profile.private_key_path == (source_folder / "dummy.key").resolve()
    assert result.paths.credentials_dir.is_dir()
    assert result.paths.storage_root.is_dir()


def test_discovery_rejects_unencrypted_pem_private_key(tmp_path: Path) -> None:
    source_folder = tmp_path / "external-pem"
    source_folder.mkdir()
    (source_folder / "dummy.cer").write_bytes(b"\x30\x82SYNTHETIC-CERTIFICATE")
    (source_folder / "dummy.pem").write_text(
        "-----BEGIN " + "PRIVATE KEY-----\nSYNTHETIC\n-----END " + "PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    with pytest.raises(setup.SetupError) as exc_info:
        setup.discover_credentials(source_folder)

    assert "appears unencrypted" in str(exc_info.value)
