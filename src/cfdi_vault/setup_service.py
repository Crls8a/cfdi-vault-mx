"""Local setup orchestration and rollback-safe profile creation."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Mapping

from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference, SecretValue
from cfdi_vault.setup_core import (
    CredentialMode,
    ExistenceProvider,
    LocalProfile,
    LocalProfileStatus,
    SetupError,
    SetupResult,
    build_profile_paths,
    default_phrase_reference,
    find_repo_root,
    validate_profile_id,
    validate_rfc,
    write_profile,
)
from cfdi_vault.setup_intake import CredentialSelection, discover_credentials, guard_credential_intake, stage_credentials_for_appdata


def run_setup(
    *,
    profile_id: str,
    rfc: str,
    source_folder: Path,
    phrase_value: str,
    provider: ExistenceProvider,
    mode: CredentialMode = CredentialMode.COPIED,
    certificate_path: Path | None = None,
    private_key_path: Path | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
    repo_root: Path | None = None,
) -> SetupResult:
    """Create the local AppData profile and store the phrase through a provider."""

    safe_profile_id = validate_profile_id(profile_id)
    normalized_rfc = validate_rfc(rfc)
    paths = build_profile_paths(safe_profile_id, env=env, home=home)
    environment = env if env is not None else os.environ
    guard_credential_intake(
        source_folder=source_folder,
        destination_root=paths.base_dir,
        env=environment,
        repo_root=repo_root,
    )
    selection = discover_credentials(source_folder, certificate_path=certificate_path, private_key_path=private_key_path)
    _guard_selected_paths(selection, repo_root=repo_root)
    if not phrase_value or not phrase_value.strip():
        raise SetupError(["private-key phrase must be provided and is stored only through the secret provider"])

    phrase_ref = default_phrase_reference(safe_profile_id)
    pending_import = stage_credentials_for_appdata(selection, paths, mode=mode)
    fingerprint = _sha256_file(pending_import.staged_selection.certificate_path)
    profile = LocalProfile(
        profile_id=safe_profile_id,
        rfc=normalized_rfc,
        storage_root=paths.storage_root,
        credential_mode=mode,
        certificate_path=pending_import.final_selection.certificate_path,
        private_key_path=pending_import.final_selection.private_key_path,
        phrase_ref=phrase_ref,
        status=LocalProfileStatus.READY,
        certificate_fingerprint=fingerprint,
    )
    temp_profile_json = paths.profile_json.with_name("profile.json.tmp")
    phrase_backup: SecretValue | None = None
    phrase_backup_loaded = False
    try:
        write_profile(profile, temp_profile_json)
        phrase_backup = _backup_phrase_for_rollback(provider, phrase_ref)
        phrase_backup_loaded = True
        provider.store(
            CredentialReference(uri=phrase_ref, kind=CredentialKind.PHRASE),
            phrase_value,
            purpose="setup-credential-intake",
        )
        pending_import.commit()
        os.replace(temp_profile_json, paths.profile_json)
        pending_import.finalize()
    except Exception:
        pending_import.rollback()
        if phrase_backup_loaded:
            _restore_phrase_after_failure(provider, phrase_ref, phrase_backup)
        try:
            temp_profile_json.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return SetupResult(profile=profile, paths=paths)


def _guard_selected_paths(selection: CredentialSelection, *, repo_root: Path | None) -> None:
    root = repo_root or find_repo_root(Path.cwd())
    if root is None:
        return
    errors: list[str] = []
    for label, path in (("certificate file", selection.certificate_path), ("private key file", selection.private_key_path)):
        if _is_path_inside(path, root):
            errors.append(f"{label} must be outside the repository")
    if errors:
        raise SetupError(errors)


def _is_path_inside(path: Path, root: Path) -> bool:
    resolved_path = path.expanduser().resolve(strict=False)
    resolved_root = root.expanduser().resolve(strict=False)
    return resolved_path == resolved_root or resolved_root in resolved_path.parents


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _backup_phrase_for_rollback(provider: ExistenceProvider, phrase_ref: str) -> SecretValue | None:
    reference = CredentialReference(uri=phrase_ref, kind=CredentialKind.PHRASE)
    try:
        if provider.exists(reference, purpose="setup-rollback-check"):
            return provider.resolve(reference, purpose="setup-rollback-backup")
    except CredentialProviderError as exc:
        raise SetupError(["private-key phrase reference could not be prepared for safe rollback"]) from exc
    return None


def _restore_phrase_after_failure(provider: ExistenceProvider, phrase_ref: str, phrase_backup: SecretValue | None) -> None:
    reference = CredentialReference(uri=phrase_ref, kind=CredentialKind.PHRASE)
    try:
        if phrase_backup is not None:
            provider.store(reference, phrase_backup.reveal(), purpose="setup-rollback")
            return
    except CredentialProviderError:
        return
    _delete_phrase_if_possible(provider, phrase_ref)


def _delete_phrase_if_possible(provider: ExistenceProvider, phrase_ref: str) -> None:
    delete = getattr(provider, "delete", None)
    if not callable(delete):
        return
    try:
        delete(CredentialReference(uri=phrase_ref, kind=CredentialKind.PHRASE), purpose="setup-rollback")
    except CredentialProviderError:
        pass
