"""Redacted setup profile status helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference
from cfdi_vault.setup_core import (
    ExistenceProvider,
    LocalProfile,
    LocalProfileStatus,
    SetupError,
    build_profile_paths,
    load_profile,
    redact_fingerprint,
    redact_rfc,
)


@dataclass(frozen=True)
class ProfileInspection:
    """Redacted status report for CLI status and doctor output."""

    profile_id: str
    redacted_rfc: str | None
    status: LocalProfileStatus
    credential_mode: str
    certificate_state: str
    private_key_state: str
    phrase_state: str
    storage_state: str
    redacted_fingerprint: str | None


def inspect_profile(
    profile_id: str,
    *,
    provider: ExistenceProvider | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> ProfileInspection:
    """Return a redacted, non-secret profile status report."""

    paths = build_profile_paths(profile_id, env=env, home=home)
    if not paths.profile_json.is_file():
        return _missing_inspection(profile_id)
    try:
        profile = load_profile(profile_id, env=env, home=home)
    except SetupError:
        return ProfileInspection(
            profile_id=profile_id,
            redacted_rfc=None,
            status=LocalProfileStatus.INSECURE,
            credential_mode="invalid",
            certificate_state="missing",
            private_key_state="missing",
            phrase_state="missing",
            storage_state="missing",
            redacted_fingerprint=None,
        )

    certificate_loaded = profile.certificate_path.is_file()
    private_key_loaded = profile.private_key_path.is_file()
    storage_loaded = profile.storage_root.is_dir()
    phrase_loaded = _phrase_exists(profile, provider)
    status = LocalProfileStatus.READY if all((certificate_loaded, private_key_loaded, storage_loaded, phrase_loaded)) else LocalProfileStatus.MISSING
    return ProfileInspection(
        profile_id=profile.profile_id,
        redacted_rfc=redact_rfc(profile.rfc),
        status=status,
        credential_mode=profile.credential_mode.value,
        certificate_state=_state(certificate_loaded),
        private_key_state=_state(private_key_loaded),
        phrase_state=_state(phrase_loaded),
        storage_state=_state(storage_loaded),
        redacted_fingerprint=redact_fingerprint(profile.certificate_fingerprint),
    )


def format_profile_status(inspection: ProfileInspection) -> str:
    """Format a status report without revealing RFCs, paths, or references."""

    lines = [
        f"Setup profile: {inspection.profile_id}",
        f"Status: {inspection.status.value}",
        f"RFC: {inspection.redacted_rfc or 'missing'}",
        f"Credential mode: {inspection.credential_mode}",
        f"Certificate: {inspection.certificate_state} (<redacted-path>)",
        f"Private key: {inspection.private_key_state} (<redacted-path>)",
        f"Private-key phrase: {inspection.phrase_state} (<redacted-reference>)",
        f"Storage: {inspection.storage_state} (<redacted-path>)",
        f"Certificate fingerprint: {inspection.redacted_fingerprint or 'missing'}",
    ]
    return "\n".join(lines)


def _missing_inspection(profile_id: str) -> ProfileInspection:
    return ProfileInspection(
        profile_id=profile_id,
        redacted_rfc=None,
        status=LocalProfileStatus.MISSING,
        credential_mode="missing",
        certificate_state="missing",
        private_key_state="missing",
        phrase_state="missing",
        storage_state="missing",
        redacted_fingerprint=None,
    )


def _phrase_exists(profile: LocalProfile, provider: ExistenceProvider | None) -> bool:
    if provider is None:
        return bool(profile.phrase_ref)
    try:
        return provider.exists(
            CredentialReference(uri=profile.phrase_ref, kind=CredentialKind.PHRASE),
            purpose="setup-status",
        )
    except CredentialProviderError:
        return False


def _state(ok: bool) -> str:
    return "loaded" if ok else "missing"
