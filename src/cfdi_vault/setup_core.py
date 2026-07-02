"""Core local setup profile model and AppData path helpers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import json
import os
from pathlib import Path
from typing import Mapping, Protocol

from cfdi_vault.config import PROFILE_ID_PATTERN, RFC_PATTERN
from cfdi_vault.secrets import CredentialReference, SecretValue


APPDATA_DIR_NAME = "cfdi-vault-mx"
DIRECT_CREDENTIAL_ENV_VARS = frozenset(
    {
        "CFDI_VAULT_EFIRMA_PASSWORD",
        "CFDI_VAULT_PRIVATE_KEY",
        "CFDI_VAULT_PRIVATE_KEY_CONTENT",
    }
)
PROFILE_JSON_INDENT = 2


class SetupError(ValueError):
    """Raised when local setup input is unsafe or invalid."""

    def __init__(self, errors: list[str] | tuple[str, ...]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(errors))


class CredentialMode(StrEnum):
    """How local credential file paths are represented in the profile."""

    COPIED = "copied"
    REFERENCED = "referenced"


class LocalProfileStatus(StrEnum):
    """Persisted setup readiness status for the local profile."""

    READY = "ready"
    MISSING = "missing"
    INSECURE = "insecure"


class ExistenceProvider(Protocol):
    """Secret provider shape used by setup without depending on an adapter."""

    def store(self, reference: CredentialReference, value: str, *, purpose: str) -> None:
        """Store one credential value without returning it."""

    def exists(self, reference: CredentialReference, *, purpose: str) -> bool:
        """Check whether one credential reference exists."""

    def resolve(self, reference: CredentialReference, *, purpose: str) -> SecretValue:
        """Resolve one credential value for immediate in-memory use."""


@dataclass(frozen=True)
class AppDataPaths:
    """Resolved local profile paths under the user's AppData root."""

    base_dir: Path
    profiles_dir: Path
    profile_dir: Path
    profile_json: Path
    credentials_dir: Path
    storage_root: Path


@dataclass(frozen=True)
class LocalProfile:
    """Local AppData profile document for one RFC."""

    profile_id: str
    rfc: str
    storage_root: Path
    credential_mode: CredentialMode
    certificate_path: Path
    private_key_path: Path
    phrase_ref: str
    status: LocalProfileStatus
    certificate_fingerprint: str

    def to_document(self) -> dict[str, str]:
        """Return the stable JSON shape stored in profile.json."""

        return {
            "profileId": self.profile_id,
            "rfc": self.rfc,
            "storageRoot": str(self.storage_root),
            "credentialMode": self.credential_mode.value,
            "certificatePath": str(self.certificate_path),
            "privateKeyPath": str(self.private_key_path),
            "passwordRef": self.phrase_ref,
            "status": self.status.value,
            "certificateFingerprint": self.certificate_fingerprint,
        }


@dataclass(frozen=True)
class SetupResult:
    """Result of creating or updating a local setup profile."""

    profile: LocalProfile
    paths: AppDataPaths


def validate_rfc(value: str) -> str:
    """Validate and normalize an RFC-shaped profile value."""

    normalized = value.strip().upper()
    if not RFC_PATTERN.fullmatch(normalized):
        raise SetupError(["RFC must be 12 or 13 uppercase RFC-shaped characters"])
    return normalized


def validate_profile_id(value: str) -> str:
    """Validate a profile id that can safely become a folder name."""

    normalized = value.strip()
    if not PROFILE_ID_PATTERN.fullmatch(normalized):
        raise SetupError(["profile id must use 2-64 letters, numbers, dot, underscore, or dash"])
    return normalized


def resolve_appdata_root(*, env: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
    """Resolve the cfdi-vault-mx AppData root with the documented fallback."""

    environment = env if env is not None else os.environ
    local_appdata = environment.get("LOCALAPPDATA")
    if local_appdata and local_appdata.strip():
        return Path(local_appdata).expanduser() / APPDATA_DIR_NAME
    return (home or Path.home()).expanduser() / "AppData" / "Local" / APPDATA_DIR_NAME


def build_profile_paths(profile_id: str, *, env: Mapping[str, str] | None = None, home: Path | None = None) -> AppDataPaths:
    """Build AppData paths for one profile without creating them."""

    safe_profile_id = validate_profile_id(profile_id)
    base_dir = resolve_appdata_root(env=env, home=home)
    profiles_dir = base_dir / "profiles"
    profile_dir = profiles_dir / safe_profile_id
    return AppDataPaths(
        base_dir=base_dir,
        profiles_dir=profiles_dir,
        profile_dir=profile_dir,
        profile_json=profile_dir / "profile.json",
        credentials_dir=profile_dir / "credentials",
        storage_root=base_dir / "storage" / safe_profile_id,
    )


def ensure_profile_layout(paths: AppDataPaths) -> None:
    """Create the local profile, credential, and storage folders."""

    paths.credentials_dir.mkdir(parents=True, exist_ok=True)
    paths.storage_root.mkdir(parents=True, exist_ok=True)


def write_profile(profile: LocalProfile, profile_json: Path) -> None:
    """Write one local profile document to AppData."""

    profile_json.parent.mkdir(parents=True, exist_ok=True)
    profile_json.write_text(
        json.dumps(profile.to_document(), indent=PROFILE_JSON_INDENT, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_profile(profile_id: str, *, env: Mapping[str, str] | None = None, home: Path | None = None) -> LocalProfile:
    """Load one AppData profile document."""

    paths = build_profile_paths(profile_id, env=env, home=home)
    if not paths.profile_json.is_file():
        raise SetupError([f"profile is not configured: {profile_id}"])
    try:
        data = json.loads(paths.profile_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SetupError([f"profile JSON is invalid: {exc.msg}"]) from exc
    return profile_from_document(data)


def profile_from_document(data: Mapping[str, object]) -> LocalProfile:
    """Parse a profile.json document."""

    errors: list[str] = []
    profile_id = _required_text(data, "profileId", errors)
    rfc = _required_text(data, "rfc", errors)
    storage_root = _required_text(data, "storageRoot", errors)
    credential_mode = _required_text(data, "credentialMode", errors)
    certificate_path = _required_text(data, "certificatePath", errors)
    private_key_path = _required_text(data, "privateKeyPath", errors)
    phrase_ref = _required_text(data, "passwordRef", errors)
    status = _required_text(data, "status", errors)
    certificate_fingerprint = _required_text(data, "certificateFingerprint", errors)
    if errors:
        raise SetupError(errors)
    assert profile_id and rfc and storage_root and credential_mode and certificate_path
    assert private_key_path and phrase_ref and status and certificate_fingerprint
    try:
        mode = CredentialMode(credential_mode)
        parsed_status = LocalProfileStatus(status)
    except ValueError as exc:
        raise SetupError(["profile contains an unsupported credential mode or status"]) from exc
    return LocalProfile(
        profile_id=validate_profile_id(profile_id),
        rfc=validate_rfc(rfc),
        storage_root=Path(storage_root),
        credential_mode=mode,
        certificate_path=Path(certificate_path),
        private_key_path=Path(private_key_path),
        phrase_ref=phrase_ref,
        status=parsed_status,
        certificate_fingerprint=certificate_fingerprint,
    )


def default_phrase_reference(profile_id: str) -> str:
    """Build the controlled local phrase reference for one profile."""

    safe_profile_id = validate_profile_id(profile_id)
    return f"windows-credential-manager://cfdi-vault/setup/{safe_profile_id}/private-key-phrase"


def redact_rfc(value: str) -> str:
    """Redact an RFC while keeping enough shape for recognition."""

    normalized = value.strip().upper()
    if len(normalized) <= 4:
        return "*" * len(normalized)
    return normalized[:2] + "*" * (len(normalized) - 4) + normalized[-2:]


def redact_fingerprint(value: str) -> str:
    """Redact a fingerprint for status/doctor output."""

    clean = value.strip().lower()
    if len(clean) <= 12:
        return "<redacted>"
    return f"{clean[:6]}...{clean[-6:]}"


def find_repo_root(start: Path) -> Path | None:
    """Find the nearest git repository root from a starting path."""

    current = start.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _required_text(data: Mapping[str, object], key: str, errors: list[str]) -> str | None:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"profile.{key} must be a non-empty string")
        return None
    return value
