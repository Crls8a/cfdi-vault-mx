"""Safe local configuration for RFC download profiles.

The module validates non-secret operating configuration only. Credential material
must be represented by references to an external custody mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlparse


RFC_PATTERN = re.compile(r"^[A-Z&Ñ]{3,4}\d{6}[A-Z0-9]{3}$", re.IGNORECASE)
PROFILE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$")
FINGERPRINT_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
TIME_PATTERN = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")

ALLOWED_REFERENCE_SCHEMES = frozenset(
    {
        "windows-credential-manager",
        "vault",
        "kms",
        "local-dev-dummy",
    }
)
SENSITIVE_FIELD_MARKERS = (
    "password",
    "passphrase",
    "privatekey",
    "secret",
    "token",
)
SENSITIVE_PATH_MARKERS = (
    "certificatepath",
    "certpath",
    "cerpath",
    "keypath",
    "efirmapath",
    "fielpath",
    "csdpath",
)
DANGEROUS_REFERENCE_SUFFIXES = frozenset({".cer", ".key", ".pem", ".pfx", ".p12"})
SENSITIVE_STRING_PATTERNS = (
    re.compile(r"BEGIN (?:RSA |DSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY", re.IGNORECASE),
    re.compile(r"\bMII[A-Za-z0-9+/]{20,}={0,2}\b"),
)


class ConfigValidationError(ValueError):
    """Raised when a config document does not match the safe schema."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(errors))


@dataclass(frozen=True)
class DownloadSettings:
    """Which SAT document direction and request strategy a profile uses."""

    issued: bool
    received: bool
    metadata_first: bool


@dataclass(frozen=True)
class InitialRange:
    """Initial closed date range for first profile synchronization."""

    start_date: date
    end_date: date | None = None


@dataclass(frozen=True)
class ScheduleSettings:
    """Basic local scheduling intent for a profile."""

    enabled: bool
    interval_minutes: int | None = None
    daily_at: str | None = None
    timezone: str = "UTC"


@dataclass(frozen=True)
class CredentialReferences:
    """External references to credential custody entries."""

    certificate_ref: str
    private_key_ref: str
    phrase_ref: str


@dataclass(frozen=True)
class ProfileConfig:
    """One taxpayer/RFC operating profile."""

    profile_id: str
    rfc: str
    storage_root: str
    download: DownloadSettings
    max_concurrency: int
    schedule: ScheduleSettings
    certificate_fingerprint: str
    credential_refs: CredentialReferences
    initial_range: InitialRange | None = None
    lookback_days: int | None = None


@dataclass(frozen=True)
class AppConfig:
    """Validated application configuration."""

    schema_version: int
    profiles: tuple[ProfileConfig, ...]

    def get_profile(self, profile_id: str) -> ProfileConfig:
        for profile in self.profiles:
            if profile.profile_id == profile_id:
                return profile
        raise KeyError(profile_id)


def load_config(path: str | Path) -> AppConfig:
    """Load and validate a JSON config file."""

    config_path = Path(path)
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigValidationError([f"invalid JSON: {exc.msg}"]) from exc
    if not isinstance(data, Mapping):
        raise ConfigValidationError(["config root must be a JSON object"])
    return validate_config(data)


def validate_config(data: Mapping[str, Any]) -> AppConfig:
    """Validate a config mapping and return typed configuration."""

    errors: list[str] = []
    _find_raw_credential_fields(data, path="config", errors=errors)
    _reject_unknown_keys(data, "config", {"schemaVersion", "profiles"}, errors)

    schema_version = data.get("schemaVersion")
    if schema_version != 1:
        errors.append("schemaVersion must be 1")

    raw_profiles = data.get("profiles")
    profiles: list[ProfileConfig] = []
    if not isinstance(raw_profiles, list) or not raw_profiles:
        errors.append("profiles must be a non-empty array")
    else:
        seen_profile_ids: set[str] = set()
        for index, raw_profile in enumerate(raw_profiles):
            path = f"profiles[{index}]"
            if not isinstance(raw_profile, Mapping):
                errors.append(f"{path} must be an object")
                continue
            profile = _parse_profile(raw_profile, path, errors)
            if profile is None:
                continue
            if profile.profile_id in seen_profile_ids:
                errors.append(f"{path}.profileId must be unique")
            seen_profile_ids.add(profile.profile_id)
            profiles.append(profile)

    if errors:
        raise ConfigValidationError(errors)
    return AppConfig(schema_version=1, profiles=tuple(profiles))


def _parse_profile(data: Mapping[str, Any], path: str, errors: list[str]) -> ProfileConfig | None:
    _reject_unknown_keys(
        data,
        path,
        {
            "profileId",
            "rfc",
            "storageRoot",
            "download",
            "initialRange",
            "lookbackDays",
            "maxConcurrency",
            "schedule",
            "certificateFingerprint",
            "credentialRefs",
        },
        errors,
    )
    profile_id = _required_string(data, "profileId", path, errors)
    rfc = _required_string(data, "rfc", path, errors)
    storage_root = _required_string(data, "storageRoot", path, errors)
    certificate_fingerprint = _required_string(data, "certificateFingerprint", path, errors)

    if profile_id and not PROFILE_ID_PATTERN.match(profile_id):
        errors.append(f"{path}.profileId must use 2-64 letters, numbers, dot, underscore, or dash")
    if rfc and not RFC_PATTERN.match(rfc):
        errors.append(f"{path}.rfc must be an RFC-shaped value")
    if storage_root and storage_root.strip() != storage_root:
        errors.append(f"{path}.storageRoot must not have leading or trailing whitespace")
    if certificate_fingerprint and not FINGERPRINT_PATTERN.match(certificate_fingerprint):
        errors.append(f"{path}.certificateFingerprint must be a 64-character SHA-256 hex fingerprint")

    download = _parse_download(data.get("download"), f"{path}.download", errors)
    initial_range = _parse_initial_range(data.get("initialRange"), f"{path}.initialRange", errors)
    lookback_days = _parse_positive_int(data.get("lookbackDays"), f"{path}.lookbackDays", errors, required=False)
    if initial_range is None and lookback_days is None:
        errors.append(f"{path} must define initialRange or lookbackDays")
    if initial_range is not None and lookback_days is not None:
        errors.append(f"{path} must not define both initialRange and lookbackDays")

    max_concurrency = _parse_positive_int(data.get("maxConcurrency"), f"{path}.maxConcurrency", errors, required=True)
    if max_concurrency is not None and max_concurrency > 10:
        errors.append(f"{path}.maxConcurrency must be 10 or less")

    schedule = _parse_schedule(data.get("schedule"), f"{path}.schedule", errors)
    credential_refs = _parse_credential_refs(data.get("credentialRefs"), f"{path}.credentialRefs", errors)

    if any(value is None for value in (profile_id, rfc, storage_root, download, max_concurrency, schedule, credential_refs)):
        return None
    if certificate_fingerprint is None:
        return None

    return ProfileConfig(
        profile_id=str(profile_id),
        rfc=str(rfc).upper(),
        storage_root=str(storage_root),
        download=download,
        initial_range=initial_range,
        lookback_days=lookback_days,
        max_concurrency=int(max_concurrency),
        schedule=schedule,
        certificate_fingerprint=str(certificate_fingerprint).lower(),
        credential_refs=credential_refs,
    )


def _parse_download(value: Any, path: str, errors: list[str]) -> DownloadSettings | None:
    if not isinstance(value, Mapping):
        errors.append(f"{path} must be an object")
        return None
    _reject_unknown_keys(value, path, {"issued", "received", "metadataFirst"}, errors)
    issued = value.get("issued")
    received = value.get("received")
    metadata_first = value.get("metadataFirst")
    for key, raw in (("issued", issued), ("received", received), ("metadataFirst", metadata_first)):
        if not isinstance(raw, bool):
            errors.append(f"{path}.{key} must be true or false")
    if isinstance(issued, bool) and isinstance(received, bool) and not (issued or received):
        errors.append(f"{path} must enable issued or received downloads")
    if all(isinstance(raw, bool) for raw in (issued, received, metadata_first)):
        return DownloadSettings(issued=issued, received=received, metadata_first=metadata_first)
    return None


def _parse_initial_range(value: Any, path: str, errors: list[str]) -> InitialRange | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        errors.append(f"{path} must be an object")
        return None
    _reject_unknown_keys(value, path, {"startDate", "endDate"}, errors)
    start = _parse_date(value.get("startDate"), f"{path}.startDate", errors, required=True)
    end = _parse_date(value.get("endDate"), f"{path}.endDate", errors, required=False)
    if start and end and end < start:
        errors.append(f"{path}.endDate must be greater than or equal to startDate")
    if start is None:
        return None
    return InitialRange(start_date=start, end_date=end)


def _parse_schedule(value: Any, path: str, errors: list[str]) -> ScheduleSettings | None:
    if not isinstance(value, Mapping):
        errors.append(f"{path} must be an object")
        return None
    _reject_unknown_keys(value, path, {"enabled", "intervalMinutes", "dailyAt", "timezone"}, errors)
    enabled = value.get("enabled")
    if not isinstance(enabled, bool):
        errors.append(f"{path}.enabled must be true or false")
        return None
    interval_minutes = _parse_positive_int(value.get("intervalMinutes"), f"{path}.intervalMinutes", errors, required=False)
    daily_at = value.get("dailyAt")
    if daily_at is not None:
        if not isinstance(daily_at, str) or not TIME_PATTERN.match(daily_at):
            errors.append(f"{path}.dailyAt must use HH:MM 24-hour format")
            daily_at = None
    timezone = value.get("timezone", "UTC")
    if not isinstance(timezone, str) or not timezone.strip():
        errors.append(f"{path}.timezone must be a non-empty string")
        timezone = "UTC"
    if enabled and interval_minutes is None and daily_at is None:
        errors.append(f"{path} must define intervalMinutes or dailyAt when enabled")
    return ScheduleSettings(
        enabled=enabled,
        interval_minutes=interval_minutes,
        daily_at=daily_at,
        timezone=timezone,
    )


def _parse_credential_refs(value: Any, path: str, errors: list[str]) -> CredentialReferences | None:
    if not isinstance(value, Mapping):
        errors.append(f"{path} must be an object")
        return None
    _reject_unknown_keys(value, path, {"certificateRef", "privateKeyRef", "passphraseRef"}, errors)
    certificate_ref = _required_reference(value, "certificateRef", path, errors)
    private_key_ref = _required_reference(value, "privateKeyRef", path, errors)
    phrase_ref = _required_reference(value, "passphraseRef", path, errors)
    if None in (certificate_ref, private_key_ref, phrase_ref):
        return None
    return CredentialReferences(
        certificate_ref=certificate_ref,
        private_key_ref=private_key_ref,
        phrase_ref=phrase_ref,
    )


def _required_reference(data: Mapping[str, Any], key: str, path: str, errors: list[str]) -> str | None:
    value = _required_string(data, key, path, errors)
    if value is None:
        return None
    parsed = urlparse(value)
    if parsed.scheme not in ALLOWED_REFERENCE_SCHEMES or not parsed.netloc:
        errors.append(
            f"{path}.{key} must use one of these reference schemes: "
            + ", ".join(sorted(ALLOWED_REFERENCE_SCHEMES))
        )
    if _reference_contains_credential_file_segment(value):
        errors.append(f"{path}.{key} must be a credential reference, not a credential file path")
    return value


def _reject_unknown_keys(
    data: Mapping[str, Any], path: str, allowed_keys: set[str], errors: list[str]
) -> None:
    for key in data:
        if str(key) not in allowed_keys:
            errors.append(f"{path}.{key} is not allowed by the safe config schema")


def _required_string(data: Mapping[str, Any], key: str, path: str, errors: list[str]) -> str | None:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path}.{key} must be a non-empty string")
        return None
    return value


def _parse_date(value: Any, path: str, errors: list[str], *, required: bool) -> date | None:
    if value is None:
        if required:
            errors.append(f"{path} is required")
        return None
    if not isinstance(value, str):
        errors.append(f"{path} must be an ISO date string")
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        errors.append(f"{path} must be an ISO date string")
        return None


def _parse_positive_int(value: Any, path: str, errors: list[str], *, required: bool) -> int | None:
    if value is None:
        if required:
            errors.append(f"{path} is required")
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        errors.append(f"{path} must be a positive integer")
        return None
    return value


def _find_raw_credential_fields(value: Any, *, path: str, errors: list[str]) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            key_text = str(key)
            normalized = re.sub(r"[^a-z0-9]", "", key_text.lower())
            if _looks_like_raw_credential_key(normalized):
                errors.append(f"{path}.{key_text} must be a credential reference, not a raw credential field")
            _find_raw_credential_fields(nested, path=f"{path}.{key_text}", errors=errors)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _find_raw_credential_fields(nested, path=f"{path}[{index}]", errors=errors)
    elif isinstance(value, str):
        _find_sensitive_string_value(value, path=path, errors=errors)


def _looks_like_raw_credential_key(normalized_key: str) -> bool:
    if normalized_key.endswith("ref") or normalized_key.endswith("refs"):
        return False
    if normalized_key in {"certificatefingerprint", "credentialrefs"}:
        return False
    if any(marker in normalized_key for marker in SENSITIVE_FIELD_MARKERS):
        return True
    return normalized_key in SENSITIVE_PATH_MARKERS


def _find_sensitive_string_value(value: str, *, path: str, errors: list[str]) -> None:
    for pattern in SENSITIVE_STRING_PATTERNS:
        if pattern.search(value):
            errors.append(f"{path} contains private key or certificate-like material")
            return


def _reference_contains_credential_file_segment(value: str) -> bool:
    parsed = urlparse(value)
    segments = [parsed.netloc, *parsed.path.replace("\\", "/").split("/")]
    for segment in segments:
        clean = segment.split("?", 1)[0].split("#", 1)[0].lower()
        if any(clean.endswith(suffix) for suffix in DANGEROUS_REFERENCE_SUFFIXES):
            return True
    return False
