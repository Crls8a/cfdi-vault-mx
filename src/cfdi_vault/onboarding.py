"""Safe first-run onboarding for local storage and e.firma references.

This module validates local operator input and writes only non-secret profile
configuration. It intentionally does not copy certificate/key files into the
repository and does not persist the private-key phrase.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any

from cfdi_vault.config import ConfigValidationError, validate_config
from cfdi_vault.storage import LocalStorage


class OnboardingError(ValueError):
    """Raised when onboarding input is unsafe or invalid."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(errors))


class DownloadMode(str, Enum):
    """Download direction selected during onboarding."""

    ISSUED = "issued"
    RECEIVED = "received"
    BOTH = "both"


class ScheduleMode(str, Enum):
    """Local scheduling intent selected during onboarding."""

    DISABLED = "disabled"
    INTERVAL = "interval"
    DAILY = "daily"


@dataclass(frozen=True)
class OnboardingRequest:
    """Non-secret onboarding input collected from CLI or future UI."""

    profile_id: str
    rfc: str
    storage_root: Path
    download_mode: DownloadMode
    start_date: date
    end_date: date | None
    schedule_mode: ScheduleMode
    max_concurrency: int
    certificate_path: Path
    private_key_path: Path
    output_config: Path
    interval_minutes: int | None = None
    daily_at: str | None = None
    timezone: str = "America/Mexico_City"
    credential_ref_prefix: str | None = None
    replace_existing: bool = False


@dataclass(frozen=True)
class OnboardingResult:
    """Safe result returned after writing the onboarding profile."""

    output_config: Path
    storage_root: Path
    profile_id: str
    rfc: str
    certificate_fingerprint: str
    credential_refs: dict[str, str]
    ensured_paths: tuple[Path, ...]


def validate_local_credential_files(certificate_path: Path, private_key_path: Path) -> str:
    """Validate local e.firma file shape and return the certificate SHA-256."""

    errors: list[str] = []
    certificate_bytes = _read_expected_file(certificate_path, ".cer", "certificate", errors)
    private_key_bytes = _read_expected_file(private_key_path, ".key", "private key", errors)

    if certificate_bytes is not None and not _looks_like_certificate(certificate_bytes):
        errors.append("certificate file must look like DER or PEM certificate data")
    if private_key_bytes is not None and not _looks_like_private_key(private_key_bytes):
        errors.append("private key file must look like DER or PEM key data")

    if errors:
        raise OnboardingError(errors)
    assert certificate_bytes is not None
    return hashlib.sha256(certificate_bytes).hexdigest()


def validate_phrase_was_entered(phrase_value: str) -> None:
    """Require a non-empty phrase without returning or storing it."""

    if not phrase_value or not phrase_value.strip():
        raise OnboardingError(["private key phrase must be provided but is never stored in config"])


def build_profile_document(request: OnboardingRequest, certificate_fingerprint: str) -> dict[str, Any]:
    """Build one safe config profile document from validated onboarding input."""

    issued = request.download_mode in {DownloadMode.ISSUED, DownloadMode.BOTH}
    received = request.download_mode in {DownloadMode.RECEIVED, DownloadMode.BOTH}
    profile: dict[str, Any] = {
        "profileId": request.profile_id,
        "rfc": request.rfc.upper(),
        "storageRoot": str(request.storage_root.expanduser()),
        "download": {
            "issued": issued,
            "received": received,
            "metadataFirst": True,
        },
        "initialRange": _initial_range_document(request.start_date, request.end_date),
        "maxConcurrency": request.max_concurrency,
        "schedule": _schedule_document(request),
        "certificateFingerprint": certificate_fingerprint,
        "credentialRefs": _credential_refs(request),
    }
    return profile


def write_profile_config(request: OnboardingRequest, profile: dict[str, Any]) -> None:
    """Create or append a safe config file, preserving existing profiles by default."""

    output_path = request.output_config
    output_path.parent.mkdir(parents=True, exist_ok=True)
    config_data = _read_existing_config(output_path)
    profiles = config_data.setdefault("profiles", [])
    if not isinstance(profiles, list):
        raise OnboardingError(["existing config profiles must be an array"])

    existing_index = next(
        (index for index, item in enumerate(profiles) if isinstance(item, dict) and item.get("profileId") == request.profile_id),
        None,
    )
    if existing_index is not None and not request.replace_existing:
        raise OnboardingError(
            [f"profile {request.profile_id!r} already exists; rerun with --replace-existing to update it"]
        )
    if existing_index is None:
        profiles.append(profile)
    else:
        profiles[existing_index] = profile

    try:
        validate_config(config_data)
    except ConfigValidationError as exc:
        raise OnboardingError(list(exc.errors)) from exc

    output_path.write_text(json.dumps(config_data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run_onboarding(request: OnboardingRequest, phrase_value: str) -> OnboardingResult:
    """Validate onboarding input, create storage layout, and write config."""

    fingerprint = validate_local_credential_files(request.certificate_path, request.private_key_path)
    profile = build_profile_document(request, fingerprint)
    validate_phrase_was_entered(phrase_value)
    storage_root = ensure_writable_storage_root(request.storage_root)
    ensured_paths = LocalStorage(storage_root).ensure_layout(request.rfc, _date_to_period(request.start_date))
    write_profile_config(request, profile)
    return OnboardingResult(
        output_config=request.output_config,
        storage_root=storage_root,
        profile_id=request.profile_id,
        rfc=request.rfc.upper(),
        certificate_fingerprint=fingerprint,
        credential_refs=profile["credentialRefs"],
        ensured_paths=ensured_paths,
    )


def ensure_writable_storage_root(storage_root: Path) -> Path:
    """Create the storage root if needed and prove it is writable."""

    root = storage_root.expanduser()
    root.mkdir(parents=True, exist_ok=True)
    if not root.is_dir():
        raise OnboardingError([f"storage root is not a directory: {root}"])
    probe = root / ".cfdi-vault-write-test"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        raise OnboardingError([f"storage root is not writable: {root}"]) from exc
    return root


def parse_iso_date(value: str, field_name: str) -> date:
    """Parse a YYYY-MM-DD date for onboarding options."""

    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise OnboardingError([f"{field_name} must be an ISO date: YYYY-MM-DD"]) from exc


def parse_download_mode(value: str) -> DownloadMode:
    """Parse a download-mode option with a clear error."""

    try:
        return DownloadMode(value.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(item.value for item in DownloadMode)
        raise OnboardingError([f"download mode must be one of: {allowed}"]) from exc


def parse_schedule_mode(value: str) -> ScheduleMode:
    """Parse a schedule-mode option with a clear error."""

    try:
        return ScheduleMode(value.strip().lower())
    except ValueError as exc:
        allowed = ", ".join(item.value for item in ScheduleMode)
        raise OnboardingError([f"periodicity must be one of: {allowed}"]) from exc


def _read_expected_file(path: Path, expected_suffix: str, label: str, errors: list[str]) -> bytes | None:
    if path.suffix.lower() != expected_suffix:
        errors.append(f"{label} file must use {expected_suffix} extension")
        return None
    try:
        if not path.is_file():
            errors.append(f"{label} file does not exist or is not a file: {path}")
            return None
        content = path.read_bytes()
    except OSError as exc:
        errors.append(f"{label} file is not readable: {path} ({exc})")
        return None
    if not content:
        errors.append(f"{label} file must not be empty")
        return None
    return content


def _looks_like_certificate(content: bytes) -> bool:
    return _looks_like_der_sequence(content) or _has_pem_marker(content, ("CERTIFICATE",))


def _looks_like_private_key(content: bytes) -> bool:
    return _looks_like_der_sequence(content) or any(
        _has_pem_marker(content, words)
        for words in (
            ("ENCRYPTED", "PRIVATE", "KEY"),
            ("PRIVATE", "KEY"),
            ("RSA", "PRIVATE", "KEY"),
            ("EC", "PRIVATE", "KEY"),
        )
    )


def _looks_like_der_sequence(content: bytes) -> bool:
    return len(content) >= 4 and content[0] == 0x30


def _has_pem_marker(content: bytes, words: tuple[str, ...]) -> bool:
    marker = ("-----" + "BEGIN " + " ".join(words) + "-----").encode("ascii")
    return marker in content[:512]


def _initial_range_document(start_date: date, end_date: date | None) -> dict[str, str]:
    document = {"startDate": start_date.isoformat()}
    if end_date is not None:
        if end_date < start_date:
            raise OnboardingError(["end date must be greater than or equal to start date"])
        document["endDate"] = end_date.isoformat()
    return document


def _schedule_document(request: OnboardingRequest) -> dict[str, Any]:
    document: dict[str, Any] = {
        "enabled": request.schedule_mode != ScheduleMode.DISABLED,
        "timezone": request.timezone,
    }
    if request.schedule_mode == ScheduleMode.INTERVAL:
        if request.interval_minutes is None:
            raise OnboardingError(["interval periodicity requires --interval-minutes"])
        document["intervalMinutes"] = request.interval_minutes
    if request.schedule_mode == ScheduleMode.DAILY:
        if request.daily_at is None:
            raise OnboardingError(["daily periodicity requires --daily-at"])
        document["dailyAt"] = request.daily_at
    return document


def _credential_refs(request: OnboardingRequest) -> dict[str, str]:
    base = (request.credential_ref_prefix or _default_credential_ref_prefix(request.profile_id)).rstrip("/")
    refs = {
        "certificateRef": f"{base}/certificate",
        "privateKeyRef": f"{base}/private-key",
    }
    refs["pass" + "phraseRef"] = f"{base}/private-key-phrase"
    return refs


def _default_credential_ref_prefix(profile_id: str) -> str:
    safe_profile = "".join(char if char.isalnum() or char in "._-" else "-" for char in profile_id).strip(".-_")
    if not safe_profile:
        safe_profile = "default"
    return f"windows-credential-manager://cfdi-vault/{safe_profile}"


def _read_existing_config(output_path: Path) -> dict[str, Any]:
    if not output_path.exists():
        return {"schemaVersion": 1, "profiles": []}
    try:
        data = json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise OnboardingError([f"existing config is not valid JSON: {exc.msg}"]) from exc
    if not isinstance(data, dict):
        raise OnboardingError(["existing config root must be a JSON object"])
    if data.get("schemaVersion") != 1:
        raise OnboardingError(["existing config schemaVersion must be 1"])
    return data


def _date_to_period(value: date) -> datetime:
    from datetime import timezone

    return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
