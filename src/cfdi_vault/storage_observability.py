"""Offline, redacted observations for stored evidence references.

This application service reads metadata through a narrow storage port. It does
not expose adapter roots, physical paths, evidence bytes, or the original
storage key in its result objects.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from cfdi_vault.storage_contract import (
    EvidenceReference,
    StorageKey,
    StorageNotFoundError,
)


class StorageStatPort(Protocol):
    """Minimal storage behavior required for offline observation."""

    def stat(self, key: str | StorageKey) -> EvidenceReference:
        """Return metadata for one reference without reading it into the CLI."""


class InvalidStorageReferenceError(ValueError):
    """Raised when a caller provides a non-canonical storage reference."""


class StorageObservationError(RuntimeError):
    """Raised when a storage adapter cannot safely report reference state."""


@dataclass(frozen=True, slots=True)
class StorageObservation:
    """Redacted state for one storage reference.

    ``reference`` is an irreversible short fingerprint. ``location`` is a
    logical, redacted URI and never an adapter-specific physical path.
    """

    exists: bool
    reference: str
    category: str
    size_bytes: int | None = None
    sha256_prefix: str | None = None
    location: str | None = None


class StorageObservabilityService:
    """Report filesystem evidence state without exposing sensitive paths."""

    def __init__(self, storage: StorageStatPort) -> None:
        self._storage = storage

    def status(self, reference: str | StorageKey) -> StorageObservation:
        """Return exists/not-found state for a canonical storage reference.

        Invalid references raise ``InvalidStorageReferenceError``. Adapter
        failures raise ``StorageObservationError`` with no original detail.
        """

        key = _parse_reference(reference)
        safe_reference = _reference_fingerprint(key)
        category = _safe_category(key)
        try:
            metadata = self._storage.stat(key)
        except StorageNotFoundError:
            return StorageObservation(False, safe_reference, category)
        except Exception:
            raise StorageObservationError("storage observation failed") from None
        if metadata.key != key:
            raise StorageObservationError("storage observation failed")
        return StorageObservation(
            True,
            safe_reference,
            category,
            size_bytes=metadata.size_bytes,
            sha256_prefix=metadata.sha256[:12],
        )

    def locate(self, reference: str | StorageKey) -> StorageObservation:
        """Return a redacted logical location, or a not-found observation."""

        observation = self.status(reference)
        if not observation.exists:
            return observation
        return StorageObservation(
            exists=True,
            reference=observation.reference,
            category=observation.category,
            size_bytes=observation.size_bytes,
            sha256_prefix=observation.sha256_prefix,
            location=(
                f"filesystem://{observation.category}/{observation.reference}"
            ),
        )


def _parse_reference(reference: str | StorageKey) -> StorageKey:
    """Validate one reference without repeating unsafe input in failures."""

    try:
        return StorageKey.parse(reference)
    except (TypeError, ValueError):
        raise InvalidStorageReferenceError("invalid storage reference") from None


def _reference_fingerprint(key: StorageKey) -> str:
    """Derive the only reference identifier allowed in user-facing output."""

    digest = hashlib.sha256(str(key).encode("utf-8")).hexdigest()
    return f"ref-{digest[:12]}"


def _safe_category(key: StorageKey) -> str:
    """Classify evidence without returning any original key segment."""

    for category in ("metadata", "packages", "xml"):
        if category in key.parts:
            return category
    return "evidence"
