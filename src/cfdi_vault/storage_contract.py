"""Runtime-agnostic object-key and evidence-reference contracts.

This module owns metadata about stored evidence. Evidence bytes remain behind a
storage port, while PostgreSQL or another control plane may persist the stable
reference returned by an adapter.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
import re


_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_SEGMENT_PATTERN = re.compile(r"[^A-Za-z0-9_.=-]+")
_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True, slots=True)
class StorageKey:
    """Canonical, relative POSIX object key.

    Keys never contain a filesystem root. The active adapter decides where the
    referenced bytes live, so the same value can later address filesystem or
    object storage without leaking a local path into queue/API contracts.
    """

    value: str

    def __post_init__(self) -> None:
        _validate_key(self.value)

    def __str__(self) -> str:
        return self.value

    @property
    def parts(self) -> tuple[str, ...]:
        """Return validated path segments for filesystem adapters."""

        return tuple(self.value.split("/"))

    @classmethod
    def parse(cls, value: str | StorageKey) -> StorageKey:
        """Return a validated key without silently repairing unsafe input."""

        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise TypeError("storage key must be a string or StorageKey")
        return cls(value)

    @classmethod
    def metadata(
        cls,
        rfc: str,
        period: datetime,
        request_id: str,
        sha256: str,
        *,
        extension: str = "csv",
    ) -> StorageKey:
        """Build an RFC/period-partitioned metadata evidence key."""

        filename = f"{_safe_segment(request_id)}-{_sha256_prefix(sha256)}.{_safe_segment(extension.lstrip('.'))}"
        return cls._period_key(rfc, "metadata", period, filename)

    @classmethod
    def package(cls, rfc: str, period: datetime, package_id: str, sha256: str) -> StorageKey:
        """Build an RFC/period-partitioned raw package key."""

        filename = f"{_safe_segment(package_id)}-{_sha256_prefix(sha256)}.zip"
        return cls._period_key(rfc, "packages", period, filename)

    @classmethod
    def xml(cls, rfc: str, issue_date: datetime, uuid: str, sha256: str) -> StorageKey:
        """Build an RFC/period-partitioned XML evidence key."""

        filename = f"{_safe_segment(uuid.upper())}-{_sha256_prefix(sha256)}.xml"
        return cls._period_key(rfc, "xml", issue_date, filename)

    @classmethod
    def _period_key(cls, rfc: str, family: str, period: datetime, filename: str) -> StorageKey:
        return cls(
            "/".join(
                (
                    _safe_segment(rfc.upper()),
                    family,
                    f"{period.year:04d}",
                    f"{period.month:02d}",
                    filename,
                )
            )
        )


class StorageError(Exception):
    """Base adapter-neutral storage failure that never exposes local paths."""

    def __init__(self, key: StorageKey, operation: str, detail: str) -> None:
        self.key = StorageKey.parse(key)
        self.operation = operation
        super().__init__(f"storage {operation} {detail}")


class StorageCollisionError(StorageError, ValueError):
    """Raised when a key would overwrite or alias different evidence."""

    def __init__(self, key: StorageKey, detail: str = "collision", *, operation: str = "write") -> None:
        super().__init__(key, operation, detail)


class StorageNotFoundError(StorageError, FileNotFoundError):
    """Raised when evidence does not exist for a key."""

    def __init__(self, key: StorageKey, operation: str = "read") -> None:
        super().__init__(key, operation, "not found")


class StorageIOError(StorageError, OSError):
    """Raised when an adapter cannot complete an I/O operation."""

    def __init__(self, key: StorageKey, operation: str) -> None:
        super().__init__(key, operation, "failed")


@dataclass(frozen=True, slots=True, init=False)
class EvidenceReference:
    """Stable metadata with string keys normalized to ``StorageKey``."""

    key: StorageKey
    sha256: str
    size_bytes: int

    def __init__(self, key: StorageKey | str, sha256: str, size_bytes: int) -> None:
        object.__setattr__(self, "key", key)
        object.__setattr__(self, "sha256", sha256)
        object.__setattr__(self, "size_bytes", size_bytes)
        self.__post_init__()

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", StorageKey.parse(self.key))
        if not _SHA256_PATTERN.fullmatch(self.sha256):
            raise ValueError("evidence reference SHA-256 must be 64 hexadecimal characters")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int):
            raise TypeError("evidence reference size_bytes must be an integer")
        if self.size_bytes < 0:
            raise ValueError("evidence reference size_bytes cannot be negative")
        object.__setattr__(self, "sha256", self.sha256.lower())

    def as_dict(self) -> dict[str, str | int]:
        """Serialize only indexable metadata, never evidence bytes or local paths."""

        return {"storage_key": str(self.key), "sha256": self.sha256, "size_bytes": self.size_bytes}


def _validate_key(value: str) -> None:
    if (
        not value
        or value != value.strip()
        or "\\" in value
        or value.startswith("/")
        or _DRIVE_PREFIX.match(value)
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("storage key must be a canonical relative POSIX path")
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in value.split("/")) or path.as_posix() != value:
        raise ValueError("storage key contains an unsafe or non-canonical segment")


def _safe_segment(value: str) -> str:
    normalized = _SEGMENT_PATTERN.sub("-", value.strip()).strip(".-_")
    if not normalized:
        raise ValueError("storage path segment cannot be empty")
    return normalized


def _sha256_prefix(value: str) -> str:
    if not _SHA256_PATTERN.fullmatch(value):
        raise ValueError("storage evidence SHA-256 must be 64 hexadecimal characters")
    return value.lower()[:12]
