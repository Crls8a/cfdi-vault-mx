"""Local storage resolver for SAT metadata, packages, XML evidence, and exports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re

from cfdi_vault.storage_contract import (
    EvidenceReference,
    StorageCollisionError,
    StorageError,
    StorageIOError,
    StorageKey,
    StorageNotFoundError,
)


SEGMENT_PATTERN = re.compile(r"[^A-Za-z0-9_.=-]+")


@dataclass(frozen=True, slots=True)
class StoredFile(EvidenceReference):
    """Result of an idempotent local write."""

    path: Path
    written: bool

    @property
    def reference(self) -> EvidenceReference:
        """Return adapter-neutral metadata without exposing the local path."""

        return EvidenceReference(key=self.key, sha256=self.sha256, size_bytes=self.size_bytes)


def sha256_bytes(content: bytes) -> str:
    """Return the SHA-256 hex digest for bytes."""

    return hashlib.sha256(content).hexdigest()


class LocalStorage:
    """Filesystem storage rooted at the configured storage directory.

    Layout:

    ``<root>/<RFC>/metadata/YYYY/MM/``
    ``<root>/<RFC>/packages/YYYY/MM/``
    ``<root>/<RFC>/xml/YYYY/MM/``
    ``<root>/<RFC>/logs/``
    ``<root>/<RFC>/db/``
    """

    def __init__(self, root: str | Path = "storage") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def metadata_key(self, rfc: str, period: datetime, id_solicitud: str, sha256: str, *, extension: str = "csv") -> str:
        """Build a deterministic key for a metadata TXT/CSV index."""

        self.ensure_layout(rfc, period)
        return str(StorageKey.metadata(rfc, period, id_solicitud, sha256, extension=extension))

    def package_key(self, rfc: str, period: datetime, id_paquete: str, sha256: str) -> str:
        """Build a deterministic key for a SAT package ZIP."""

        self.ensure_layout(rfc, period)
        return str(StorageKey.package(rfc, period, id_paquete, sha256))

    def xml_key(self, rfc: str, issue_date: datetime, uuid: str, sha256: str) -> str:
        """Build a deterministic key for extracted XML evidence."""

        self.ensure_layout(rfc, issue_date)
        return str(StorageKey.xml(rfc, issue_date, uuid, sha256))

    def write_bytes(self, key: str | StorageKey, content: bytes) -> str:
        """Store bytes and return a storage reference.

        This method keeps the legacy overwrite behavior. Recovery code
        should prefer ``write_bytes_idempotent`` for SAT evidence.
        """

        storage_key = StorageKey.parse(key)
        path = self.path_for_key(storage_key)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        except OSError:
            raise StorageIOError(storage_key, "write") from None
        return str(path)

    def write_bytes_idempotent(self, key: str | StorageKey, content: bytes) -> StoredFile:
        """Write bytes once and reuse an existing identical file.

        If a file already exists at the deterministic key with different bytes,
        the method refuses to overwrite it. That protects SAT evidence from
        accidental mutation and surfaces hash/path collisions immediately.
        """

        storage_key = StorageKey.parse(key)
        path = self.path_for_key(storage_key)
        digest = sha256_bytes(content)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                existing = path.read_bytes()
                existing_digest = sha256_bytes(existing)
                if existing_digest != digest:
                    raise StorageCollisionError(storage_key)
                return StoredFile(
                    key=storage_key,
                    sha256=digest,
                    size_bytes=len(existing),
                    path=path,
                    written=False,
                )
            path.write_bytes(content)
        except StorageError:
            raise
        except OSError:
            raise StorageIOError(storage_key, "write") from None
        return StoredFile(
            key=storage_key,
            sha256=digest,
            size_bytes=len(content),
            path=path,
            written=True,
        )

    def read_bytes(self, key: str | StorageKey) -> bytes:
        """Read evidence bytes addressed by a validated storage key."""

        storage_key = StorageKey.parse(key)
        return self._read_bytes(storage_key, operation="read")

    def _read_bytes(self, storage_key: StorageKey, *, operation: str) -> bytes:
        try:
            return self.path_for_key(storage_key).read_bytes()
        except StorageError:
            raise
        except FileNotFoundError:
            raise StorageNotFoundError(storage_key, operation) from None
        except OSError:
            raise StorageIOError(storage_key, operation) from None

    def stat(self, key: str | StorageKey) -> EvidenceReference:
        """Return indexable metadata for stored evidence."""

        storage_key = StorageKey.parse(key)
        content = self._read_bytes(storage_key, operation="stat")
        return EvidenceReference(key=storage_key, sha256=sha256_bytes(content), size_bytes=len(content))

    def path_for_key(self, key: str | StorageKey) -> Path:
        """Resolve a storage key under the configured root."""

        storage_key = StorageKey.parse(key)
        try:
            self._reject_case_alias(storage_key)
            path = self.root.joinpath(*storage_key.parts)
            root = self.root.resolve()
            path.resolve().relative_to(root)
            return path
        except StorageError:
            raise
        except (OSError, ValueError):
            raise StorageIOError(storage_key, "resolve") from None

    def _reject_case_alias(self, key: StorageKey) -> None:
        current = self.root
        for part in key.parts:
            if not current.is_dir():
                return
            for entry in current.iterdir():
                if entry.name.casefold() == part.casefold() and entry.name != part:
                    raise StorageCollisionError(key, "case-insensitive alias", operation="resolve")
            current /= part

    def ensure_layout(self, rfc: str | None = None, period: datetime | None = None) -> tuple[Path, ...]:
        """Create the base layout and return the folders that were ensured."""

        if rfc is None:
            self.root.mkdir(parents=True, exist_ok=True)
            return (self.root,)

        safe_rfc = _safe_rfc(rfc)
        moment = period or datetime.now(timezone.utc)
        year, month = _year_month(moment)
        paths = (
            self.root / safe_rfc / "metadata" / year / month,
            self.root / safe_rfc / "packages" / year / month,
            self.root / safe_rfc / "xml" / year / month,
            self.root / safe_rfc / "logs",
            self.root / safe_rfc / "db",
            self.root / safe_rfc / "exports",
        )
        for path in paths:
            path.mkdir(parents=True, exist_ok=True)
        return paths

def _year_month(moment: datetime) -> tuple[str, str]:
    return f"{moment.year:04d}", f"{moment.month:02d}"


def _safe_rfc(value: str) -> str:
    return _safe_segment(value.upper())


def _safe_segment(value: str) -> str:
    normalized = SEGMENT_PATTERN.sub("-", value.strip()).strip(".-_")
    if not normalized:
        raise ValueError("storage path segment cannot be empty")
    return normalized
