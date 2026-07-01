"""Local storage resolver for SAT metadata, packages, XML evidence, and exports."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re


SEGMENT_PATTERN = re.compile(r"[^A-Za-z0-9_.=-]+")


@dataclass(frozen=True)
class StoredFile:
    """Result of an idempotent local write."""

    path: Path
    sha256: str
    size_bytes: int
    written: bool


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

        return self._period_key(
            rfc,
            "metadata",
            period,
            f"{_safe_segment(id_solicitud)}-{_safe_segment(sha256[:12])}.{_safe_segment(extension.lstrip('.'))}",
        )

    def package_key(self, rfc: str, period: datetime, id_paquete: str, sha256: str) -> str:
        """Build a deterministic key for a SAT package ZIP."""

        return self._period_key(
            rfc,
            "packages",
            period,
            f"{_safe_segment(id_paquete)}-{_safe_segment(sha256[:12])}.zip",
        )

    def xml_key(self, rfc: str, issue_date: datetime, uuid: str, sha256: str) -> str:
        """Build a deterministic key for extracted XML evidence."""

        return self._period_key(
            rfc,
            "xml",
            issue_date,
            f"{_safe_segment(uuid.upper())}-{_safe_segment(sha256[:12])}.xml",
        )

    def write_bytes(self, key: str, content: bytes) -> str:
        """Store bytes and return a storage reference.

        This method keeps the port-compatible overwrite behavior. Recovery code
        should prefer ``write_bytes_idempotent`` for SAT evidence.
        """

        path = self.path_for_key(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return str(path)

    def write_bytes_idempotent(self, key: str, content: bytes) -> StoredFile:
        """Write bytes once and reuse an existing identical file.

        If a file already exists at the deterministic key with different bytes,
        the method refuses to overwrite it. That protects SAT evidence from
        accidental mutation and surfaces hash/path collisions immediately.
        """

        path = self.path_for_key(key)
        digest = sha256_bytes(content)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            existing = path.read_bytes()
            existing_digest = sha256_bytes(existing)
            if existing_digest != digest:
                raise ValueError(f"storage collision for {path}: existing SHA-256 differs")
            return StoredFile(path=path, sha256=digest, size_bytes=len(existing), written=False)
        path.write_bytes(content)
        return StoredFile(path=path, sha256=digest, size_bytes=len(content), written=True)

    def path_for_key(self, key: str) -> Path:
        """Resolve a storage key under the configured root."""

        safe_key = key.replace("\\", "/").lstrip("/")
        path = self.root / safe_key
        root = self.root.resolve()
        resolved_parent = path.parent.resolve()
        resolved_parent.relative_to(root)
        return path

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

    def _period_key(self, rfc: str, family: str, period: datetime, filename: str) -> str:
        self.ensure_layout(rfc, period)
        year, month = _year_month(period)
        return "/".join((_safe_rfc(rfc), family, year, month, filename))


def _year_month(moment: datetime) -> tuple[str, str]:
    return f"{moment.year:04d}", f"{moment.month:02d}"


def _safe_rfc(value: str) -> str:
    return _safe_segment(value.upper())


def _safe_segment(value: str) -> str:
    normalized = SEGMENT_PATTERN.sub("-", value.strip()).strip(".-_")
    if not normalized:
        raise ValueError("storage path segment cannot be empty")
    return normalized
