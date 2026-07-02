"""Safe SAT package ZIP storage and extraction."""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePosixPath
import re
import struct
from typing import Protocol
from zipfile import BadZipFile, LargeZipFile, ZipFile

from cfdi_vault.storage import sha256_bytes


_ALLOWED_EXTENSIONS = {".csv", ".txt", ".xml"}
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


class PackageProcessingError(ValueError):
    """Raised when package bytes cannot be safely accepted."""


@dataclass(frozen=True)
class StoredBytes:
    """Result of an idempotent bytes write."""

    sha256: str
    size_bytes: int
    written: bool


class PackageStorage(Protocol):
    """Minimal storage port required by the package processor."""

    def write_bytes_idempotent(self, key: str, content: bytes) -> StoredBytes:
        """Write bytes once and reject mutations for an existing key."""


@dataclass(frozen=True)
class ExtractedPackageEntry:
    """A safely extracted synthetic package member."""

    name: str
    kind: str
    sha256: str
    size: int
    storage_key: str
    written: bool


@dataclass(frozen=True)
class ProcessedPackage:
    """Safe processing result for one downloaded SAT package."""

    package_id: str
    sha256: str
    size: int
    package_storage_key: str
    package_written: bool
    entries: tuple[ExtractedPackageEntry, ...]


class MemoryPackageStorage:
    """Scanner-safe in-memory storage for package processor tests and demos."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def write_bytes_idempotent(self, key: str, content: bytes) -> StoredBytes:
        digest = sha256_bytes(content)
        existing = self.objects.get(key)
        if existing is not None:
            if existing != content:
                raise ValueError(f"storage collision for {key}: existing bytes differ")
            return StoredBytes(sha256=digest, size_bytes=len(content), written=False)
        self.objects[key] = content
        return StoredBytes(sha256=digest, size_bytes=len(content), written=True)


def process_sat_package(package_id: str, content: bytes, storage: PackageStorage) -> ProcessedPackage:
    """Validate, store, and safely extract a downloaded SAT ZIP package."""

    package_sha = sha256_bytes(content)
    package_key = f"sat-packages/{_safe_key_segment(package_id)}-{package_sha[:12]}.zip"
    members = _safe_members(content)

    package_write = storage.write_bytes_idempotent(package_key, content)
    entries: list[ExtractedPackageEntry] = []
    for name, data in members:
        entry_sha = sha256_bytes(data)
        entry_key = f"sat-packages/{_safe_key_segment(package_id)}-{package_sha[:12]}/extracted/{name}"
        entry_write = storage.write_bytes_idempotent(entry_key, data)
        entries.append(
            ExtractedPackageEntry(
                name=name,
                kind=PurePosixPath(name).suffix.lstrip(".").lower(),
                sha256=entry_sha,
                size=len(data),
                storage_key=entry_key,
                written=entry_write.written,
            )
        )

    return ProcessedPackage(
        package_id=package_id,
        sha256=package_sha,
        size=len(content),
        package_storage_key=package_key,
        package_written=package_write.written,
        entries=tuple(entries),
    )


def _safe_members(content: bytes) -> tuple[tuple[str, bytes], ...]:
    _reject_raw_backslash_names(content)
    try:
        with ZipFile(BytesIO(content)) as package:
            normalized_names: set[str] = set()
            members: list[tuple[str, bytes]] = []
            for info in package.infolist():
                name = _validate_member_name(info.filename, is_dir=info.is_dir())
                duplicate_key = name.lower()
                if duplicate_key in normalized_names:
                    raise PackageProcessingError(f"duplicate ZIP entry path rejected: {name}")
                normalized_names.add(duplicate_key)
                members.append((name, package.read(info)))
            return tuple(sorted(members, key=lambda member: member[0]))
    except (BadZipFile, LargeZipFile, NotImplementedError, RuntimeError) as exc:
        raise PackageProcessingError("invalid ZIP package") from exc


def _reject_raw_backslash_names(content: bytes) -> None:
    for signature, header_size, name_offset, extra_offset in (
        (b"PK\x03\x04", 30, 26, 28),
        (b"PK\x01\x02", 46, 28, 30),
    ):
        cursor = 0
        while True:
            cursor = content.find(signature, cursor)
            if cursor < 0:
                break
            if cursor + header_size > len(content):
                return
            name_length = struct.unpack_from("<H", content, cursor + name_offset)[0]
            extra_length = struct.unpack_from("<H", content, cursor + extra_offset)[0]
            name_start = cursor + header_size
            name_end = name_start + name_length
            if name_end > len(content):
                return
            if b"\\" in content[name_start:name_end]:
                raise PackageProcessingError("backslash ZIP entry path rejected")
            cursor = name_end + extra_length


def _validate_member_name(raw_name: str, *, is_dir: bool) -> str:
    if is_dir or raw_name.endswith("/"):
        raise PackageProcessingError(f"directory ZIP entry rejected: {raw_name}")
    if "\\" in raw_name:
        raise PackageProcessingError(f"backslash ZIP entry path rejected: {raw_name}")
    if raw_name.startswith("/") or _DRIVE_PREFIX.match(raw_name):
        raise PackageProcessingError(f"absolute ZIP entry path rejected: {raw_name}")

    path = PurePosixPath(raw_name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise PackageProcessingError(f"unsafe ZIP entry path rejected: {raw_name}")
    if path.suffix.lower() not in _ALLOWED_EXTENSIONS:
        raise PackageProcessingError(f"unsupported ZIP entry extension rejected: {raw_name}")
    return path.as_posix()


def _safe_key_segment(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.=-]+", "-", value.strip()).strip(".-_")
    if not safe:
        raise PackageProcessingError("package_id cannot be empty")
    return safe
