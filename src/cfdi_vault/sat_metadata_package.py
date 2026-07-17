"""Internal ZIP-to-TXT processing for SAT metadata recovery evidence."""

from __future__ import annotations

import re
import stat
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePosixPath
from zipfile import BadZipFile, LargeZipFile, ZipFile, ZipInfo

from cfdi_vault.package_processor import PackageProcessingError, PackageStorage, _reject_raw_backslash_names
from cfdi_vault.storage import sha256_bytes

_RUN_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_DELIMITERS = ("~", "\t", "|", ",")
_MAX_PACKAGE_BYTES = 512 * 1024**2
_MAX_TXT_MEMBERS = 32
_MAX_TXT_FILE_BYTES = 1024**3
_MAX_TOTAL_TXT_BYTES = 2 * 1024**3
_MAX_COMPRESSION_RATIO = 200


class MetadataPackageError(ValueError):
    """Raised when a metadata package cannot be accepted safely."""


@dataclass(frozen=True)
class MetadataTextInspection:
    """Structural facts that exclude metadata rows and raw bytes."""

    encoding: str
    delimiter: str | None
    headers: tuple[str, ...]
    column_count: int
    records_present: bool


@dataclass(frozen=True)
class StoredMetadataText:
    """Private local-state evidence for one extracted TXT."""

    sha256: str
    storage_key: str
    written: bool
    inspection: MetadataTextInspection


@dataclass(frozen=True)
class ProcessedMetadataPackage:
    """Private local-state result for one safely processed metadata ZIP."""

    package_sha256: str
    package_storage_key: str
    package_written: bool
    texts: tuple[StoredMetadataText, ...]

    def redacted(self) -> dict[str, object]:
        """Return aggregate structural evidence without identifiers or content."""

        return {
            "zip_valid": True,
            "package_written": self.package_written,
            "txt_count": len(self.texts),
            "texts": [
                {
                    "written": text.written,
                    "encoding": text.inspection.encoding,
                    "delimiter": text.inspection.delimiter,
                    "headers": list(text.inspection.headers),
                    "column_count": text.inspection.column_count,
                    "records_present": text.inspection.records_present,
                }
                for text in self.texts
            ],
        }


def process_metadata_package(
    run_ref: str,
    package_ordinal: int,
    content: bytes,
    storage: PackageStorage,
) -> ProcessedMetadataPackage:
    """Validate and store a metadata ZIP before storing its TXT members."""

    if len(content) > _MAX_PACKAGE_BYTES:
        raise MetadataPackageError("metadata ZIP download budget exceeded")
    safe_run_ref = _validate_run_ref(run_ref)
    ordinal = _validate_ordinal(package_ordinal)
    package_sha = sha256_bytes(content)
    package_key = f"sat-metadata/{safe_run_ref}/packages/{ordinal}-{package_sha[:12]}.zip"

    try:
        _reject_raw_backslash_names(content)
    except PackageProcessingError:
        raise MetadataPackageError("backslash ZIP entry rejected") from None
    try:
        with ZipFile(BytesIO(content)) as package:
            members = _validated_txt_members(package)
    except MetadataPackageError:
        raise
    except (BadZipFile, LargeZipFile, NotImplementedError, RuntimeError):
        raise MetadataPackageError("invalid ZIP package") from None

    try:
        with ZipFile(BytesIO(content)) as package:
            extracted = tuple(package.read(info) for info in members)
    except (BadZipFile, LargeZipFile, NotImplementedError, RuntimeError):
        raise MetadataPackageError("invalid ZIP package") from None

    package_write = storage.write_bytes_idempotent(package_key, content)
    multiple = len(extracted) > 1
    texts: list[StoredMetadataText] = []
    for entry_ordinal, data in enumerate(extracted, start=1):
        digest = sha256_bytes(data)
        discriminator = f"{ordinal}-{entry_ordinal}" if multiple else str(ordinal)
        key = f"sat-metadata/{safe_run_ref}/txt/{discriminator}-{digest[:12]}.txt"
        write = storage.write_bytes_idempotent(key, data)
        texts.append(
            StoredMetadataText(
                sha256=digest,
                storage_key=key,
                written=write.written,
                inspection=_inspect_text(data),
            )
        )

    return ProcessedMetadataPackage(
        package_sha256=package_sha,
        package_storage_key=package_key,
        package_written=package_write.written,
        texts=tuple(texts),
    )


def _validate_run_ref(run_ref: str) -> str:
    if not isinstance(run_ref, str) or not _RUN_REF.fullmatch(run_ref):
        raise MetadataPackageError("run_ref must be an opaque safe segment")
    return run_ref


def _validate_ordinal(package_ordinal: int) -> int:
    if isinstance(package_ordinal, bool) or not isinstance(package_ordinal, int) or package_ordinal < 1:
        raise MetadataPackageError("package ordinal must be a positive integer")
    return package_ordinal


def _validated_txt_members(package: ZipFile) -> tuple[ZipInfo, ...]:
    members = package.infolist()
    if not members:
        raise MetadataPackageError("empty ZIP package")
    if len(members) > _MAX_TXT_MEMBERS:
        raise MetadataPackageError("metadata TXT member budget exceeded")

    names: set[str] = set()
    total_size = 0
    for info in members:
        name = info.filename
        path = PurePosixPath(name)
        mode = info.external_attr >> 16
        if info.is_dir() or name.endswith("/") or stat.S_ISDIR(mode):
            raise MetadataPackageError("directory ZIP entry rejected")
        if stat.S_ISLNK(mode):
            raise MetadataPackageError("symlink ZIP entry rejected")
        if "\\" in name:
            raise MetadataPackageError("backslash ZIP entry rejected")
        if name.startswith("/") or _DRIVE_PREFIX.match(name):
            raise MetadataPackageError("absolute ZIP entry rejected")
        if any(part in {"", ".", ".."} for part in path.parts):
            raise MetadataPackageError("unsafe ZIP entry rejected")
        if path.suffix.lower() != ".txt":
            raise MetadataPackageError("non-TXT ZIP entry rejected")
        duplicate_key = path.as_posix().casefold()
        if duplicate_key in names:
            raise MetadataPackageError("duplicate ZIP entry rejected")
        names.add(duplicate_key)
        if type(info.file_size) is not int or type(info.compress_size) is not int:
            raise MetadataPackageError("invalid ZIP size metadata")
        if info.file_size < 0 or info.compress_size < 0:
            raise MetadataPackageError("invalid ZIP size metadata")
        if info.file_size > _MAX_TXT_FILE_BYTES:
            raise MetadataPackageError("metadata TXT size budget exceeded")
        total_size += info.file_size
        if total_size > _MAX_TOTAL_TXT_BYTES:
            raise MetadataPackageError("metadata TXT total budget exceeded")
        if info.file_size > info.compress_size * _MAX_COMPRESSION_RATIO:
            raise MetadataPackageError("metadata TXT compression ratio exceeded")

    return tuple(sorted(members, key=lambda info: info.filename.casefold()))


def _inspect_text(content: bytes) -> MetadataTextInspection:
    try:
        decoded = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return MetadataTextInspection("unsupported_encoding", None, (), 0, False)

    lines = decoded.splitlines()
    if not lines or not lines[0].strip():
        return MetadataTextInspection("utf-8-sig", None, (), 0, any(line.strip() for line in lines[1:]))
    header = lines[0]
    delimiter = next((candidate for candidate in _DELIMITERS if candidate in header), None)
    headers = tuple(part.strip() for part in header.split(delimiter)) if delimiter else (header.strip(),)
    return MetadataTextInspection(
        encoding="utf-8-sig",
        delimiter=delimiter,
        headers=headers,
        column_count=len(headers),
        records_present=any(line.strip() for line in lines[1:]),
    )
