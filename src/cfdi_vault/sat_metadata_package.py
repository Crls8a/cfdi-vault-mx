"""Internal ZIP-to-TXT processing for SAT metadata recovery evidence."""

from __future__ import annotations

import codecs
import hashlib
import re
import stat
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator
from zipfile import BadZipFile, LargeZipFile, ZipFile, ZipInfo

from cfdi_vault.metadata_parser import FIELD_ALIASES, REQUIRED_METADATA_FIELDS
from cfdi_vault.package_processor import PackageProcessingError, PackageStorage, _reject_raw_backslash_names
from cfdi_vault.sat_artifact_store import ArtifactStoreError, StoredArtifact, write_artifact
from cfdi_vault.storage import sha256_bytes

_RUN_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_CAMPAIGN_REF = re.compile(r"cmp-[0-9a-f]{12}").fullmatch
_WORK_REF = re.compile(r"work-[0-9a-f]{12}").fullmatch
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_MAX_PACKAGE_BYTES = 512 * 1024**2
_MAX_TXT_MEMBERS = 32
_MAX_TXT_FILE_BYTES = 1024**3
_MAX_TOTAL_TXT_BYTES = 2 * 1024**3
_MAX_COMPRESSION_RATIO = 200
_MAX_HEADER_BYTES = 1024**2
_DECODE_WINDOW_BYTES = 1024**2
_IO_BLOCK_BYTES = 1024**2


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


def _redacted_inspection(inspection: MetadataTextInspection) -> dict[str, object]:
    return {
        "encoding": inspection.encoding,
        "delimiter": inspection.delimiter,
        "headers": list(inspection.headers),
        "column_count": inspection.column_count,
        "records_present": inspection.records_present,
    }


@dataclass(frozen=True, slots=True, repr=False)
class DurableMetadataText:
    """Private durable evidence for one streamed metadata TXT."""

    artifact: StoredArtifact
    inspection: MetadataTextInspection

    def redacted(self) -> dict[str, object]:
        """Return structural evidence without durable identifiers."""

        return _redacted_inspection(self.inspection)

    def __repr__(self) -> str:
        return f"DurableMetadataText({self.redacted()!r})"


@dataclass(frozen=True, slots=True, repr=False)
class DurableMetadataPackage:
    """Private durable result for a preflighted metadata package."""

    package: StoredArtifact
    texts: tuple[DurableMetadataText, ...]

    def redacted(self) -> dict[str, object]:
        """Return aggregate structural evidence without durable identifiers."""

        return {
            "zip_valid": True,
            "txt_count": len(self.texts),
            "texts": [text.redacted() for text in self.texts],
        }

    def __repr__(self) -> str:
        return f"DurableMetadataPackage({self.redacted()!r})"


@dataclass(frozen=True, slots=True)
class _MemberEvidence:
    sha256: str
    byte_count: int


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
    inspections = tuple(_inspect_text(data) for data in extracted)
    texts: list[StoredMetadataText] = []
    for entry_ordinal, (data, inspection) in enumerate(zip(extracted, inspections), start=1):
        digest = sha256_bytes(data)
        discriminator = f"{ordinal}-{entry_ordinal}" if multiple else str(ordinal)
        key = f"sat-metadata/{safe_run_ref}/txt/{discriminator}-{digest[:12]}.txt"
        write = storage.write_bytes_idempotent(key, data)
        texts.append(
            StoredMetadataText(
                sha256=digest,
                storage_key=key,
                written=write.written,
                inspection=inspection,
            )
        )

    return ProcessedMetadataPackage(
        package_sha256=package_sha,
        package_storage_key=package_key,
        package_written=package_write.written,
        texts=tuple(texts),
    )


def process_metadata_package_durably(
    *,
    campaign_ref: str,
    work_ref: str,
    package_ordinal: int,
    first_text_ordinal: int,
    content: bytes,
    storage_root: str | Path,
) -> DurableMetadataPackage:
    """Preflight every TXT, then stream the package and members durably."""

    if (
        type(campaign_ref) is not str
        or _CAMPAIGN_REF(campaign_ref) is None
        or type(work_ref) is not str
        or _WORK_REF(work_ref) is None
        or type(package_ordinal) is not int
        or package_ordinal <= 0
        or type(first_text_ordinal) is not int
        or first_text_ordinal <= 0
        or type(content) is not bytes
    ):
        raise MetadataPackageError("invalid durable metadata package input") from None
    if len(content) > _MAX_PACKAGE_BYTES:
        raise MetadataPackageError("metadata ZIP download budget exceeded") from None

    try:
        _reject_raw_backslash_names(content)
    except PackageProcessingError:
        raise MetadataPackageError("backslash ZIP entry rejected") from None
    try:
        with ZipFile(BytesIO(content)) as package:
            members = _validated_txt_members(package)
            preflighted = tuple(_preflight_member(package, info) for info in members)
    except MetadataPackageError:
        raise
    except (BadZipFile, LargeZipFile, NotImplementedError, RuntimeError, OSError):
        raise MetadataPackageError("invalid ZIP package") from None

    relative_base = f"sat-metadata/{campaign_ref}/{work_ref}"
    try:
        package_artifact = write_artifact(
            storage_root=storage_root,
            relative_dir=f"{relative_base}/packages",
            ordinal=package_ordinal,
            suffix=".zip",
            chunks=_bytes_chunks(content),
            max_bytes=_MAX_PACKAGE_BYTES,
        )
        texts: list[DurableMetadataText] = []
        with ZipFile(BytesIO(content)) as package:
            for index, (info, (inspection, expected)) in enumerate(zip(members, preflighted)):
                artifact = write_artifact(
                    storage_root=storage_root,
                    relative_dir=f"{relative_base}/txt",
                    ordinal=first_text_ordinal + index,
                    suffix=".txt",
                    chunks=_member_chunks(package, info, expected=expected),
                    max_bytes=_MAX_TXT_FILE_BYTES,
                )
                if (artifact.sha256, artifact.byte_count) != (expected.sha256, expected.byte_count):
                    raise MetadataPackageError("metadata artifact storage failed") from None
                texts.append(DurableMetadataText(artifact, inspection))
    except ArtifactStoreError:
        raise MetadataPackageError("metadata artifact storage failed") from None
    except MetadataPackageError:
        raise
    except (BadZipFile, LargeZipFile, NotImplementedError, RuntimeError, OSError):
        raise MetadataPackageError("invalid ZIP package") from None
    return DurableMetadataPackage(package_artifact, tuple(texts))


def _bytes_chunks(content: bytes) -> Iterator[bytes]:
    for start in range(0, len(content), _IO_BLOCK_BYTES):
        yield content[start : start + _IO_BLOCK_BYTES]


def _member_chunks(
    package: ZipFile,
    info: ZipInfo,
    *,
    captured: list[_MemberEvidence] | None = None,
    expected: _MemberEvidence | None = None,
) -> Iterator[bytes]:
    digest = hashlib.sha256()
    actual_size = 0
    try:
        with package.open(info) as stream:
            while block := stream.read(_IO_BLOCK_BYTES):
                if type(block) is not bytes or len(block) > _IO_BLOCK_BYTES:
                    raise MetadataPackageError("invalid ZIP package") from None
                actual_size += len(block)
                if actual_size > info.file_size:
                    raise MetadataPackageError("invalid ZIP package") from None
                digest.update(block)
                yield block
        evidence = _MemberEvidence(digest.hexdigest(), actual_size)
        if actual_size != info.file_size or (expected is not None and evidence != expected):
            raise MetadataPackageError("invalid ZIP package") from None
        if captured is not None:
            captured.append(evidence)
    except MetadataPackageError:
        raise
    except (BadZipFile, LargeZipFile, NotImplementedError, RuntimeError, OSError):
        raise MetadataPackageError("invalid ZIP package") from None


def _preflight_member(package: ZipFile, info: ZipInfo) -> tuple[MetadataTextInspection, _MemberEvidence]:
    evidence: list[_MemberEvidence] = []
    chunks = _member_chunks(package, info, captured=evidence)
    inspection = _inspect_text_chunks(chunks)
    for _remaining in chunks:
        pass
    if len(evidence) != 1:
        raise MetadataPackageError("invalid ZIP package") from None
    return inspection, evidence[0]


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


def _inspect_text_chunks(
    chunks: Iterable[bytes], *, max_bytes: int = _MAX_TXT_FILE_BYTES
) -> MetadataTextInspection:
    """Inspect bounded UTF-8 metadata structure without retaining row text."""

    if type(max_bytes) is not int or max_bytes <= 0 or type(chunks) is bytes:
        raise MetadataPackageError("invalid metadata TXT stream") from None
    decoder = codecs.getincrementaldecoder("utf-8-sig")()
    header_parts: list[str] = []
    header_complete = False
    counting_header = True
    records_present = False
    total_bytes = 0
    header_bytes = 0
    seen = False

    def consume(decoded: str) -> None:
        nonlocal header_complete, records_present
        if header_complete:
            records_present = records_present or any(not char.isspace() for char in decoded)
            return
        for index, char in enumerate(decoded):
            if char not in "\r\n":
                continue
            header_parts.append(decoded[:index])
            header_complete = True
            records_present = any(not decoded[position].isspace() for position in range(index + 1, len(decoded)))
            return
        header_parts.append(decoded)

    try:
        for chunk in chunks:
            seen = True
            if type(chunk) is not bytes or not chunk:
                raise MetadataPackageError("invalid metadata TXT stream") from None
            total_bytes += len(chunk)
            if total_bytes > max_bytes:
                raise MetadataPackageError("metadata TXT byte budget exceeded") from None
            if counting_header:
                positions = tuple(position for position in (chunk.find(b"\r"), chunk.find(b"\n")) if position >= 0)
                header_bytes += min(positions) if positions else len(chunk)
                if header_bytes > _MAX_HEADER_BYTES:
                    raise MetadataPackageError("metadata TXT header budget exceeded") from None
                counting_header = not positions
            view = memoryview(chunk)
            for start in range(0, len(view), _DECODE_WINDOW_BYTES):
                consume(decoder.decode(view[start : start + _DECODE_WINDOW_BYTES]))
        consume(decoder.decode(b"", final=True))
    except UnicodeDecodeError:
        return MetadataTextInspection("unsupported_encoding", None, (), 0, False)
    except MetadataPackageError:
        raise
    except Exception:
        raise MetadataPackageError("invalid metadata TXT stream") from None
    if not seen:
        raise MetadataPackageError("invalid metadata TXT stream") from None

    header = "".join(header_parts)
    headers = tuple(part.strip() for part in header.split("~")) if "~" in header else ()
    normalized = tuple(value.casefold() for value in headers)
    known = {alias.casefold() for aliases in FIELD_ALIASES.values() for alias in aliases}
    compatible = (
        headers
        and all(headers)
        and len(set(normalized)) == len(normalized)
        and all(value in known for value in normalized)
        and all(any(alias.casefold() in normalized for alias in FIELD_ALIASES[field]) for field in REQUIRED_METADATA_FIELDS)
    )
    if not compatible:
        raise MetadataPackageError("invalid metadata TXT structure") from None
    return MetadataTextInspection("utf-8-sig", "~", headers, len(headers), records_present)


def _inspect_text(content: bytes) -> MetadataTextInspection:
    """Inspect one in-memory TXT through the bounded incremental path."""

    return _inspect_text_chunks((content,))
