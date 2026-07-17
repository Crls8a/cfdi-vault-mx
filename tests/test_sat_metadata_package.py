from __future__ import annotations

import hashlib
import json
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest

import cfdi_vault.sat_metadata_package as subject
from cfdi_vault.package_processor import MemoryPackageStorage
from cfdi_vault.sat_metadata_package import MetadataPackageError, process_metadata_package


def _zip(entries: list[tuple[str | ZipInfo, bytes]]) -> bytes:
    buffer = BytesIO()
    rewrites: list[tuple[bytes, bytes]] = []
    with ZipFile(buffer, "w", ZIP_DEFLATED) as package:
        for name, content in entries:
            zip_name = name
            if isinstance(name, str) and "\\" in name:
                zip_name = name.replace("\\", "/")
                rewrites.append((zip_name.encode(), name.encode()))
            package.writestr(zip_name, content)
    data = buffer.getvalue()
    for safe_name, raw_name in rewrites:
        data = data.replace(safe_name, raw_name)
    return data


def _info(name: str, size: int, compressed: int) -> ZipInfo:
    info = ZipInfo(name)
    info.file_size = size
    info.compress_size = compressed
    return info


class _Package:
    def __init__(self, members: list[ZipInfo]) -> None:
        self.members = members

    def infolist(self) -> list[ZipInfo]:
        return self.members

    def __enter__(self) -> _Package:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _info: ZipInfo) -> bytes:
        raise AssertionError("package.read must not run")


def test_stores_zip_before_single_txt_and_inspects_only_structure() -> None:
    content = b"\xef\xbb\xbfVersion~Status\n1~Synthetic\n"
    package = _zip([("private/member-name.txt", content)])
    storage = MemoryPackageStorage()
    writes: list[str] = []
    original_write = storage.write_bytes_idempotent

    def recording_write(key: str, data: bytes):  # type: ignore[no-untyped-def]
        writes.append(key)
        return original_write(key, data)

    storage.write_bytes_idempotent = recording_write  # type: ignore[method-assign]
    result = process_metadata_package("run_alpha-1", 2, package, storage)

    package_sha = hashlib.sha256(package).hexdigest()
    txt_sha = hashlib.sha256(content).hexdigest()
    assert writes == [
        f"sat-metadata/run_alpha-1/packages/2-{package_sha[:12]}.zip",
        f"sat-metadata/run_alpha-1/txt/2-{txt_sha[:12]}.txt",
    ]
    repeated = process_metadata_package("run_alpha-1", 2, package, storage)
    assert result.package_sha256 == package_sha
    assert result.texts[0].sha256 == txt_sha
    assert repeated.package_written is False
    assert repeated.texts[0].written is False
    assert result.texts[0].inspection.encoding == "utf-8-sig"
    assert result.texts[0].inspection.delimiter == "~"
    assert result.texts[0].inspection.headers == ("Version", "Status")
    assert result.texts[0].inspection.column_count == 2
    assert result.texts[0].inspection.records_present is True
    assert content not in json.dumps(result.redacted()).encode()


def test_multiple_txt_keys_are_deterministic_and_never_reuse_member_names() -> None:
    content = b"Column\n"
    package = _zip([("zeta-secret.txt", content), ("nested/alpha-secret.TXT", content)])
    storage = MemoryPackageStorage()

    result = process_metadata_package("opaque", 1, package, storage)

    digest = hashlib.sha256(content).hexdigest()[:12]
    text_keys = [text.storage_key for text in result.texts]
    assert text_keys == [
        f"sat-metadata/opaque/txt/1-1-{digest}.txt",
        f"sat-metadata/opaque/txt/1-2-{digest}.txt",
    ]
    assert all("secret" not in key for key in storage.objects)
    assert result.redacted()["txt_count"] == 2


@pytest.mark.parametrize("run_ref", ["", "../run", "/run", "C:/run", "run\\child", "run child"])
def test_rejects_unsafe_run_ref_without_writes(run_ref: str) -> None:
    storage = MemoryPackageStorage()

    with pytest.raises(MetadataPackageError, match="run_ref"):
        process_metadata_package(run_ref, 1, _zip([("metadata.txt", b"Header\n")]), storage)

    assert storage.objects == {}


@pytest.mark.parametrize("ordinal", [0, -1, True])
def test_rejects_invalid_package_ordinal_without_writes(ordinal: int) -> None:
    storage = MemoryPackageStorage()

    with pytest.raises(MetadataPackageError, match="ordinal"):
        process_metadata_package("run", ordinal, _zip([("metadata.txt", b"Header\n")]), storage)

    assert storage.objects == {}


@pytest.mark.parametrize(
    "member",
    ["../metadata.txt", "/metadata.txt", "C:/metadata.txt", "nested\\metadata.txt", "metadata.xml"],
)
def test_rejects_unsafe_or_non_txt_member_without_writes(member: str) -> None:
    storage = MemoryPackageStorage()

    with pytest.raises(MetadataPackageError):
        process_metadata_package("run", 1, _zip([(member, b"Header\n")]), storage)

    assert storage.objects == {}


def test_rejects_directories_symlinks_and_case_insensitive_duplicates() -> None:
    directory = ZipInfo("nested/")
    symlink = ZipInfo("link.txt")
    symlink.create_system = 3
    symlink.external_attr = 0o120777 << 16
    archives = [
        _zip([(directory, b"")]),
        _zip([(symlink, b"target")]),
        _zip([("metadata.txt", b"one"), ("METADATA.TXT", b"two")]),
    ]

    for package in archives:
        storage = MemoryPackageStorage()
        with pytest.raises(MetadataPackageError):
            process_metadata_package("run", 1, package, storage)
        assert storage.objects == {}


@pytest.mark.parametrize("package", [b"not-a-zip", _zip([])])
def test_rejects_corrupt_or_empty_package_without_writes(package: bytes) -> None:
    storage = MemoryPackageStorage()

    with pytest.raises(MetadataPackageError):
        process_metadata_package("run", 1, package, storage)

    assert storage.objects == {}


def test_unsupported_encoding_is_stored_without_guessing_or_row_output() -> None:
    content = b"Header~State\n\xff~private-row\n"
    storage = MemoryPackageStorage()

    result = process_metadata_package("run", 1, _zip([("metadata.txt", content)]), storage)

    inspection = result.texts[0].inspection
    assert inspection.encoding == "unsupported_encoding"
    assert inspection.delimiter is None
    assert inspection.headers == ()
    assert inspection.column_count == 0
    assert inspection.records_present is False
    serialized = json.dumps(result.redacted(), sort_keys=True)
    assert "private-row" not in serialized
    assert result.package_sha256 not in serialized
    assert result.package_storage_key not in serialized
    assert result.texts[0].sha256 not in serialized
    assert result.texts[0].storage_key not in serialized
    assert "run" not in serialized


@pytest.mark.parametrize(("limit_offset", "accepted"), [(1, True), (0, True), (-1, False)])
def test_package_download_budget_boundaries_without_large_allocation(
    limit_offset: int, accepted: bool, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    package = _zip([("metadata.txt", b"Header\n")])
    monkeypatch.setattr(subject, "_MAX_PACKAGE_BYTES", len(package) + limit_offset)
    storage = MemoryPackageStorage()
    if accepted:
        process_metadata_package("run", 1, package, storage)
    else:
        with pytest.raises(MetadataPackageError, match="^metadata ZIP download budget exceeded$"):
            process_metadata_package("run", 1, package, storage)
    assert len(storage.objects) == (2 if accepted else 0)


@pytest.mark.parametrize(("count", "accepted"), [(31, True), (32, True), (33, False)])
def test_txt_member_count_boundaries_precede_writes(count: int, accepted: bool) -> None:
    package = _zip([(f"member-{index}.txt", b"Header\n") for index in range(count)])
    storage = MemoryPackageStorage()
    if accepted:
        process_metadata_package("run", 1, package, storage)
    else:
        with pytest.raises(MetadataPackageError, match="^metadata TXT member budget exceeded$"):
            process_metadata_package("run", 1, package, storage)
    assert len(storage.objects) == (count + 1 if accepted else 0)


@pytest.mark.parametrize(
    ("size", "accepted"),
    [(1024**3 - 1, True), (1024**3, True), (1024**3 + 1, False)],
)
def test_declared_member_size_boundaries(size: int, accepted: bool) -> None:
    package = _Package([_info("metadata.txt", size, max(1, size))])
    if accepted:
        assert subject._validated_txt_members(package)  # type: ignore[arg-type]
    else:
        with pytest.raises(MetadataPackageError, match="^metadata TXT size budget exceeded$"):
            subject._validated_txt_members(package)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("sizes", "accepted"),
    [((1024**3, 1024**3 - 1), True), ((1024**3, 1024**3), True), ((1024**3, 1024**3, 1), False)],
)
def test_aggregate_declared_size_boundaries(sizes: tuple[int, ...], accepted: bool) -> None:
    package = _Package([_info(f"member-{index}.txt", size, size) for index, size in enumerate(sizes)])
    if accepted:
        assert len(subject._validated_txt_members(package)) == len(sizes)  # type: ignore[arg-type]
    else:
        with pytest.raises(MetadataPackageError, match="^metadata TXT total budget exceeded$"):
            subject._validated_txt_members(package)  # type: ignore[arg-type]


@pytest.mark.parametrize(("size", "compressed", "accepted"), [(199, 1, True), (200, 1, True), (201, 1, False)])
def test_compression_ratio_boundaries_are_integer_safe(size: int, compressed: int, accepted: bool) -> None:
    package = _Package([_info("metadata.txt", size, compressed)])
    if accepted:
        assert subject._validated_txt_members(package)  # type: ignore[arg-type]
    else:
        with pytest.raises(MetadataPackageError, match="^metadata TXT compression ratio exceeded$"):
            subject._validated_txt_members(package)  # type: ignore[arg-type]


@pytest.mark.parametrize(("size", "accepted"), [(0, True), (1, False)])
def test_zero_compressed_size_does_not_divide(size: int, accepted: bool) -> None:
    package = _Package([_info("metadata.txt", size, 0)])
    if accepted:
        assert subject._validated_txt_members(package)  # type: ignore[arg-type]
    else:
        with pytest.raises(MetadataPackageError, match="compression ratio"):
            subject._validated_txt_members(package)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["file_size", "compress_size"])
@pytest.mark.parametrize("value", [True, 1.5, -12345])
def test_invalid_zip_size_metadata_is_fixed_and_redacted(field: str, value: object) -> None:
    info = _info("private-member.txt", 1, 1)
    setattr(info, field, value)
    with pytest.raises(MetadataPackageError) as caught:
        subject._validated_txt_members(_Package([info]))  # type: ignore[arg-type]
    assert str(caught.value) == "invalid ZIP size metadata"
    assert "private-member" not in str(caught.value) and "12345" not in str(caught.value)


@pytest.mark.parametrize("case", ["members", "ratio"])
def test_member_budget_rejection_precedes_storage_and_read(case: str, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    members = (
        [_info(f"member-{index}.txt", 1, 1) for index in range(33)]
        if case == "members"
        else [_info("metadata.txt", 201, 1)]
    )
    fake = _Package(members)
    monkeypatch.setattr(subject, "ZipFile", lambda _content: fake)
    storage = MemoryPackageStorage()
    with pytest.raises(MetadataPackageError):
        process_metadata_package("run", 1, _zip([("metadata.txt", b"Header\n")]), storage)
    assert storage.objects == {}


def test_package_budget_rejection_precedes_zip_parsing_and_storage(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(subject, "_MAX_PACKAGE_BYTES", 1)
    monkeypatch.setattr(subject, "_reject_raw_backslash_names", lambda _content: pytest.fail("ZIP parsing must not run"))
    storage = MemoryPackageStorage()
    with pytest.raises(MetadataPackageError, match="download budget"):
        process_metadata_package("run", 1, b"xx", storage)
    assert storage.objects == {}
