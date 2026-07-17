from __future__ import annotations

import hashlib
import json
import traceback
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipExtFile, ZipFile, ZipInfo

import pytest

import cfdi_vault.sat_metadata_package as subject
from cfdi_vault.package_processor import MemoryPackageStorage
from cfdi_vault.sat_metadata_package import MetadataPackageError, process_metadata_package

_VALID_HEADER = b"uuid~rfcEmisor~rfcReceptor~fechaEmision~estadoComprobante~tipoComprobante"
_VALID_HEADERS = ("uuid", "rfcEmisor", "rfcReceptor", "fechaEmision", "estadoComprobante", "tipoComprobante")
_CAMPAIGN = "cmp-0123456789ab"
_WORK = "work-abcdef012345"


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


def _crc_corrupted_zip(name: str) -> bytes:
    payload = b"synthetic-crc-content"
    buffer = BytesIO()
    with ZipFile(buffer, "w") as package:
        package.writestr(name, payload)
    corrupted = bytearray(buffer.getvalue())
    corrupted[corrupted.index(payload)] ^= 1
    return bytes(corrupted)


def _late_crc_corrupted_zip(name: str) -> bytes:
    payload = b"\xff" + b"x" * (1024**2 + 32)
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_STORED) as package:
        package.writestr(name, payload)
    corrupted = bytearray(buffer.getvalue())
    corrupted[corrupted.index(payload) + 1024**2 + 1] ^= 1
    return bytes(corrupted)


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


class _OnePass:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.iterations = 0

    def __iter__(self):  # type: ignore[no-untyped-def]
        self.iterations += 1
        if self.iterations != 1:
            raise AssertionError("stream consumed twice")
        yield from (bytes((value,)) for value in self.content)


def test_stores_zip_before_single_txt_and_inspects_only_structure() -> None:
    content = b"\xef\xbb\xbf" + _VALID_HEADER + b"\nsynthetic-row\n"
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
    assert result.texts[0].inspection.headers == _VALID_HEADERS
    assert result.texts[0].inspection.column_count == 6
    assert result.texts[0].inspection.records_present is True
    assert content not in json.dumps(result.redacted()).encode()


def test_multiple_txt_keys_are_deterministic_and_never_reuse_member_names() -> None:
    content = _VALID_HEADER + b"\n"
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
    package = _zip([("metadata.txt", _VALID_HEADER + b"\n")])
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
    package = _zip([(f"member-{index}.txt", _VALID_HEADER + b"\n") for index in range(count)])
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


def test_crc_failure_is_fixed_redacted_and_never_written() -> None:
    marker = "private-client-marker-209.txt"
    storage = MemoryPackageStorage()
    with pytest.raises(MetadataPackageError) as caught:
        process_metadata_package("run", 1, _crc_corrupted_zip(marker), storage)
    rendered = "".join(traceback.format_exception(caught.value))
    assert str(caught.value) == "invalid ZIP package" and caught.value.__cause__ is None
    assert marker not in rendered and "Bad CRC-32" not in rendered
    assert storage.objects == {}


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_incremental_inspector_consumes_one_byte_chunks_once(newline: bytes) -> None:
    stream = _OnePass(b"\xef\xbb\xbf" + _VALID_HEADER + newline + "synthetic-\u00e9".encode() + newline)
    result = subject._inspect_text_chunks(stream)
    assert result == subject.MetadataTextInspection("utf-8-sig", "~", _VALID_HEADERS, 6, True)
    assert stream.iterations == 1


@pytest.mark.parametrize(("tail", "records"), [(b"", False), (b"\r\n \n", False), (b"\nrow", True)])
def test_incremental_inspector_distinguishes_header_only_from_records(tail: bytes, records: bool) -> None:
    result = subject._inspect_text_chunks((_VALID_HEADER + tail,))
    assert result.headers == _VALID_HEADERS and result.records_present is records


def test_late_invalid_utf8_returns_exact_unsupported_inspection() -> None:
    result = subject._inspect_text_chunks((_VALID_HEADER + b"\nrow\n", b"\xff"))
    assert result == subject.MetadataTextInspection("unsupported_encoding", None, (), 0, False)


@pytest.mark.parametrize("delimiter", [b",", b"|", b"\t", b""])
def test_incremental_inspector_rejects_every_alternate_delimiter(delimiter: bytes) -> None:
    header = delimiter.join(_VALID_HEADER.split(b"~"))
    with pytest.raises(MetadataPackageError, match="^invalid metadata TXT structure$"):
        subject._inspect_text_chunks((header,))


@pytest.mark.parametrize(
    "header",
    [
        _VALID_HEADER + b"~UUID",
        _VALID_HEADER + b"~private-header-marker",
        _VALID_HEADER.replace(b"~tipoComprobante", b""),
        _VALID_HEADER.replace(b"~rfcReceptor", b"~~rfcReceptor"),
    ],
)
def test_invalid_headers_raise_fixed_redacted_error(header: bytes) -> None:
    with pytest.raises(MetadataPackageError) as caught:
        subject._inspect_text_chunks((header,))
    rendered = "".join(traceback.format_exception(caught.value))
    assert str(caught.value) == "invalid metadata TXT structure" and caught.value.__cause__ is None
    assert "private-header-marker" not in rendered and header.decode() not in rendered


@pytest.mark.parametrize(("offset", "accepted"), [(1, True), (0, True), (-1, False)])
def test_actual_txt_byte_budget_boundaries(offset: int, accepted: bool) -> None:
    content = _VALID_HEADER
    if accepted:
        assert subject._inspect_text_chunks((content,), max_bytes=len(content) + offset).headers == _VALID_HEADERS
    else:
        with pytest.raises(MetadataPackageError, match="^metadata TXT byte budget exceeded$"):
            subject._inspect_text_chunks((content,), max_bytes=len(content) + offset)


@pytest.mark.parametrize(("offset", "accepted"), [(1, True), (0, True), (-1, False)])
def test_header_budget_boundaries(offset: int, accepted: bool, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(subject, "_MAX_HEADER_BYTES", len(_VALID_HEADER) + offset)
    if accepted:
        assert subject._inspect_text_chunks((_VALID_HEADER,)).headers == _VALID_HEADERS
    else:
        with pytest.raises(MetadataPackageError, match="^metadata TXT header budget exceeded$"):
            subject._inspect_text_chunks((_VALID_HEADER,))


@pytest.mark.parametrize("changes", [{"chunks": b"raw"}, {"chunks": (b"",)}, {"chunks": (bytearray(b"x"),)}, {"chunks": ()}, {"max_bytes": True}, {"max_bytes": 0}, {"max_bytes": 1.0}])
def test_incremental_inspector_rejects_invalid_exact_inputs(changes: dict[str, object]) -> None:
    values: dict[str, object] = {"chunks": (_VALID_HEADER,), "max_bytes": 1024}
    values.update(changes)
    with pytest.raises(MetadataPackageError, match="^invalid metadata TXT stream$"):
        subject._inspect_text_chunks(**values)  # type: ignore[arg-type]


def test_incompatible_txt_is_inspected_before_txt_write() -> None:
    package = _zip([("metadata.txt", b"private-header-marker~unknown\nrow")])
    storage = MemoryPackageStorage()
    with pytest.raises(MetadataPackageError, match="^invalid metadata TXT structure$"):
        process_metadata_package("run", 1, package, storage)
    assert len(storage.objects) == 1
    assert next(iter(storage.objects)).endswith(".zip")


def test_single_large_source_chunk_is_subdivided_before_decode(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    real_factory = subject.codecs.getincrementaldecoder
    decode_sizes: list[int] = []

    class TrackingDecoder:
        def __init__(self) -> None:
            self.inner = real_factory("utf-8-sig")()

        def decode(self, data, final=False):  # type: ignore[no-untyped-def]
            decode_sizes.append(len(data))
            return self.inner.decode(data, final)

    monkeypatch.setattr(subject.codecs, "getincrementaldecoder", lambda _encoding: TrackingDecoder)
    content = _VALID_HEADER + b"\n" + b"x" * (4 * 1024**2 + 17)
    result = subject._inspect_text(content)
    assert result.headers == _VALID_HEADERS and result.records_present is True
    assert len(decode_sizes) > 4 and max(decode_sizes) <= 1024**2


def test_later_invalid_member_prevents_every_txt_write() -> None:
    package = _zip(
        [
            ("a-valid.txt", _VALID_HEADER + b"\nrow"),
            ("z-invalid.txt", b"private-header-marker~unknown\nrow"),
        ]
    )
    storage = MemoryPackageStorage()
    with pytest.raises(MetadataPackageError, match="^invalid metadata TXT structure$"):
        process_metadata_package("run", 1, package, storage)
    assert len(storage.objects) == 1
    assert all(key.endswith(".zip") for key in storage.objects)


def _durable(tmp_path, package: bytes, **changes):  # type: ignore[no-untyped-def]
    values = {
        "campaign_ref": _CAMPAIGN,
        "work_ref": _WORK,
        "package_ordinal": 2,
        "first_text_ordinal": 7,
        "content": package,
        "storage_root": tmp_path / "external",
    }
    values.update(changes)
    return subject.process_metadata_package_durably(**values)


def test_durable_metadata_storage_has_private_evidence_and_is_idempotent(tmp_path) -> None:  # type: ignore[no-untyped-def]
    text = _VALID_HEADER + b"\nsynthetic-row"
    package = _zip([("z-private.txt", text), ("a-private.txt", text)])
    result = _durable(tmp_path, package)
    package_hash = hashlib.sha256(package).hexdigest()
    text_hash = hashlib.sha256(text).hexdigest()
    assert result.package.relative_key == f"sat-metadata/{_CAMPAIGN}/{_WORK}/packages/2-{package_hash[:12]}.zip"
    assert [item.artifact.relative_key for item in result.texts] == [
        f"sat-metadata/{_CAMPAIGN}/{_WORK}/txt/7-{text_hash[:12]}.txt",
        f"sat-metadata/{_CAMPAIGN}/{_WORK}/txt/8-{text_hash[:12]}.txt",
    ]
    root = tmp_path / "external"
    assert (root / result.package.relative_key).read_bytes() == package
    assert all((root / item.artifact.relative_key).read_bytes() == text for item in result.texts)
    assert _durable(tmp_path, package) == result
    public = result.redacted()
    rendered = repr(result)
    assert public["zip_valid"] is True and public["txt_count"] == 2
    assert public["texts"][0]["headers"] == list(_VALID_HEADERS)
    assert "written" not in str(public)
    assert all(marker not in rendered for marker in (_CAMPAIGN, _WORK, package_hash, text_hash, str(tmp_path), "private"))


def test_durable_unsupported_encoding_is_stored(tmp_path) -> None:  # type: ignore[no-untyped-def]
    content = _VALID_HEADER + b"\n\xff"
    result = _durable(tmp_path, _zip([("metadata.txt", content)]))
    assert result.texts[0].inspection == subject.MetadataTextInspection("unsupported_encoding", None, (), 0, False)
    assert (tmp_path / "external" / result.texts[0].artifact.relative_key).read_bytes() == content


def test_durable_unsupported_encoding_still_preflights_the_full_member(tmp_path) -> None:  # type: ignore[no-untyped-def]
    package = _late_crc_corrupted_zip("private-late-crc.txt")
    with pytest.raises(MetadataPackageError, match="^invalid ZIP package$") as caught:
        _durable(tmp_path, package)
    assert caught.value.__cause__ is None
    assert not (tmp_path / "external").exists()


@pytest.mark.parametrize(
    ("package", "reason"),
    [
        (_zip([("a-valid.txt", _VALID_HEADER + b"\nrow"), ("z-private-marker.txt", b"unknown~header\nrow")]), "invalid metadata TXT structure"),
        (_crc_corrupted_zip("private-crc-marker.txt"), "invalid ZIP package"),
    ],
)
def test_durable_preflight_failure_writes_nothing(tmp_path, package: bytes, reason: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(MetadataPackageError, match=f"^{reason}$") as caught:
        _durable(tmp_path, package)
    rendered = "".join(traceback.format_exception(caught.value))
    assert "private" not in rendered and caught.value.__cause__ is None
    root = tmp_path / "external"
    assert not root.exists() or not any(root.rglob("*"))


def test_durable_path_never_uses_zipfile_read_and_bounds_every_stream(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    rows = b"".join(hashlib.sha256(str(index).encode()).hexdigest().encode() for index in range(17_000))
    content = _VALID_HEADER + b"\n" + rows
    package = _zip([("metadata.txt", content)])
    real_read = ZipExtFile.read
    real_write = subject.write_artifact
    requests: list[int] = []
    blocks: list[int] = []

    def tracked_read(stream, size=-1):  # type: ignore[no-untyped-def]
        requests.append(size)
        return real_read(stream, size)

    def tracked_write(**kwargs):  # type: ignore[no-untyped-def]
        chunks = kwargs["chunks"]
        assert iter(chunks) is chunks

        def tracked():  # type: ignore[no-untyped-def]
            for block in chunks:
                blocks.append(len(block))
                yield block

        return real_write(**{**kwargs, "chunks": tracked()})

    monkeypatch.setattr(subject.ZipFile, "read", lambda *_args: pytest.fail("ZipFile.read must not run"))
    monkeypatch.setattr(ZipExtFile, "read", tracked_read)
    monkeypatch.setattr(subject, "write_artifact", tracked_write)
    result = _durable(tmp_path, package)
    assert result.texts[0].inspection.records_present is True
    assert requests and blocks and max(requests) <= 1024**2 and max(blocks) <= 1024**2


@pytest.mark.parametrize(
    "changes",
    [
        {"campaign_ref": "cmp-ABCDEF012345"},
        {"work_ref": "work-short"},
        {"package_ordinal": True},
        {"first_text_ordinal": 0},
        {"content": bytearray(b"zip")},
    ],
)
def test_durable_inputs_are_exact_and_write_nothing(tmp_path, changes: dict[str, object]) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(MetadataPackageError, match="^invalid durable metadata package input$"):
        _durable(tmp_path, _zip([("metadata.txt", _VALID_HEADER)]), **changes)
    assert not (tmp_path / "external").exists()


def test_durable_storage_failure_is_fixed_and_redacted(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    marker = "C:/private/storage/path"
    monkeypatch.setattr(subject, "write_artifact", lambda **_kwargs: (_ for _ in ()).throw(subject.ArtifactStoreError(marker)))
    with pytest.raises(MetadataPackageError) as caught:
        _durable(tmp_path, _zip([("metadata.txt", _VALID_HEADER)]))
    rendered = "".join(traceback.format_exception(caught.value))
    assert str(caught.value) == "metadata artifact storage failed" and caught.value.__cause__ is None
    assert marker not in rendered
