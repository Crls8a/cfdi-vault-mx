from __future__ import annotations

import hashlib
import os
import stat
import traceback
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import cfdi_vault.sat_artifact_store as subject


def _args(tmp_path: Path, **changes):  # type: ignore[no-untyped-def]
    values = {
        "storage_root": tmp_path / "external",
        "relative_dir": "sat-metadata/campaign/work/packages",
        "ordinal": 1,
        "suffix": ".zip",
        "chunks": (b"abc", b"def"),
        "max_bytes": 6,
    }
    values.update(changes)
    return values


class _OnePass:
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self.chunks, self.iterations = chunks, 0

    def __iter__(self):  # type: ignore[no-untyped-def]
        self.iterations += 1
        if self.iterations != 1:
            raise AssertionError("iterated twice")
        yield from self.chunks


def test_write_streams_once_hashes_and_returns_only_relative_evidence(tmp_path: Path) -> None:
    chunks = _OnePass((b"abc", b"def"))
    result = subject.write_artifact(**_args(tmp_path, chunks=chunks))
    digest = hashlib.sha256(b"abcdef").hexdigest()
    expected = f"sat-metadata/campaign/work/packages/1-{digest[:12]}.zip"

    assert result == subject.StoredArtifact(expected, digest, 6)
    assert chunks.iterations == 1
    assert (tmp_path / "external" / Path(expected)).read_bytes() == b"abcdef"
    assert str(tmp_path) not in repr(result)
    with pytest.raises(FrozenInstanceError):
        result.byte_count = 7  # type: ignore[misc]


def test_existing_identical_is_idempotent_and_different_content_collides(tmp_path: Path) -> None:
    first = subject.write_artifact(**_args(tmp_path))
    path = tmp_path / "external" / Path(first.relative_key)
    before = path.stat().st_mtime_ns

    assert subject.write_artifact(**_args(tmp_path)) == first
    assert path.read_bytes() == b"abcdef" and path.stat().st_mtime_ns == before
    path.write_bytes(b"tampered")
    with pytest.raises(subject.ArtifactStoreError, match="^artifact-collision$"):
        subject.write_artifact(**_args(tmp_path))
    assert path.read_bytes() == b"tampered"


def test_concurrent_different_winner_is_never_overwritten(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    digest = hashlib.sha256(b"abcdef").hexdigest()
    destination = tmp_path / "external/sat-metadata/campaign/work/packages"
    final = destination / f"1-{digest[:12]}.zip"
    winner = b"concurrent-winner"

    def race(_source, target):  # type: ignore[no-untyped-def]
        Path(target).write_bytes(winner)
        raise FileExistsError

    monkeypatch.setattr(subject.os, "link", race)
    with pytest.raises(subject.ArtifactStoreError, match="^artifact-collision$"):
        subject.write_artifact(**_args(tmp_path))
    assert final.read_bytes() == winner
    assert not any(path.name.startswith(".artifact-") for path in destination.iterdir())


def test_rejects_noncanonical_exact_inputs_before_artifact_visibility(tmp_path: Path) -> None:
    class Text(str):
        pass

    class Blob(bytes):
        pass

    invalid = (
        {"storage_root": Path("relative")},
        {"storage_root": Path(__file__).resolve().parents[1] / "private"},
        *({"relative_dir": value} for value in ("", "/abs", "../x", "a/../b", "a\\b", "a//b", "./a", "A", "a_b")),
        *({"ordinal": value} for value in (True, 0, -1, 1.0)),
        *({"suffix": value} for value in (".pdf", ".ZIP", Text(".zip"))),
        *({"max_bytes": value} for value in (True, 0, -1, 1.0)),
        *({"chunks": value} for value in ((b"",), (bytearray(b"x"),), ("x",), (Blob(b"x"),), b"x")),
    )
    for changes in invalid:
        with pytest.raises(subject.ArtifactStoreError):
            subject.write_artifact(**_args(tmp_path, **changes))
    assert not any((tmp_path / "external").rglob("*.zip"))


def test_symlink_loop_root_error_is_typed_and_redacted(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    marker = "C:/private/taxpayer/symlink-loop"
    monkeypatch.setattr(subject.Path, "resolve", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(marker)))
    with pytest.raises(subject.ArtifactStoreError) as caught:
        subject.write_artifact(**_args(tmp_path))
    rendered = "".join(traceback.format_exception(caught.value))
    assert caught.value.reason == "artifact-root-invalid" and caught.value.__cause__ is None
    assert marker not in rendered


@pytest.mark.parametrize(
    ("chunks", "limit", "reason"),
    [([], 1, "artifact-empty"), ([b"ab", b"cd"], 3, "artifact-too-large")],
)
def test_empty_or_over_budget_stream_cleans_temporary_file(
    tmp_path: Path, chunks, limit: int, reason: str,  # type: ignore[no-untyped-def]
) -> None:
    destination = tmp_path / "external/sat-metadata/campaign/work/packages"
    with pytest.raises(subject.ArtifactStoreError, match=f"^{reason}$"):
        subject.write_artifact(**_args(tmp_path, chunks=chunks, max_bytes=limit))
    assert destination.is_dir()
    assert list(destination.iterdir()) == []


def test_rejects_synthetic_symlink_escape_without_writing(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    root = tmp_path / "external"
    root.mkdir()
    original = subject.os.lstat

    def linked(path):  # type: ignore[no-untyped-def]
        info = original(path)
        if Path(path).name == "sat-metadata":
            return os.stat_result((stat.S_IFLNK,) + tuple(info)[1:])
        return info

    monkeypatch.setattr(subject.os, "lstat", linked)
    with pytest.raises(subject.ArtifactStoreError, match="^artifact-path-invalid$"):
        subject.write_artifact(**_args(tmp_path))
    assert not any(root.rglob("*.zip"))


def test_rejects_existing_final_symlink_instead_of_following_it(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    stored = subject.write_artifact(**_args(tmp_path))
    final = tmp_path / "external" / Path(stored.relative_key)
    original = subject.os.lstat

    def linked(path):  # type: ignore[no-untyped-def]
        info = original(path)
        if Path(path) == final:
            return os.stat_result((stat.S_IFLNK,) + tuple(info)[1:])
        return info

    monkeypatch.setattr(subject.os, "lstat", linked)
    with pytest.raises(subject.ArtifactStoreError, match="^artifact-path-invalid$"):
        subject.write_artifact(**_args(tmp_path))


def test_windows_skips_directory_sync_but_posix_performs_it(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    directory_syncs = []
    links, file_syncs = [], []
    real_link, real_fsync = subject.os.link, subject.os.fsync
    monkeypatch.setattr(subject, "_fsync_directory_posix", lambda path: directory_syncs.append(path))
    monkeypatch.setattr(subject.os, "link", lambda source, target: (links.append(target), real_link(source, target))[1])
    monkeypatch.setattr(subject.os, "fsync", lambda descriptor: (file_syncs.append(descriptor), real_fsync(descriptor))[1])

    monkeypatch.setattr(subject, "_WINDOWS", True)
    subject.write_artifact(**_args(tmp_path, ordinal=1))
    assert len(links) == len(file_syncs) == 1 and directory_syncs == []
    monkeypatch.setattr(subject, "_WINDOWS", False)
    subject.write_artifact(**_args(tmp_path, ordinal=2))
    assert len(links) == len(file_syncs) == 2
    assert directory_syncs == [tmp_path / "external/sat-metadata/campaign/work/packages"]


def test_oserror_is_redacted_and_cleans_temp(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    marker = "C:/private/taxpayer/artifact.zip"
    monkeypatch.setattr(subject.os, "link", lambda *_args: (_ for _ in ()).throw(PermissionError(marker)))
    with pytest.raises(subject.ArtifactStoreError) as caught:
        subject.write_artifact(**_args(tmp_path))
    rendered = "".join(traceback.format_exception(caught.value))
    destination = tmp_path / "external/sat-metadata/campaign/work/packages"
    assert caught.value.reason == "artifact-write-failed" and caught.value.__cause__ is None
    assert marker not in rendered and list(destination.iterdir()) == []
