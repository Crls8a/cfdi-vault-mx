"""Internal durable storage for opaque SAT campaign artifacts."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WINDOWS = os.name == "nt"
_ALLOWED_SUFFIXES = frozenset({".zip", ".txt", ".xml"})
_SEGMENT = re.compile(r"[a-z0-9][a-z0-9-]{0,63}").fullmatch


class ArtifactStoreError(RuntimeError):
    """Expose only a fixed, non-sensitive artifact failure reason."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    """Sanitized evidence for a durably stored artifact."""

    relative_key: str
    sha256: str
    byte_count: int


def _fail(reason: str) -> None:
    raise ArtifactStoreError(reason) from None


def _validated_root(value: str | Path) -> Path:
    if type(value) not in {str, type(Path())}:
        _fail("artifact-input-invalid")
    root = Path(value)
    if not root.is_absolute():
        _fail("artifact-root-invalid")
    try:
        resolved = root.resolve(strict=False)
        if resolved == _REPO_ROOT or resolved.is_relative_to(_REPO_ROOT):
            _fail("artifact-root-invalid")
    except (OSError, RuntimeError):
        _fail("artifact-root-invalid")
    return root


def _validated_segments(value: str) -> tuple[str, ...]:
    if type(value) is not str or "\\" in value or value.startswith("/"):
        _fail("artifact-path-invalid")
    segments = tuple(value.split("/"))
    if not segments or any(_SEGMENT(segment) is None for segment in segments):
        _fail("artifact-path-invalid")
    return segments


def _ensure_directory(root: Path, segments: tuple[str, ...]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    paths = (root, *(root.joinpath(*segments[:index]) for index in range(1, len(segments) + 1)))
    for path in paths:
        path.mkdir(exist_ok=True)
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            _fail("artifact-path-invalid")
    return paths[-1]


def _inspect(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def _fsync_directory_posix(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_artifact(
    *,
    storage_root: str | Path,
    relative_dir: str,
    ordinal: int,
    suffix: str,
    chunks: Iterable[bytes],
    max_bytes: int,
) -> StoredArtifact:
    """Stream one artifact to durable external storage and return safe evidence."""

    root = _validated_root(storage_root)
    segments = _validated_segments(relative_dir)
    if type(ordinal) is not int or ordinal <= 0:
        _fail("artifact-input-invalid")
    if type(suffix) is not str or suffix not in _ALLOWED_SUFFIXES:
        _fail("artifact-input-invalid")
    if type(max_bytes) is not int or max_bytes <= 0 or type(chunks) is bytes:
        _fail("artifact-input-invalid")

    temporary: Path | None = None
    destination: Path | None = None
    try:
        destination = _ensure_directory(root, segments)
        descriptor, raw_temporary = tempfile.mkstemp(prefix=".artifact-", dir=destination)
        temporary = Path(raw_temporary)
        digest = hashlib.sha256()
        byte_count = 0
        with os.fdopen(descriptor, "wb") as stream:
            try:
                iterator = iter(chunks)
                for chunk in iterator:
                    if type(chunk) is not bytes or not chunk:
                        _fail("artifact-input-invalid")
                    if byte_count + len(chunk) > max_bytes:
                        _fail("artifact-too-large")
                    stream.write(chunk)
                    digest.update(chunk)
                    byte_count += len(chunk)
            except ArtifactStoreError:
                raise
            except Exception:
                _fail("artifact-input-invalid")
            if byte_count == 0:
                _fail("artifact-empty")
            stream.flush()
            os.fsync(stream.fileno())

        hexdigest = digest.hexdigest()
        filename = f"{ordinal}-{hexdigest[:12]}{suffix}"
        final = destination / filename
        result = StoredArtifact("/".join((*segments, filename)), hexdigest, byte_count)
        try:
            os.link(temporary, final)
        except FileExistsError:
            final_info = os.lstat(final)
            if stat.S_ISLNK(final_info.st_mode) or not stat.S_ISREG(final_info.st_mode):
                _fail("artifact-path-invalid")
            if _inspect(final) != (byte_count, hexdigest):
                _fail("artifact-collision")
        else:
            if _inspect(final) != (byte_count, hexdigest):
                _fail("artifact-verification-failed")
        temporary.unlink()
        temporary = None
        if not _WINDOWS:
            _fsync_directory_posix(destination)
        return result
    except ArtifactStoreError:
        raise
    except OSError:
        _fail("artifact-write-failed")
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
                if destination is not None and not _WINDOWS:
                    _fsync_directory_posix(destination)
            except OSError:
                pass
