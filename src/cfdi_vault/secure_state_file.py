"""Internal canonical, locked, atomic storage for opaque local state bytes."""

from __future__ import annotations

import os
import re
import stat
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

_REPO_ROOT = Path(__file__).resolve().parents[2]
_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_LOCK_NAME = ".secure-state-file.lock"


class SecureStateFileError(ValueError):
    """Report filesystem failures with a sanitized reason only."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, repr=False)
class _SecureStateTransaction:
    path: Path

    def read(self) -> bytes | None:
        return _read(self.path)

    def replace(self, payload: bytes) -> None:
        if type(payload) is not bytes:
            raise SecureStateFileError("state-file-payload-invalid")
        _atomic_write(self.path, payload)


def secure_state_path(
    storage_root: str | Path, filename: str, *, repo_root: str | Path | None = None,
) -> Path:
    """Return one canonical external state path for an opaque safe filename."""
    root = _canonical_root(storage_root, repo_root)
    _validate_name(filename)
    return _state_path(root, filename, create=False)


@contextmanager
def secure_state_transaction(
    storage_root: str | Path, filename: str, *, repo_root: str | Path | None = None,
) -> Iterator[_SecureStateTransaction]:
    """Hold the stable root lock across an opaque read-transition-replace cycle."""
    _validate_name(filename)
    root = _canonical_root(storage_root, repo_root, create=True)
    with _exclusive_lock(root):
        yield _SecureStateTransaction(_state_path(root, filename, create=True))


def _canonical_root(
    storage_root: str | Path, repo_root: str | Path | None, *, create: bool = False,
) -> Path:
    try:
        root = Path(storage_root).expanduser()
        repository = Path(repo_root).expanduser() if repo_root is not None else _REPO_ROOT
    except (TypeError, ValueError, OSError):
        raise SecureStateFileError("state-file-path-invalid") from None
    if not root.is_absolute() or not repository.is_absolute():
        raise SecureStateFileError("storage-root-not-absolute")
    try:
        root, repository = root.resolve(strict=False), repository.resolve(strict=False)
    except (OSError, RuntimeError):
        raise SecureStateFileError("state-file-path-invalid") from None
    if root == repository or repository in root.parents:
        raise SecureStateFileError("storage-root-inside-repository")
    if create:
        try:
            root.mkdir(parents=True, exist_ok=True)
            _validate_directory(root, root.parent)
        except OSError:
            raise SecureStateFileError("state-file-path-invalid") from None
    return root


def _state_path(root: Path, filename: str, *, create: bool) -> Path:
    state = root / "state"
    try:
        if create:
            state.mkdir(exist_ok=True)
        elif not (state.exists() or state.is_symlink()):
            return state / filename
        _validate_directory(state, root)
    except OSError:
        raise SecureStateFileError("state-file-path-invalid") from None
    path = state / filename
    _validate_file(path, state, missing=True)
    return path


def _validate_name(value: object) -> None:
    if type(value) is not str or not _NAME_RE.fullmatch(value):
        raise SecureStateFileError("state-file-name-invalid")


def _validate_directory(path: Path, parent: Path) -> None:
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or _linked(info)
            or path.resolve(strict=True).parent != parent.resolve(strict=True)):
        raise SecureStateFileError("state-file-path-invalid")


def _validate_file(path: Path, parent: Path, *, missing: bool) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        if missing:
            return
        raise
    except OSError:
        raise SecureStateFileError("state-file-path-invalid") from None
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or _linked(info)
            or path.resolve(strict=True).parent != parent.resolve(strict=True)):
        raise SecureStateFileError("state-file-path-invalid")


def _linked(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _validate_open_file(path: Path, parent: Path, descriptor: int) -> os.stat_result:
    _validate_file(path, parent, missing=False)
    named, opened = os.lstat(path), os.fstat(descriptor)
    if ((named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode)):
        raise SecureStateFileError("state-file-path-invalid")
    return opened


@contextmanager
def _exclusive_lock(root: Path) -> Iterator[None]:
    path, descriptor = root / _LOCK_NAME, None
    try:
        _validate_file(path, root, missing=True)
        descriptor = os.open(
            path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        opened = _validate_open_file(path, root, descriptor)
        if opened.st_size == 0:
            os.write(descriptor, b"\0")
            os.fsync(descriptor)
        try:
            _operate_lock(descriptor, acquire=True)
        except (BlockingIOError, PermissionError):
            raise SecureStateFileError("state-file-busy") from None
        _validate_open_file(path, root, descriptor)
    except SecureStateFileError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        raise SecureStateFileError("state-file-lock-failed") from None
    try:
        yield
    finally:
        failed, release_failed = sys.exc_info()[0] is not None, False
        try:
            _operate_lock(descriptor, acquire=False)
        except OSError:
            release_failed = True
        try:
            os.close(descriptor)
        except OSError:
            release_failed = True
        if release_failed and not failed:
            raise SecureStateFileError("state-file-lock-release-failed") from None


def _operate_lock(descriptor: int, *, acquire: bool) -> None:
    os.lseek(descriptor, 0, os.SEEK_SET)
    if os.name == "nt":
        import msvcrt
        mode = msvcrt.LK_NBLCK if acquire else msvcrt.LK_UNLCK
        msvcrt.locking(descriptor, mode, 1)
    else:
        import fcntl
        mode = fcntl.LOCK_EX | fcntl.LOCK_NB if acquire else fcntl.LOCK_UN
        fcntl.flock(descriptor, mode)


def _read(path: Path) -> bytes | None:
    descriptor: int | None = None
    try:
        _validate_file(path, path.parent, missing=False)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        _validate_open_file(path, path.parent, descriptor)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            return stream.read()
    except FileNotFoundError:
        return None
    except SecureStateFileError:
        raise
    except OSError:
        raise SecureStateFileError("state-file-unreadable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _atomic_write(path: Path, payload: bytes) -> None:
    """Write and fsync a verified same-directory temp before atomic replacement."""
    descriptor: int | None = None
    temporary: Path | None = None
    created: os.stat_result | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
        temporary = Path(name)
        created = os.fstat(descriptor)
        _validate_open_file(temporary, path.parent, descriptor)
        stream = os.fdopen(descriptor, "wb")
        descriptor = None
        with stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _validate_file(temporary, path.parent, missing=False)
        current = os.lstat(temporary)
        if (current.st_dev, current.st_ino) != (created.st_dev, created.st_ino):
            raise SecureStateFileError("state-file-path-invalid")
        _validate_file(path, path.parent, missing=True)
        os.replace(temporary, path)
        temporary = None
        _fsync_directory(path.parent)
    except SecureStateFileError:
        raise
    except OSError:
        raise SecureStateFileError("state-file-write-failed") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None and created is not None:
            _safe_unlink(temporary, created)
def _safe_unlink(path: Path, expected: os.stat_result) -> None:
    """Remove only the exact temp inode created by this transaction."""
    try:
        current = os.lstat(path)
        if (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino):
            path.unlink()
    except OSError:
        pass


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
