"""Internal canonical, locked, atomic storage for opaque local state bytes.

After canonicalization, the configured storage root and all descendants are a
private ACL trust boundary for each transaction. Pre-existing linked/reparse
nodes and noncanonical filenames are rejected, and honest processes coordinate
through the root lock. Identity and hash checks fail closed when they observe a
change, but dependency-free code cannot promise namespace containment against a
hostile same-user process concurrently mutating any node inside the trusted tree.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
import tempfile
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

_REPO_ROOT = Path(__file__).resolve().parents[2]
_NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
_LOCK_NAME = ".secure-state-file.lock"
_RESERVED = {"con", "prn", "aux", "nul"} | {f"{prefix}{number}" for prefix in ("com", "lpt") for number in range(1, 10)}
_Identity = tuple[int, int]


class SecureStateFileError(ValueError):
    """Report filesystem failures with a sanitized reason only."""

    def __init__(self, reason: str, *, committed: bool = False, uncertain: bool = False) -> None:
        self.reason, self.committed, self.uncertain = reason, committed, uncertain
        super().__init__(reason)

    @property
    def retry_safe(self) -> bool:
        """Return whether a caller may safely retry without reconciliation."""
        return not self.committed and not self.uncertain


@dataclass(frozen=True)
class SecureStateWriteOutcome:
    """Confirm one visible, hash-verified atomic replacement."""

    committed: bool
    uncertain: bool
    sha256: str


@dataclass
class _CommitState:
    committed: bool = False


@dataclass(frozen=True)
class _NamespaceSnapshot:
    root: Path
    state: Path
    root_identity: _Identity
    state_identity: _Identity

    def validate(self) -> None:
        try:
            _validate_directory_identity(self.root, self.root.parent, self.root_identity)
            _validate_directory_identity(self.state, self.root, self.state_identity)
        except OSError:
            raise SecureStateFileError("state-file-path-invalid") from None


@dataclass(repr=False)
class _SecureStateTransaction:
    path: Path
    namespace: _NamespaceSnapshot
    commit_state: _CommitState

    def read(self) -> bytes | None:
        try:
            self.namespace.validate()
            payload = _read(self.path)
            self.namespace.validate()
            return payload
        except SecureStateFileError:
            raise
        except OSError:
            raise SecureStateFileError("state-file-unreadable") from None

    def replace(self, payload: bytes) -> SecureStateWriteOutcome:
        if type(payload) is not bytes:
            raise SecureStateFileError("state-file-payload-invalid")
        if self.commit_state.committed:
            raise SecureStateFileError(
                "state-file-transition-already-committed", committed=True,
            )
        try:
            outcome = _atomic_write(self.path, payload, self.namespace.validate)
        except SecureStateFileError as exc:
            self.commit_state.committed |= exc.committed
            raise
        except OSError:
            raise SecureStateFileError("state-file-write-failed") from None
        self.commit_state.committed = True
        return outcome


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
    """Lock one transaction whose canonical root tree remains ACL-private."""
    _validate_name(filename)
    root = _canonical_root(storage_root, repo_root, create=True)
    root_identity, commit_state = _directory_identity(root, root.parent), _CommitState()
    with _exclusive_lock(root, root_identity, commit_state):
        path = _state_path(root, filename, create=True)
        namespace = _NamespaceSnapshot(root, path.parent, root_identity, _directory_identity(path.parent, root))
        namespace.validate()
        yield _SecureStateTransaction(path, namespace, commit_state)


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
            try:
                state.mkdir()
            except FileExistsError:
                pass
        elif not (state.exists() or state.is_symlink()):
            return state / filename
        _validate_directory(state, root)
        if create:
            _fsync_directory(root)
    except OSError:
        raise SecureStateFileError("state-file-path-invalid") from None
    path = state / filename
    _validate_file(path, state, missing=True)
    return path


def _validate_name(value: object) -> None:
    base = value.split(".", 1)[0] if type(value) is str else ""
    if (type(value) is not str or not _NAME_RE.fullmatch(value) or value.endswith(".")
            or ".." in value or base in _RESERVED):
        raise SecureStateFileError("state-file-name-invalid")


def _validate_directory(path: Path, parent: Path) -> None:
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or _linked(info)
            or path.resolve(strict=True).parent != parent.resolve(strict=True)):
        raise SecureStateFileError("state-file-path-invalid")


def _directory_identity(path: Path, parent: Path) -> _Identity:
    try:
        _validate_directory(path, parent)
        info = os.lstat(path)
    except OSError:
        raise SecureStateFileError("state-file-path-invalid") from None
    return info.st_dev, info.st_ino


def _validate_directory_identity(path: Path, parent: Path, expected: _Identity) -> None:
    if _directory_identity(path, parent) != expected:
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
    try:
        invalid = (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or _linked(info)
                   or path.resolve(strict=True).parent != parent.resolve(strict=True))
    except OSError:
        raise SecureStateFileError("state-file-path-invalid") from None
    if invalid:
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
def _exclusive_lock(
    root: Path, root_identity: _Identity, commit_state: _CommitState,
) -> Iterator[None]:
    path, descriptor = root / _LOCK_NAME, None
    try:
        _validate_directory_identity(root, root.parent, root_identity)
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
        _validate_directory_identity(root, root.parent, root_identity)
    except SecureStateFileError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    except OSError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
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
            reason = "state-file-commit-uncertain" if commit_state.committed else "state-file-lock-release-failed"
            raise SecureStateFileError(
                reason, committed=commit_state.committed, uncertain=commit_state.committed,
            ) from None


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


def _atomic_write(
    path: Path, payload: bytes, verify_namespace: Callable[[], None],
) -> SecureStateWriteOutcome:
    """Write and fsync a verified same-directory temp before atomic replacement."""
    descriptor: int | None = None
    temporary: Path | None = None
    created: os.stat_result | None = None
    visible = False
    digest = hashlib.sha256(payload).hexdigest()
    try:
        verify_namespace()
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
        temporary = Path(name)
        created = os.fstat(descriptor)
        _validate_open_file(temporary, path.parent, descriptor)
        stream = os.fdopen(os.dup(descriptor), "wb")
        with stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _validate_open_file(temporary, path.parent, descriptor)
        if _hash_descriptor(descriptor) != digest:
            raise SecureStateFileError("state-file-path-invalid")
        verify_namespace()
        os.close(descriptor)
        descriptor = None
        _verify_named_temp(temporary, path.parent, created, digest)
        verify_namespace()
        previous = _file_snapshot(path)
        verify_namespace()
        try:
            os.replace(temporary, path)
        except OSError:
            try:
                visible = _file_snapshot(path) != previous
            except (OSError, SecureStateFileError):
                visible = True
            raise
        visible = True
        temporary = None
        verify_namespace()
        _verify_named_file(path, path.parent, created, digest)
        _fsync_directory(path.parent)
        return SecureStateWriteOutcome(True, False, digest)
    except SecureStateFileError:
        if visible:
            raise SecureStateFileError(
                "state-file-commit-uncertain", committed=True, uncertain=True,
            ) from None
        raise
    except OSError:
        if visible:
            raise SecureStateFileError(
                "state-file-commit-uncertain", committed=True, uncertain=True,
            ) from None
        raise SecureStateFileError("state-file-write-failed") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None and created is not None:
            _safe_unlink(temporary, created)


def _hash_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while chunk := os.read(descriptor, 65_536):
        digest.update(chunk)
    return digest.hexdigest()


def _file_snapshot(path: Path) -> tuple[_Identity, str] | None:
    descriptor: int | None = None
    try:
        _validate_file(path, path.parent, missing=False)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = _validate_open_file(path, path.parent, descriptor)
        return (opened.st_dev, opened.st_ino), _hash_descriptor(descriptor)
    except FileNotFoundError:
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _verify_named_file(
    path: Path, parent: Path, expected: os.stat_result, digest: str,
) -> None:
    if _file_snapshot(path) != ((expected.st_dev, expected.st_ino), digest):
        raise SecureStateFileError("state-file-path-invalid")


def _verify_named_temp(
    path: Path, parent: Path, expected: os.stat_result, digest: str,
) -> None:
    _verify_named_file(path, parent, expected, digest)


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
