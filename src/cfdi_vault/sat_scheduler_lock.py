"""Held operating-system file locks for one-shot SAT scheduler work."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO


class SchedulerLockError(RuntimeError):
    """Raised when a scheduler OS lock cannot be acquired or released."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass
class LocalFileLock:
    """Hold an exclusive OS lock handle for the complete scheduler cycle.

    The lock file is persistent. Windows uses ``msvcrt`` byte-range locking;
    other platforms use ``fcntl.flock`` for hermetic test portability. Process
    death releases the OS lock automatically, so old metadata is harmless and
    is rewritten only after a new owner acquires exclusivity.
    """

    path: Path
    now: datetime | None = None
    owner_marker: str = field(default_factory=lambda: secrets.token_hex(16))
    _handle: BinaryIO | None = field(default=None, init=False, repr=False)

    def acquire(self) -> None:
        """Acquire and hold the OS lock or raise a redacted contention reason."""

        if self._handle is not None:
            raise SchedulerLockError("scheduler-lock-already-acquired")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            handle = os.fdopen(descriptor, "r+b")
            _ensure_lock_byte(handle)
            _lock_handle(handle)
        except OSError as exc:
            try:
                handle.close()
            except (OSError, UnboundLocalError):
                pass
            raise SchedulerLockError("scheduler-lock-held") from exc

        try:
            document = {
                "ownerMarker": self.owner_marker,
                "createdAt": _format_dt(_utc_now(self.now)),
                "pid": os.getpid(),
            }
            payload = (json.dumps(document, sort_keys=True) + "\n").encode("utf-8")
            handle.seek(0)
            handle.write(payload)
            handle.truncate()
            handle.flush()
            os.fsync(handle.fileno())
            handle.seek(0)
        except OSError as exc:
            _release_handle(handle)
            handle.close()
            raise SchedulerLockError("scheduler-lock-metadata-write-failed") from exc
        self._handle = handle

    def release(self) -> None:
        """Release this held handle without deleting the persistent lock file."""

        handle = self._handle
        if handle is None:
            return
        self._handle = None
        try:
            handle.seek(0)
            _release_handle(handle)
        except OSError as exc:
            raise SchedulerLockError("scheduler-lock-release-failed") from exc
        finally:
            handle.close()

    def __enter__(self) -> LocalFileLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


def _ensure_lock_byte(handle: BinaryIO) -> None:
    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"\0")
        handle.flush()
        os.fsync(handle.fileno())
    handle.seek(0)


def _lock_handle(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release_handle(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _format_dt(value: datetime) -> str:
    return _utc_now(value).isoformat().replace("+00:00", "Z")


def _utc_now(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    aware = current if current.tzinfo is not None else current.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc)
