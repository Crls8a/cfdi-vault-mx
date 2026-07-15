from __future__ import annotations

import json
from datetime import datetime, timezone
from multiprocessing import get_context
from pathlib import Path

import pytest

from cfdi_vault.sat_scheduler_lock import LocalFileLock, SchedulerLockError

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)


def test_lock_blocks_overlap_and_keeps_persistent_lock_file(tmp_path: Path) -> None:
    path = tmp_path / "scheduler.lock"
    first = LocalFileLock(path, now=NOW)
    first.acquire()

    with pytest.raises(SchedulerLockError, match="scheduler-lock-held"):
        LocalFileLock(path, now=NOW).acquire()

    first.release()
    assert path.exists()
    next_owner = LocalFileLock(path, now=NOW)
    next_owner.acquire()
    next_owner.release()
    assert path.exists()


def test_unlocked_stale_metadata_is_harmless_and_rewritten(tmp_path: Path) -> None:
    path = tmp_path / "scheduler.lock"
    path.write_text('{"ownerMarker":"stale","createdAt":"2000-01-01T00:00:00Z"}\n', encoding="utf-8")

    owner = LocalFileLock(path, now=NOW)
    owner.acquire()
    owner.release()
    document = json.loads(path.read_text(encoding="utf-8"))

    assert document["ownerMarker"] != "stale"
    assert document["createdAt"] == "2026-07-14T12:00:00Z"
    assert path.exists()


def test_os_lock_recovers_after_holder_process_is_terminated(tmp_path: Path) -> None:
    path = tmp_path / "scheduler.lock"
    context = get_context("spawn")
    ready = context.Queue()
    release = context.Event()
    holder = context.Process(target=_hold_lock, args=(path, ready, release))
    holder.start()
    assert ready.get(timeout=10) == "locked"

    with pytest.raises(SchedulerLockError, match="scheduler-lock-held"):
        LocalFileLock(path, now=NOW).acquire()

    holder.terminate()
    holder.join(timeout=10)
    assert not holder.is_alive()

    recovered = LocalFileLock(path, now=NOW)
    recovered.acquire()
    recovered.release()
    assert path.exists()


def _hold_lock(path: Path, ready: object, release: object) -> None:
    lock = LocalFileLock(path, now=NOW)
    lock.acquire()
    ready.put("locked")
    release.wait(timeout=30)
    lock.release()
