from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest.mock import Mock

import pytest

import cfdi_vault.secure_state_file as subject

NAME = "sat-campaign-cmp-000000000000.json"


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    repository, storage = tmp_path / "checkout", tmp_path / "storage"
    repository.mkdir()
    return repository, storage


def test_locked_roundtrip_is_atomic_and_retains_stable_root_lock(tmp_path) -> None:
    repository, storage = _roots(tmp_path)
    path = subject.secure_state_path(storage, NAME, repo_root=repository)
    with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
        assert transaction.read() is None
        transaction.replace(b"first")
    with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
        transaction.replace(b"second")
    assert path.read_bytes() == b"second" and (storage / ".secure-state-file.lock").exists()


def test_root_and_filename_are_canonical_absolute_and_external(tmp_path) -> None:
    repository, _ = _roots(tmp_path)
    with pytest.raises(subject.SecureStateFileError, match="storage-root-not-absolute"):
        subject.secure_state_path(Path("relative"), NAME, repo_root=repository)
    with pytest.raises(subject.SecureStateFileError, match="storage-root-inside-repository"):
        subject.secure_state_path(repository / "private", NAME, repo_root=repository)
    for unsafe in ("../escape", "state/file", ".hidden", "x" * 129, True):
        with pytest.raises(subject.SecureStateFileError, match="state-file-name-invalid"):
            subject.secure_state_path(tmp_path / "external", unsafe, repo_root=repository)  # type: ignore[arg-type]
    target, configured = tmp_path / "target", tmp_path / "configured"
    target.mkdir()
    configured.symlink_to(target, target_is_directory=True)
    assert subject.secure_state_path(configured, NAME, repo_root=repository).is_relative_to(target.resolve())


@pytest.mark.parametrize(
    "attack", ("state-symlink", "file-symlink", "lock-symlink", "file-hardlink", "lock-hardlink"),
)
def test_linked_named_nodes_cannot_escape(tmp_path, attack: str) -> None:
    repository, storage = _roots(tmp_path)
    node, kind = attack.split("-")
    outside = tmp_path / "outside"
    storage.mkdir()
    state = storage / "state"
    if node == "state":
        outside.mkdir()
        state.symlink_to(outside, target_is_directory=True)
    else:
        state.mkdir()
        outside.write_bytes(b"sentinel")
        link = storage / ".secure-state-file.lock" if node == "lock" else state / NAME
        link.symlink_to(outside) if kind == "symlink" else os.link(outside, link)
    with pytest.raises(subject.SecureStateFileError, match="state-file-path-invalid"):
        with subject.secure_state_transaction(storage, NAME, repo_root=repository):
            pass
    if node != "state":
        assert outside.read_bytes() == b"sentinel"


def test_descriptor_and_temp_cleanup_require_exact_created_identity(tmp_path) -> None:
    parent = tmp_path / "state"
    parent.mkdir()
    named, other = parent / "named", parent / "other"
    named.write_bytes(b"named")
    other.write_bytes(b"other")
    descriptor = os.open(other, os.O_RDONLY)
    try:
        with pytest.raises(subject.SecureStateFileError, match="state-file-path-invalid"):
            subject._validate_open_file(named, parent, descriptor)  # noqa: SLF001
    finally:
        os.close(descriptor)
    temporary, target = parent / "temporary", parent / "target"
    temporary.write_bytes(b"created")
    created = os.lstat(temporary)
    temporary.unlink()
    target.write_bytes(b"sentinel")
    temporary.symlink_to(target)
    subject._safe_unlink(temporary, created)  # noqa: SLF001
    assert temporary.is_symlink() and target.read_bytes() == b"sentinel"


def test_contention_is_busy_for_the_complete_transaction(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    entered, release, original = Event(), Event(), subject._atomic_write

    def blocked(path, payload):  # type: ignore[no-untyped-def]
        entered.set()
        release.wait()
        original(path, payload)

    monkeypatch.setattr(subject, "_atomic_write", blocked)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_write, storage, repository)
        entered.wait(timeout=5)
        try:
            with pytest.raises(subject.SecureStateFileError, match="state-file-busy"):
                with subject.secure_state_transaction(storage, NAME, repo_root=repository):
                    pass
        finally:
            release.set()
        future.result()


def _write(storage: Path, repository: Path) -> None:
    with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
        transaction.replace(b"payload")


def test_failed_replace_preserves_state_cleans_temp_and_success_fsyncs_parent(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    _write(storage, repository)
    path, original_replace = subject.secure_state_path(storage, NAME, repo_root=repository), subject.os.replace
    monkeypatch.setattr(subject.os, "replace", Mock(side_effect=OSError("synthetic")))
    with pytest.raises(subject.SecureStateFileError, match="state-file-write-failed"):
        with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
            transaction.replace(b"changed")
    assert path.read_bytes() == b"payload" and not tuple(path.parent.glob(f".{NAME}.tmp-*"))
    fsync_directory = Mock()
    monkeypatch.setattr(subject.os, "replace", original_replace)
    monkeypatch.setattr(subject, "_fsync_directory", fsync_directory)
    _write(storage, repository)
    fsync_directory.assert_called_once_with(path.parent)
