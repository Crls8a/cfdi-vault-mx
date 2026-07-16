from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest.mock import Mock, call

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
        outcome = transaction.replace(b"first")
        assert outcome == subject.SecureStateWriteOutcome(
            committed=True, uncertain=False, sha256=hashlib.sha256(b"first").hexdigest(),
        )
    with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
        transaction.replace(b"second")
    assert path.read_bytes() == b"second" and (storage / ".secure-state-file.lock").exists()


def test_replace_is_a_single_transition_and_cannot_be_retried_in_transaction(tmp_path) -> None:
    repository, storage = _roots(tmp_path)
    with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
        transaction.replace(b"first")
        with pytest.raises(subject.SecureStateFileError, match="state-file-transition-already-committed") as raised:
            transaction.replace(b"second")
    assert raised.value.committed and not raised.value.uncertain and not raised.value.retry_safe
    assert subject.secure_state_path(storage, NAME, repo_root=repository).read_bytes() == b"first"


def test_root_and_filename_are_canonical_absolute_and_external(tmp_path) -> None:
    repository, _ = _roots(tmp_path)
    with pytest.raises(subject.SecureStateFileError, match="storage-root-not-absolute"):
        subject.secure_state_path(Path("relative"), NAME, repo_root=repository)
    with pytest.raises(subject.SecureStateFileError, match="storage-root-inside-repository"):
        subject.secure_state_path(repository / "private", NAME, repo_root=repository)
    for unsafe in (
        "../escape", "state/file", "state\\file", "name:", ".hidden", "name.", "name ",
        "name..json", "con", "con.json", "aux.txt", "com1.log", "lpt9", "Name.json",
        "méxico.json", "x" * 129, True,
    ):
        with pytest.raises(subject.SecureStateFileError, match="state-file-name-invalid"):
            subject.secure_state_path(tmp_path / "external", unsafe, repo_root=repository)  # type: ignore[arg-type]
    target, configured = tmp_path / "target", tmp_path / "configured"
    target.mkdir()
    configured.symlink_to(target, target_is_directory=True)
    assert subject.secure_state_path(configured, NAME, repo_root=repository).is_relative_to(target.resolve())


@pytest.mark.parametrize(
    "attack", ("state-symlink", "file-symlink", "lock-symlink", "file-hardlink", "lock-hardlink"),
)
def test_preexisting_linked_named_nodes_are_rejected(tmp_path, attack: str) -> None:
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

    def blocked(path, payload, verify_namespace):  # type: ignore[no-untyped-def]
        entered.set()
        release.wait()
        original(path, payload, verify_namespace)

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
    with pytest.raises(subject.SecureStateFileError, match="state-file-write-failed") as raised:
        with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
            transaction.replace(b"changed")
    assert not raised.value.committed and not raised.value.uncertain and raised.value.retry_safe
    assert path.read_bytes() == b"payload" and not tuple(path.parent.glob(f".{NAME}.tmp-*"))
    fsync_directory = Mock()
    monkeypatch.setattr(subject.os, "replace", original_replace)
    monkeypatch.setattr(subject, "_fsync_directory", fsync_directory)
    _write(storage, repository)
    assert fsync_directory.call_args_list == [call(storage.resolve()), call(path.parent)]


def test_detected_state_identity_change_fails_closed_as_defense_in_depth(tmp_path) -> None:
    repository, storage = _roots(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
        (storage / "state").rename(storage / "original-state")
        (storage / "state").symlink_to(outside, target_is_directory=True)
        with pytest.raises(subject.SecureStateFileError, match="state-file-path-invalid") as raised:
            transaction.replace(b"must-not-escape")
    assert not raised.value.committed and raised.value.retry_safe and not tuple(outside.iterdir())


def test_detected_temp_identity_change_preserves_previous_state(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    _write(storage, repository)
    path = subject.secure_state_path(storage, NAME, repo_root=repository)
    original_verify = subject._verify_named_temp

    def substitute(temporary, parent, expected, digest):  # type: ignore[no-untyped-def]
        temporary.unlink()
        temporary.write_bytes(b"foreign")
        original_verify(temporary, parent, expected, digest)

    monkeypatch.setattr(subject, "_verify_named_temp", substitute)
    with pytest.raises(subject.SecureStateFileError, match="state-file-path-invalid") as raised:
        with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
            transaction.replace(b"replacement")
    assert path.read_bytes() == b"payload" and not raised.value.committed and raised.value.retry_safe


def test_post_replace_integrity_mismatch_is_commit_uncertain(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    _write(storage, repository)
    original_replace = subject.os.replace

    def substitute(source, target):  # type: ignore[no-untyped-def]
        Path(source).unlink()
        Path(source).write_bytes(b"foreign")
        original_replace(source, target)

    monkeypatch.setattr(subject.os, "replace", substitute)
    with pytest.raises(subject.SecureStateFileError, match="state-file-commit-uncertain") as raised:
        with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
            transaction.replace(b"replacement")
    assert raised.value.committed and raised.value.uncertain and not raised.value.retry_safe


def test_state_creation_and_commit_fsync_their_parent_directories(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    fsync_directory = Mock()
    monkeypatch.setattr(subject, "_fsync_directory", fsync_directory)
    _write(storage, repository)
    assert fsync_directory.call_args_list == [call(storage.resolve()), call((storage / "state").resolve())]


def test_existing_state_retries_root_fsync_after_initial_sync_failure(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    root, calls = storage.resolve(), []

    def fail_first_root_sync(path):  # type: ignore[no-untyped-def]
        calls.append(path)
        if calls == [root]:
            raise OSError("synthetic root fsync failure")

    monkeypatch.setattr(subject, "_fsync_directory", fail_first_root_sync)
    with pytest.raises(subject.SecureStateFileError, match="state-file-path-invalid"):
        with subject.secure_state_transaction(storage, NAME, repo_root=repository):
            pass
    assert (storage / "state").is_dir()
    with subject.secure_state_transaction(storage, NAME, repo_root=repository):
        pass
    assert calls == [root, root]


def test_transaction_setup_sanitizes_second_identity_lstat_failure(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    root, original_lstat = storage.resolve(), subject.os.lstat
    root_calls = 0
    private_detail = f"private-path={storage}"

    def fail_second_identity_lstat(path):  # type: ignore[no-untyped-def]
        nonlocal root_calls
        if Path(path) == root:
            root_calls += 1
            if root_calls == 3:
                raise PermissionError(private_detail)
        return original_lstat(path)

    monkeypatch.setattr(subject.os, "lstat", fail_second_identity_lstat)
    with pytest.raises(subject.SecureStateFileError, match="^state-file-path-invalid$") as raised:
        with subject.secure_state_transaction(storage, NAME, repo_root=repository):
            pass
    assert private_detail not in str(raised.value)


def test_path_validation_sanitizes_resolve_failure(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    state = storage / "state"
    state.mkdir(parents=True)
    path = state / NAME
    path.write_bytes(b"payload")
    private_detail = f"private-path={path}"
    original_resolve = Path.resolve

    def fail_file_resolve(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        if self == path:
            raise PermissionError(private_detail)
        return original_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail_file_resolve)
    with pytest.raises(subject.SecureStateFileError, match="^state-file-path-invalid$") as raised:
        subject.secure_state_path(storage, NAME, repo_root=repository)
    assert private_detail not in str(raised.value)


def test_transaction_setup_preserves_sanitized_error_when_descriptor_cleanup_fails(
    tmp_path, monkeypatch,
) -> None:
    repository, storage = _roots(tmp_path)
    private_detail = f"private-path={storage}"
    original_close = subject.os.close

    def close_then_fail(descriptor):  # type: ignore[no-untyped-def]
        original_close(descriptor)
        raise OSError(private_detail)

    monkeypatch.setattr(
        subject, "_validate_open_file",
        Mock(side_effect=subject.SecureStateFileError("state-file-path-invalid")),
    )
    monkeypatch.setattr(subject.os, "close", close_then_fail)
    with pytest.raises(subject.SecureStateFileError, match="^state-file-path-invalid$") as raised:
        with subject.secure_state_transaction(storage, NAME, repo_root=repository):
            pass
    assert private_detail not in str(raised.value)


def test_transaction_read_sanitizes_namespace_validation_failure(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    private_detail = f"private-path={storage}"
    with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
        state, original_lstat = (storage / "state").resolve(), subject.os.lstat

        def fail_state_lstat(path):  # type: ignore[no-untyped-def]
            if Path(path) == state:
                raise OSError(private_detail)
            return original_lstat(path)

        monkeypatch.setattr(subject.os, "lstat", fail_state_lstat)
        with pytest.raises(subject.SecureStateFileError, match="^state-file-path-invalid$") as raised:
            transaction.read()
    assert private_detail not in str(raised.value)


def test_transaction_replace_sanitizes_namespace_validation_failure(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    private_detail = f"private-path={storage}"
    with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
        state, original_lstat = (storage / "state").resolve(), subject.os.lstat

        def fail_state_lstat(path):  # type: ignore[no-untyped-def]
            if Path(path) == state:
                raise PermissionError(private_detail)
            return original_lstat(path)

        monkeypatch.setattr(subject.os, "lstat", fail_state_lstat)
        with pytest.raises(subject.SecureStateFileError, match="^state-file-path-invalid$") as raised:
            transaction.replace(b"payload")
    assert raised.value.retry_safe and private_detail not in str(raised.value)


def test_transaction_read_sanitizes_unexpected_filesystem_failure(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    private_detail = f"private-path={storage}"
    with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
        monkeypatch.setattr(subject, "_read", Mock(side_effect=OSError(private_detail)))
        with pytest.raises(subject.SecureStateFileError, match="^state-file-unreadable$") as raised:
            transaction.read()
    assert private_detail not in str(raised.value)


def test_transaction_replace_sanitizes_unexpected_filesystem_failure(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    private_detail = f"private-path={storage}"
    with subject.secure_state_transaction(storage, NAME, repo_root=repository) as transaction:
        monkeypatch.setattr(subject, "_atomic_write", Mock(side_effect=OSError(private_detail)))
        with pytest.raises(subject.SecureStateFileError, match="^state-file-write-failed$") as raised:
            transaction.replace(b"payload")
    assert raised.value.retry_safe and private_detail not in str(raised.value)


def test_post_visibility_fsync_and_lock_release_failures_are_terminal(tmp_path, monkeypatch) -> None:
    repository, storage = _roots(tmp_path)
    _write(storage, repository)
    state = (storage / "state").resolve()

    def fail_state_fsync(path):  # type: ignore[no-untyped-def]
        if path == state:
            raise OSError("synthetic fsync failure")

    monkeypatch.setattr(subject, "_fsync_directory", fail_state_fsync)
    with pytest.raises(subject.SecureStateFileError, match="state-file-commit-uncertain") as raised:
        _write(storage, repository)
    assert raised.value.committed and raised.value.uncertain and not raised.value.retry_safe
    monkeypatch.undo()
    original_lock = subject._operate_lock

    def fail_release(descriptor, *, acquire):  # type: ignore[no-untyped-def]
        if not acquire:
            raise OSError("synthetic release failure")
        original_lock(descriptor, acquire=acquire)

    monkeypatch.setattr(subject, "_operate_lock", fail_release)
    with pytest.raises(subject.SecureStateFileError, match="state-file-commit-uncertain") as raised:
        _write(storage, repository)
    assert raised.value.committed and raised.value.uncertain and not raised.value.retry_safe
