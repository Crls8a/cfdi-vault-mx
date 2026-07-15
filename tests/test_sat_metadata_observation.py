from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import date, datetime, timezone
from threading import Event

import pytest

import cfdi_vault.sat_metadata_observation as subject

NOW = datetime(2026, 7, 15, 12, tzinfo=timezone.utc)
COMMIT = "a" * 40
def _event(**changes: object) -> subject.NewMetadataObservation:
    values = {
        "execution_started_at": NOW, "observed_at": NOW, "tested_commit": COMMIT,
        "hypothesis_code": "H1", "direction": "received", "kind": "metadata",
        "date_from": date(2026, 6, 30), "date_to": date(2026, 6, 30),
        "executed_stages": ("authenticate", "submit"),
        "observed_result": {"authenticationAccepted": True, "requestAccepted": True},
        "conclusion": "confirmed", "next_correction_code": "observe-again",
        "stability": "observed_once",
    }
    values.update(changes)
    return subject.NewMetadataObservation(**values)
def test_append_allocates_ids_deduplicates_and_reads_aggregates(tmp_path) -> None:
    first = subject.append_metadata_observation(tmp_path, _event())
    duplicate = subject.append_metadata_observation(tmp_path, _event())
    second = subject.append_metadata_observation(tmp_path, _event(hypothesis_code="H2"))
    assert (first, duplicate, second) == (
        ("obs-000001", True), ("obs-000001", False), ("obs-000002", True))
    assert subject.read_metadata_observation_summary(tmp_path) == {"total": 2, "lastObservationId": "obs-000002"}
@pytest.mark.parametrize(
    "changes, reason",
    (
        ({"tested_commit": "private"}, "observation-invalid"),
        ({"executed_stages": ("verify", "wait")}, "observation-stages-invalid"),
        ({"observed_result": {"header": "private"}}, "observation-result-invalid"),
        ({"observed_result": {"packageCount": True}}, "observation-result-invalid"),
        ({"observed_result": {"packageCount": 10 ** 10000}}, "observation-result-invalid"),
        ({"hypothesis_code": []}, "observation-code-invalid"),
        ({"direction": []}, "observation-scope-invalid"),
        ({"conclusion": []}, "observation-code-invalid"),
        ({"stability": "assumed"}, "observation-code-invalid"),
    ),
)
def test_input_schema_rejects_arbitrary_values(changes, reason) -> None:
    with pytest.raises(subject.MetadataObservationError, match=reason):
        _event(**changes)
def test_reader_rejects_unknown_fields_arrays_duplicate_keys_and_nonsequential_ids(tmp_path) -> None:
    subject.append_metadata_observation(tmp_path, _event())
    path = subject.metadata_observation_path(tmp_path)
    original = json.loads(path.read_text(encoding="utf-8"))
    unknown, array = dict(original, private="forbidden"), dict(original)
    array["observedResult"] = {"packageCount": []}
    wrong_id = dict(original, observationId="obs-000002")
    boolean_version = dict(original, schemaVersion=True)
    nested_list = dict(original)
    nested_list["hypothesis"] = {"code": [], "text": "private"}
    huge_integer = path.read_text(encoding="utf-8").replace('"requestAccepted":true', '"packageCount":' + "9" * 5000)
    invalid = [json.dumps(unknown), json.dumps(array), path.read_text(encoding="utf-8").replace(
        '"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'), json.dumps(wrong_id),
        json.dumps(boolean_version), json.dumps(nested_list), huge_integer]
    for index, payload in enumerate(invalid):
        root = tmp_path / str(index)
        target = subject.metadata_observation_path(root)
        target.parent.mkdir(parents=True)
        target.write_text(payload.rstrip("\n") + "\n", encoding="utf-8")
        with pytest.raises(subject.MetadataObservationError):
            subject.read_metadata_observation_summary(root)
def test_partial_tail_fails_closed_without_rewriting(tmp_path) -> None:
    subject.append_metadata_observation(tmp_path, _event())
    path = subject.metadata_observation_path(tmp_path)
    with path.open("ab") as stream:
        stream.write(b'{"partial":')
    before = path.read_bytes()
    with pytest.raises(subject.MetadataObservationError, match="observation-partial-tail"):
        subject.append_metadata_observation(tmp_path, _event(hypothesis_code="H2"))
    assert path.read_bytes() == before
def test_paths_reject_repository_symlink_and_hardlink_escapes(tmp_path) -> None:
    repo, storage, other = (tmp_path / name for name in ("checkout", "storage", "other"))
    for directory in (repo, storage, other):
        directory.mkdir()
    with pytest.raises(subject.MetadataObservationError):
        subject.metadata_observation_path(repo / "private", repo_root=repo)
    (storage / "state").symlink_to(other, target_is_directory=True)
    with pytest.raises(subject.MetadataObservationError, match="observation-path-invalid"):
        subject.append_metadata_observation(storage, _event(), repo_root=repo)
    (storage / "state").unlink()
    (storage / "state").mkdir()
    target = other / "foreign"
    target.write_bytes(b"sentinel")
    subject.metadata_observation_path(storage, repo_root=repo).symlink_to(target)
    with pytest.raises(subject.MetadataObservationError, match="observation-path-invalid"):
        subject.append_metadata_observation(storage, _event(), repo_root=repo)
    (storage / "state" / "sat-metadata-observations.jsonl").unlink()
    os.link(target, subject.metadata_observation_path(storage, repo_root=repo))
    with pytest.raises(subject.MetadataObservationError, match="observation-path-invalid"):
        subject.append_metadata_observation(storage, _event(), repo_root=repo)
    assert target.read_bytes() == b"sentinel"
def test_concurrent_append_is_rejected_while_stable_lock_is_held(tmp_path, monkeypatch) -> None:
    path = subject.metadata_observation_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.with_name(f".{path.name}.lock").write_bytes(b"\0")
    original_write = subject.os.write
    entered, release = Event(), Event()
    def blocked_write(descriptor, payload):
        entered.set()
        release.wait(timeout=5)
        return original_write(descriptor, payload)
    monkeypatch.setattr(subject.os, "write", blocked_write)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(subject.append_metadata_observation, tmp_path, _event())
        assert entered.wait(timeout=5)
        try:
            with pytest.raises(subject.MetadataObservationError, match="observation-busy"):
                subject.append_metadata_observation(tmp_path, _event(hypothesis_code="H2"))
        finally:
            release.set()
        assert future.result()[1]
def test_errors_never_echo_arbitrary_data_or_paths(tmp_path) -> None:
    private = f"private-request:{tmp_path.resolve()}"
    with pytest.raises(subject.MetadataObservationError) as captured:
        _event(observed_result={"outcome": private})
    assert str(captured.value) == "observation-result-invalid"
    assert private not in repr(captured.value)
def test_short_write_is_reported_as_uncertain(tmp_path, monkeypatch) -> None:
    path = subject.metadata_observation_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.with_name(f".{path.name}.lock").write_bytes(b"\0")
    monkeypatch.setattr(subject.os, "write", lambda *_: 0)
    with pytest.raises(subject.MetadataObservationError, match="observation-write-uncertain"):
        subject.append_metadata_observation(tmp_path, _event())
def test_state_swap_before_root_lock_cannot_escape_storage(tmp_path, monkeypatch) -> None:
    storage, outside = tmp_path / "storage", tmp_path / "outside"
    outside.mkdir()
    original_lock = subject._ledger_lock
    @contextmanager
    def swap_then_lock(anchor):
        state_dir = storage / "state"
        state_dir.rename(storage / "state-original")
        state_dir.symlink_to(outside, target_is_directory=True)
        with original_lock(anchor):
            yield
    monkeypatch.setattr(subject, "_ledger_lock", swap_then_lock)
    with pytest.raises(subject.MetadataObservationError, match="observation-path-invalid"):
        subject.append_metadata_observation(storage, _event())
    assert not (outside / "sat-metadata-observations.jsonl").exists()
    assert not tuple(outside.glob("*.lock")) and not tuple(outside.glob(".*.lock"))
    assert (storage / ".sat-metadata-observation-ledger.lock").exists()
def test_first_creation_requests_directory_fsync_via_platform_seam(tmp_path, monkeypatch) -> None:
    order: list[object] = []
    (tmp_path / ".sat-metadata-observation-ledger.lock").write_bytes(b"\0")
    monkeypatch.setattr(subject, "_DIRECTORY_FSYNC_REQUIRED", True)
    monkeypatch.setattr(subject.os, "fsync", lambda _: order.append("file"))
    monkeypatch.setattr(subject, "_fsync_directory", lambda directory: order.append(directory))
    subject.append_metadata_observation(tmp_path, _event())
    subject.append_metadata_observation(tmp_path, _event())
    assert order == ["file", subject.metadata_observation_path(tmp_path).parent]
def test_named_ledger_symlink_to_contained_sibling_is_rejected(tmp_path) -> None:
    path = subject.metadata_observation_path(tmp_path)
    path.parent.mkdir(parents=True)
    target = path.with_name("contained-sibling.jsonl")
    target.write_bytes(b"synthetic sentinel\n")
    path.symlink_to(target)
    with pytest.raises(subject.MetadataObservationError, match="observation-path-invalid"):
        subject.append_metadata_observation(tmp_path, _event())
    assert target.read_bytes() == b"synthetic sentinel\n"
def test_observed_result_is_frozen_against_caller_mutation(tmp_path) -> None:
    result = {"requestAccepted": True}
    event = _event(observed_result=result)
    result["requestAccepted"] = False
    result["private"] = {"nested": []}
    with pytest.raises(TypeError):
        event.observed_result["private"] = True
    subject.append_metadata_observation(tmp_path, event)
    stored = subject._read_metadata_observations(tmp_path)[0]
    assert stored["observedResult"] == {"requestAccepted": True}
