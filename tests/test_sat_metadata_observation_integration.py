from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile

import pytest

import cfdi_vault.sat_metadata_observation_integration as subject
import cfdi_vault.sat_metadata_recovery as lifecycle
import cfdi_vault.sat_metadata_recovery_state as state
from cfdi_vault.package_processor import MemoryPackageStorage
from cfdi_vault.sat_metadata_artifact_state import MetadataPackageArtifactState
from cfdi_vault.sat_metadata_package import process_metadata_package
from cfdi_vault.sat_metadata_recovery_runner import MetadataRecoveryAdvanceOutcome

NOW = datetime(2026, 6, 30, tzinfo=timezone.utc)
COMMIT = "a" * 40

def _record(created_at: datetime = NOW):
    recovery = lifecycle.start_metadata_recovery(
        state.recovery_ref("profile-private", "b" * 64, "request-private"), created_at=created_at,
    )
    return state.new_metadata_recovery_state(
        recovery=recovery, id_solicitud="request-private", profile_id="profile-private",
        direction="received", kind="metadata", fecha_inicial="2026-06-30",
        fecha_final="2026-06-30", criteria_hash="b" * 64,
        authorization_ref="permit-private",
    )

def _out(**changes: object) -> MetadataRecoveryAdvanceOutcome:
    values = dict(recovery={}, sat_contacted=False, verify_count=0, download_attempts=0)
    return MetadataRecoveryAdvanceOutcome(**(values | changes))

def _context(monkeypatch, root: Path):
    monkeypatch.setattr(subject, "current_repo_identity", lambda *_: COMMIT)
    return subject.prepare_metadata_observation_context(root, repo_root=root.parent / "checkout")

def _events(root: Path) -> list[dict[str, object]]:
    path = root / "state" / "sat-metadata-observations.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

def test_accepted_submission_appends_once_and_restart_reconciles_without_duplicate(monkeypatch, tmp_path) -> None:
    record = _record()
    first = subject.observe_metadata_recovery(
        _context(monkeypatch, tmp_path), before=None, after=record, outcome=_out(),
        observed_at=NOW, entry_point="metadata-recover-live", reconcile_submission=True,
    )
    second = subject.observe_metadata_recovery(
        _context(monkeypatch, tmp_path), before=record, after=record, outcome=_out(),
        observed_at=NOW + timedelta(minutes=1), entry_point="metadata-recover-live",
        reconcile_submission=True,
    )
    assert (first, second) == (1, 0)
    event = _events(tmp_path)[0]
    assert event["hypothesis"]["code"] == "H1"
    assert event["observedResult"]["requestAccepted"] is True
    serialized = json.dumps(event)
    for private in ("request-private", "profile-private", "permit-private", str(tmp_path)):
        assert private not in serialized

def test_due_verify_projects_exact_h5_provenance(monkeypatch, tmp_path) -> None:
    before = _record()
    after = replace(before, recovery=lifecycle.record_pending_verification(
        before.recovery, checked_at=NOW + timedelta(minutes=5),
    ))
    outcome = _out(sat_contacted=True, verify_count=1,
                   verify_contacts_not_before_due=1)
    subject.observe_metadata_recovery(
        _context(monkeypatch, tmp_path), before=before, after=after, outcome=outcome,
        observed_at=NOW + timedelta(minutes=5), entry_point="metadata-recovery-runner",
    )
    h5 = next(item for item in _events(tmp_path) if item["hypothesis"]["code"] == "H5")
    assert h5["observedResult"]["contactNotBeforeDue"] is True
    assert h5["observedResult"]["verifyAttempts"] == 1

def test_download_projects_structural_aggregates_without_headers_or_private_values(monkeypatch, tmp_path) -> None:
    before = _record()
    package_ref = state.package_ref("package-private")
    ready = lifecycle.record_finished_verification(
        before.recovery, checked_at=NOW + timedelta(minutes=5),
        package_refs=(package_ref,), record_count=None,
    )
    content = _zip_bytes("uuid~rfcEmisor~rfcReceptor~fechaEmision~estadoComprobante~tipoComprobante")
    processed = process_metadata_package(before.recovery.recovery_ref, 1, content, MemoryPackageStorage())
    artifact = MetadataPackageArtifactState.from_processed(package_ref, processed)
    downloading = lifecycle.begin_package_download(ready, package_ref)
    completed = lifecycle.record_package_download(downloading, package_ref, zip_valid=True, txt_count=1)
    after = replace(before, recovery=completed,
                    package_bindings=(state.PackageIdBinding(package_ref, "package-private"),),
                    artifact_bindings=(artifact,))
    subject.observe_metadata_recovery(
        _context(monkeypatch, tmp_path), before=replace(after, recovery=ready, artifact_bindings=()),
        after=after, outcome=_out(sat_contacted=True, download_attempts=1),
        observed_at=NOW + timedelta(minutes=6), entry_point="metadata-recovery-runner",
    )
    serialized = json.dumps(_events(tmp_path))
    assert all(item["hypothesis"]["code"] != "H5" for item in _events(tmp_path))
    assert '"parserCompatible": true' in serialized
    assert '"columnCount": 6' in serialized
    for forbidden in ("rfcEmisor", "package-private", "headers", "sha256", "storageKey"):
        assert forbidden not in serialized

def test_append_failure_is_sanitized_and_restart_reconciles(monkeypatch, tmp_path) -> None:
    record = _record()
    context = _context(monkeypatch, tmp_path)
    monkeypatch.setattr(subject, "append_metadata_observation", lambda *_a, **_k: (_ for _ in ()).throw(
        subject.MetadataObservationError("observation-write-uncertain")))
    with pytest.raises(subject.MetadataObservationError, match="observation-write-uncertain"):
        subject.observe_metadata_recovery(
            context, before=None, after=record, outcome=_out(), observed_at=NOW,
            entry_point="metadata-recover-live", reconcile_submission=True,
        )
    monkeypatch.setattr(subject, "_read_metadata_observations", lambda *_a, **_k: (_ for _ in ()).throw(
        subject.MetadataObservationError("private")))
    with pytest.raises(subject.MetadataObservationError, match="observation-ledger-unreadable"):
        _context(monkeypatch, tmp_path / "unreadable")
def test_stability_requires_same_root_and_distinct_execution(monkeypatch, tmp_path) -> None:
    for root, created in ((tmp_path / "one", NOW), (tmp_path / "one", NOW + timedelta(days=1)),
                          (tmp_path / "two", NOW + timedelta(days=2))):
        root.mkdir(exist_ok=True)
        record = _record(created)
        subject.observe_metadata_recovery(
            _context(monkeypatch, root), before=None, after=record, outcome=_out(),
            observed_at=created, entry_point="metadata-recover-live", reconcile_submission=True,
        )
    assert _events(tmp_path / "one")[-1]["stability"] == "stable"
    assert _events(tmp_path / "two")[-1]["stability"] == "observed_once"
def _zip_bytes(header: str) -> bytes:
    stream = BytesIO()
    with ZipFile(stream, "w") as archive:
        archive.writestr("metadata.txt", (header + "\nsynthetic~row\n").encode("utf-8-sig"))
    return stream.getvalue()
