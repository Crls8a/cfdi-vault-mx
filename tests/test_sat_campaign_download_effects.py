from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZIP_DEFLATED, ZipFile

import cfdi_vault.sat_campaign_download_effects as subject
import cfdi_vault.sat_metadata_recovery as lifecycle
import cfdi_vault.sat_metadata_recovery_state as state
from cfdi_vault.sat_campaign_manifest import CampaignWorkState
from cfdi_vault.sat_contract import SatDownloadResult, SatOutcomeAction


def _zip_bytes(name: str = "metadata.txt") -> bytes:
    output = BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        archive.writestr(name, b"synthetic")
    return output.getvalue()


PROFILE, CRITERIA = "synthetic-profile", "a" * 64
CAMPAIGN, WORK, PACKAGE = "cmp-0123456789ab", "work-abcdef012345", "synthetic-package-alpha"
NOW = datetime(2026, 7, 16, 12, tzinfo=timezone.utc)


def _setup(tmp_path: Path, monkeypatch):
    root, repo = tmp_path / "storage", tmp_path / "repo"
    recovery_ref = state.campaign_metadata_recovery_ref(PROFILE, CRITERIA)
    recovery = lifecycle.record_finished_verification(
        lifecycle.start_metadata_recovery(recovery_ref, created_at=NOW),
        checked_at=NOW, package_refs=(state.package_ref(PACKAGE),), record_count=1,
    )
    record = state.new_metadata_recovery_state(
        recovery=recovery, id_solicitud="synthetic-request", profile_id=PROFILE,
        direction="received", kind="metadata", fecha_inicial="2026-01-01",
        fecha_final="2026-01-14", criteria_hash=CRITERIA, authorization_ref="synthetic-grant",
        package_ids=(PACKAGE,),
    )
    manifest = SimpleNamespace(items=(SimpleNamespace(
        work_ref=WORK, state=CampaignWorkState.OUTSTANDING, recovery_ref=recovery_ref,
    ),))
    state.save_metadata_recovery_state(root, record, repo_root=repo)
    monkeypatch.setattr(subject, "load_campaign_manifest", lambda *a, **k: manifest)
    return root, repo, record, recovery_ref, state.package_ref(PACKAGE)


def _result(package_id=PACKAGE, content=None):
    return SatDownloadResult(
        package_id, "200", "ok", SatOutcomeAction.ACCEPTED,
        _zip_bytes() if content is None else content,
    )


def _run(root, repo, factory):
    return subject.execute_campaign_metadata_zip_download_once(
        storage_root=root, repo_root=repo, campaign_ref=CAMPAIGN,
        work_ref=WORK, downloader_factory=factory,
    )


def test_success_stores_opaque_zip_and_persists_pending_processing(tmp_path, monkeypatch):
    root, repo, record, recovery_ref, package_ref = _setup(tmp_path, monkeypatch)
    calls = []
    result = _run(root, repo, lambda: SimpleNamespace(
        download_package=lambda package: calls.append(package) or _result()))
    assert (result.zip_downloaded, result.zip_valid, result.status, calls) == (True, True, "downloaded", [PACKAGE])
    loaded = state.load_metadata_recovery_state(root, recovery_ref, repo_root=repo)
    assert loaded.recovery.status is lifecycle.RecoveryStatus.ZIP_DOWNLOADED_PENDING_PROCESSING
    assert loaded.zip_receipts[0].package_ref == package_ref
    files = tuple(root.rglob("*"))
    assert any(path.suffix == ".zip" for path in files) and not any(path.suffix == ".txt" for path in files)


def test_invalid_zip_and_mismatched_package_are_terminal(tmp_path, monkeypatch):
    root, repo, _, recovery_ref, _ = _setup(tmp_path, monkeypatch)
    bad = _run(root, repo, lambda: SimpleNamespace(download_package=lambda _: _result(content=b"bad")))
    assert (bad.status, bad.error) == ("failed", "zip-invalid")
    failed = state.load_metadata_recovery_state(root, recovery_ref, repo_root=repo)
    assert failed.recovery.status is lifecycle.RecoveryStatus.DOWNLOAD_FAILED

    root, repo, _, recovery_ref, _ = _setup(tmp_path / "second", monkeypatch)
    mismatch = _run(root, repo, lambda: SimpleNamespace(download_package=lambda _: _result("other")))
    assert (mismatch.status, mismatch.error) == ("failed", "download-invalid")
    assert state.load_metadata_recovery_state(root, recovery_ref, repo_root=repo).recovery.status is lifecycle.RecoveryStatus.DOWNLOAD_FAILED


def test_timeout_is_uncertain_and_retry_is_idempotent(tmp_path, monkeypatch):
    root, repo, _, recovery_ref, _ = _setup(tmp_path, monkeypatch)
    calls = []
    def timeout_factory():
        calls.append(1)
        raise TimeoutError

    first = _run(root, repo, timeout_factory)
    assert (first.status, first.error, len(calls)) == ("uncertain", "download-uncertain", 1)
    second = _run(root, repo, lambda: calls.append(2))
    assert second.error == "no-pending-package" and calls == [1]
    assert state.load_metadata_recovery_state(root, recovery_ref, repo_root=repo).recovery.status is lifecycle.RecoveryStatus.DOWNLOAD_UNCERTAIN


def test_receipt_replay_does_not_contact_adapter(tmp_path, monkeypatch):
    root, repo, _, _, _ = _setup(tmp_path, monkeypatch)
    calls = []
    def factory():
        calls.append(1)
        return SimpleNamespace(download_package=lambda _: _result())

    assert _run(root, repo, factory).status == "downloaded"
    replay = _run(root, repo, factory)
    assert (replay.status, replay.error, calls) == ("already-downloaded", None, [1])


def test_zip_proof_never_reads_members_or_accepts_traversal(tmp_path, monkeypatch):
    root, repo, _, _, _ = _setup(tmp_path, monkeypatch)
    content = _zip_bytes()
    unsafe_content = _zip_bytes("../evil.txt")
    monkeypatch.setattr(ZipFile, "read", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    monkeypatch.setattr(ZipFile, "open", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    assert _run(root, repo, lambda: SimpleNamespace(download_package=lambda _: _result(content=content))).status == "downloaded"

    root, repo, _, _, _ = _setup(tmp_path / "unsafe", monkeypatch)
    invalid = _run(root, repo, lambda: SimpleNamespace(
        download_package=lambda _: _result(content=unsafe_content)))
    assert (invalid.status, invalid.error) == ("failed", "zip-invalid")


def test_final_state_save_failure_fails_closed_without_recontact(tmp_path, monkeypatch):
    root, repo, _, recovery_ref, _ = _setup(tmp_path, monkeypatch)
    original = subject.save_metadata_recovery_state
    save_calls, contacts = [], []

    def flaky_save(*args, **kwargs):
        save_calls.append(1)
        if len(save_calls) == 2:
            raise RuntimeError("synthetic-state-save-failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(subject, "save_metadata_recovery_state", flaky_save)
    first = _run(root, repo, lambda: contacts.append(1) or SimpleNamespace(
        download_package=lambda _: _result()))
    second = _run(root, repo, lambda: contacts.append(2))
    loaded = state.load_metadata_recovery_state(root, recovery_ref, repo_root=repo)
    assert first.status == "uncertain"
    assert second.status != "in-progress" and contacts == [1]
    assert loaded.recovery.status is lifecycle.RecoveryStatus.DOWNLOAD_UNCERTAIN


def test_terminal_save_failure_fails_closed_without_recontact(tmp_path, monkeypatch):
    root, repo, _, recovery_ref, _ = _setup(tmp_path, monkeypatch)
    original = subject.save_metadata_recovery_state
    saves, contacts = [], []

    def flaky_save(*args, **kwargs):
        saves.append(1)
        if len(saves) == 2:
            raise RuntimeError("synthetic-terminal-save-failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(subject, "save_metadata_recovery_state", flaky_save)
    first = _run(root, repo, lambda: contacts.append(1) or SimpleNamespace(
        download_package=lambda _: _result(content=b"invalid")))
    second = _run(root, repo, lambda: contacts.append(2))
    loaded = state.load_metadata_recovery_state(root, recovery_ref, repo_root=repo)
    assert first.status == "failed"
    assert second.status != "in-progress" and contacts == [1]
    assert loaded.recovery.status is lifecycle.RecoveryStatus.DOWNLOAD_FAILED
