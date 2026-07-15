from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import BytesIO
from threading import Event
from zipfile import ZipFile

import pytest

import cfdi_vault.sat_metadata_recovery as lifecycle
import cfdi_vault.sat_metadata_recovery_state as state
from cfdi_vault.domain import SatRequestState
from cfdi_vault.package_processor import MemoryPackageStorage
from cfdi_vault.sat_contract import SatDownloadResult, SatOutcomeAction, SatVerificationError, SatVerificationResult
from cfdi_vault.sat_metadata_recovery_runner import advance_metadata_recovery_once

NOW = datetime(2026, 6, 30, tzinfo=timezone.utc)
REQUEST = "synthetic-request"
PACKAGES = ("synthetic-package-a", "synthetic-package-b")
PROFILE, CRITERIA = "synthetic-profile", "a" * 64
RUN_REF = state.recovery_ref(PROFILE, CRITERIA, REQUEST)


class _Verifier:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[str] = []

    def verify_request(self, request_id: str):  # type: ignore[no-untyped-def]
        self.calls.append(request_id)
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class _Downloader:
    def __init__(self, results: dict[str, object] | None = None) -> None:
        self.results = results or {}
        self.calls: list[str] = []

    def download_package(self, package_id: str):  # type: ignore[no-untyped-def]
        self.calls.append(package_id)
        result = self.results[package_id]
        if isinstance(result, BaseException):
            raise result
        return result


class _DefinitiveError(RuntimeError):
    effect_unknown = False


def _zip() -> bytes:
    stream = BytesIO()
    with ZipFile(stream, "w") as archive:
        archive.writestr("metadata.txt", b"\xef\xbb\xbfVersion~Status\n1~Synthetic\n")
    return stream.getvalue()


def _verification(*, packages: tuple[str, ...] = (), action=SatOutcomeAction.FINISHED,
                  request_id: str = REQUEST, sat_code: str = "5000") -> SatVerificationResult:
    state_value = SatRequestState.FINISHED if action is SatOutcomeAction.FINISHED else SatRequestState.IN_PROCESS
    return SatVerificationResult(request_id, state_value, sat_code, "Synthetic", packages, action)


def _download(package_id: str, content: bytes | None = None) -> SatDownloadResult:
    return SatDownloadResult(package_id, "5000", "Synthetic", SatOutcomeAction.FINISHED,
                             _zip() if content is None else content)


def _saved(tmp_path, recovery=None):  # type: ignore[no-untyped-def]
    recovery = recovery or lifecycle.start_metadata_recovery(RUN_REF, created_at=NOW)
    record = state.new_metadata_recovery_state(
        recovery=recovery, id_solicitud=REQUEST, profile_id=PROFILE,
        direction="received", kind="metadata", fecha_inicial="2026-06-30",
        fecha_final="2026-06-30", criteria_hash=CRITERIA,
        authorization_ref="synthetic-authorization",
    )
    state.save_metadata_recovery_state(tmp_path, record)
    return record


def _advance(tmp_path, verifier, downloader, now, storage=None):  # type: ignore[no-untyped-def]
    return advance_metadata_recovery_once(
        storage_root=tmp_path, recovery_ref=RUN_REF, verifier=verifier,
        downloader=downloader, package_storage=storage or MemoryPackageStorage(), now=now,
    )


@pytest.mark.parametrize(
    ("now", "expected"),
    [(NOW + timedelta(minutes=4), "verify_scheduled"),
     (NOW + timedelta(days=7), "pending_after_budget")],
)
def test_not_due_and_deadline_make_no_sat_calls(tmp_path, now, expected) -> None:  # type: ignore[no-untyped-def]
    _saved(tmp_path)
    verifier, downloader = _Verifier(_verification()), _Downloader()
    outcome = _advance(tmp_path, verifier, downloader, now)
    assert outcome.recovery["status"] == expected
    assert (outcome.sat_contacted, outcome.verify_count, outcome.download_attempts) == (False, 0, 0)
    assert verifier.calls == downloader.calls == []


@pytest.mark.parametrize(
    ("result", "expected"),
    [(SatVerificationError(operation="verify", code="timeout", message="safe", retryable=True),
      "verify_scheduled"),
     (_verification(action=SatOutcomeAction.IN_PROGRESS), "verify_scheduled"),
     (ValueError("PRIVATE"), "verify_failed"),
     (_verification(request_id="mismatched"), "verify_failed")],
)
def test_verify_exception_and_mismatch_classification(tmp_path, result, expected) -> None:  # type: ignore[no-untyped-def]
    _saved(tmp_path)
    outcome = _advance(tmp_path, _Verifier(result), _Downloader(), NOW + timedelta(minutes=5))
    assert outcome.recovery["status"] == expected
    assert (outcome.sat_contacted, outcome.verify_count) == (True, 1)
    assert "PRIVATE" not in repr(outcome)
    loaded = state.load_metadata_recovery_state(tmp_path, RUN_REF)
    assert loaded.recovery.verify_attempts == 1
    if expected == "verify_scheduled":
        assert loaded.recovery.next_check_at == NOW + timedelta(minutes=20)


def test_finished_without_packages_is_no_data(tmp_path) -> None:
    _saved(tmp_path)
    outcome = _advance(tmp_path, _Verifier(_verification()), _Downloader(), NOW + timedelta(minutes=5))
    assert outcome.recovery["status"] == "no_data"
    assert outcome.recovery["recordCount"] == "not_reported"
    assert outcome.download_attempts == 0


def test_sat_no_data_code_never_writes_an_invented_zero(tmp_path) -> None:
    _saved(tmp_path)
    outcome = _advance(
        tmp_path,
        _Verifier(_verification(sat_code="5004")),
        _Downloader(),
        NOW + timedelta(minutes=5),
    )

    assert outcome.recovery["status"] == "no_data"
    assert outcome.recovery["recordCount"] == "not_reported"
    assert state.load_metadata_recovery_state(tmp_path, RUN_REF).recovery.record_count is None


def test_two_packages_download_once_in_binding_order_and_terminal_is_idempotent(tmp_path) -> None:
    _saved(tmp_path)
    downloader = _Downloader({item: _download(item) for item in PACKAGES})
    outcome = _advance(tmp_path, _Verifier(_verification(packages=PACKAGES)), downloader,
                       NOW + timedelta(minutes=5))
    assert outcome.recovery["status"] == "completed"
    assert downloader.calls == list(PACKAGES)
    assert (outcome.verify_count, outcome.download_attempts) == (1, 2)
    loaded = state.load_metadata_recovery_state(tmp_path, RUN_REF)
    assert loaded.recovery.record_count is None
    assert outcome.recovery["recordCount"] == "not_reported"
    assert len(loaded.artifact_bindings) == 2
    assert all(raw not in repr(outcome) for raw in (REQUEST, *PACKAGES))
    repeated = _advance(tmp_path, _Verifier(ValueError()), _Downloader(), NOW + timedelta(hours=1))
    assert (repeated.sat_contacted, repeated.verify_count, repeated.download_attempts) == (False, 0, 0)


def test_restart_with_claimed_download_becomes_uncertain_without_sat_call(tmp_path) -> None:
    record = _saved(tmp_path)
    ready = lifecycle.record_finished_verification(
        record.recovery, checked_at=NOW + timedelta(minutes=5),
        package_refs=(state.package_ref(PACKAGES[0]),), record_count=None,
    )
    claimed = lifecycle.begin_package_download(ready, ready.packages[0].package_ref)
    record = replace(record, recovery=claimed,
                     package_bindings=(state.PackageIdBinding(ready.packages[0].package_ref, PACKAGES[0]),))
    state.save_metadata_recovery_state(tmp_path, replace(_saved(tmp_path), recovery=ready,
        package_bindings=record.package_bindings))
    state.save_metadata_recovery_state(tmp_path, record)
    outcome = _advance(tmp_path, _Verifier(ValueError()), _Downloader(), NOW + timedelta(minutes=6))
    assert outcome.recovery["status"] == "download_uncertain"
    assert outcome.sat_contacted is False


@pytest.mark.parametrize(
    ("result", "expected"),
    [(TimeoutError("PRIVATE"), "download_uncertain"),
     (_DefinitiveError("PRIVATE"), "download_failed"),
     (_download(PACKAGES[0], b"not-a-zip"), "download_failed")],
)
def test_download_failures_are_terminal_and_redacted(tmp_path, result, expected) -> None:  # type: ignore[no-untyped-def]
    _saved(tmp_path)
    outcome = _advance(
        tmp_path, _Verifier(_verification(packages=(PACKAGES[0],))),
        _Downloader({PACKAGES[0]: result}), NOW + timedelta(minutes=5),
    )
    assert outcome.recovery["status"] == expected
    assert outcome.download_attempts == 1
    assert "PRIVATE" not in repr(outcome)


def test_operation_lock_prevents_concurrent_duplicate_verification(tmp_path) -> None:
    _saved(tmp_path)
    entered, release = Event(), Event()

    class Blocking(_Verifier):
        def verify_request(self, request_id: str):  # type: ignore[no-untyped-def]
            self.calls.append(request_id)
            entered.set()
            release.wait(2)
            return _verification()

    verifier = Blocking(_verification())
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(_advance, tmp_path, verifier, _Downloader(), NOW + timedelta(minutes=5))
        assert entered.wait(1)
        busy = _advance(tmp_path, verifier, _Downloader(), NOW + timedelta(minutes=5))
        release.set()
        first.result()
    assert busy.error_kind == "busy"
    assert (busy.sat_contacted, busy.verify_count, busy.download_attempts) == (False, 0, 0)
    assert verifier.calls == [REQUEST]
