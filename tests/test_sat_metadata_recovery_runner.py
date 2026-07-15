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
from cfdi_vault.sat_contract import (
    SatDownloadResult,
    SatOperation,
    SatOutcomeAction,
    SatPackageDownloadError,
    SatVerificationError,
    SatVerificationResult,
)
from cfdi_vault.sat_live_smoke import SatLiveSmokeError
from cfdi_vault.sat_metadata_recovery_runner import (
    advance_metadata_recovery_once,
    settle_metadata_recovery_locally,
)

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


def test_local_settlement_persists_deadline_without_live_dependencies(tmp_path) -> None:
    _saved(tmp_path)

    outcome = settle_metadata_recovery_locally(
        storage_root=tmp_path, recovery_ref=RUN_REF, now=NOW + timedelta(days=7),
    )

    assert outcome.requires_live is False
    assert outcome.recovery["status"] == "pending_after_budget"
    assert state.load_metadata_recovery_state(tmp_path, RUN_REF).recovery.status.value == "pending_after_budget"


def test_local_settlement_persists_crash_left_download_as_uncertain(tmp_path) -> None:
    record = _saved(tmp_path)
    package_ref = state.package_ref(PACKAGES[0])
    ready = lifecycle.record_finished_verification(
        record.recovery, checked_at=NOW + timedelta(minutes=5),
        package_refs=(package_ref,), record_count=None,
    )
    claimed = lifecycle.begin_package_download(ready, package_ref)
    ready_record = replace(
        record, recovery=claimed,
        package_bindings=(state.PackageIdBinding(package_ref, PACKAGES[0]),),
    )
    state.save_metadata_recovery_state(tmp_path, replace(ready_record, recovery=ready))
    state.save_metadata_recovery_state(tmp_path, ready_record)

    outcome = settle_metadata_recovery_locally(
        storage_root=tmp_path, recovery_ref=RUN_REF, now=NOW + timedelta(minutes=6),
    )

    assert (outcome.requires_live, outcome.error_kind) == (False, "download_uncertain")
    assert outcome.recovery["status"] == "download_uncertain"
    assert state.load_metadata_recovery_state(tmp_path, RUN_REF).recovery.status.value == "download_uncertain"


@pytest.mark.parametrize(
    ("result", "expected", "contacted"),
    [(SatVerificationError(operation="verify", code="timeout", message="safe", retryable=True),
      "verify_scheduled", True),
     (_verification(action=SatOutcomeAction.IN_PROGRESS), "verify_scheduled", True),
     (ValueError("PRIVATE"), "verify_failed", False),
     (_verification(request_id="mismatched"), "verify_failed", True)],
)
def test_verify_exception_and_mismatch_classification(tmp_path, result, expected, contacted) -> None:  # type: ignore[no-untyped-def]
    _saved(tmp_path)
    outcome = _advance(tmp_path, _Verifier(result), _Downloader(), NOW + timedelta(minutes=5))
    assert outcome.recovery["status"] == expected
    assert (outcome.sat_contacted, outcome.verify_count) == (contacted, 1)
    assert outcome.verify_contacts_not_before_due == int(contacted)
    assert "PRIVATE" not in repr(outcome)
    loaded = state.load_metadata_recovery_state(tmp_path, RUN_REF)
    assert loaded.recovery.verify_attempts == 1
    if expected == "verify_scheduled":
        assert loaded.recovery.next_check_at == NOW + timedelta(minutes=20)


@pytest.mark.parametrize(
    ("error_kind", "expected"),
    [
        ("connect_timeout", "verify_scheduled"),
        ("timeout", "verify_scheduled"),
        ("verify_read_timeout", "verify_scheduled"),
        ("remote_closed_connection", "verify_scheduled"),
        ("connection_reset_during_post", "verify_scheduled"),
        ("proxy_connect_failed", "verify_scheduled"),
        ("http_status_error", "verify_failed"),
        ("soap_fault", "verify_failed"),
        ("tls_handshake_failed", "verify_failed"),
        ("certificate_verify_failed", "verify_failed"),
        ("client_configuration_error", "verify_failed"),
        ("envelope_build_failed", "verify_failed"),
        ("xmlsig_failed", "verify_failed"),
        ("unexpected_http_response", "verify_failed"),
    ],
)
def test_live_verify_errors_use_exact_transient_allowlist(tmp_path, error_kind, expected) -> None:  # type: ignore[no-untyped-def]
    _saved(tmp_path)
    failure = SatLiveSmokeError(
        "synthetic safe failure", stage="verify_transport", error_kind=error_kind,
    )

    outcome = _advance(tmp_path, _Verifier(failure), _Downloader(), NOW + timedelta(minutes=5))

    assert outcome.recovery["status"] == expected
    assert (outcome.sat_contacted, outcome.verify_count) == (True, 1)


@pytest.mark.parametrize(
    ("failure", "contacted"),
    [
        (SatLiveSmokeError(stage="preflight"), False),
        (SatLiveSmokeError(stage="secret_resolve"), False),
        (SatLiveSmokeError(stage="credential_load"), False),
        (SatLiveSmokeError(stage="certificate_parse"), False),
        (SatLiveSmokeError(stage="private_key_load"), False),
        (SatLiveSmokeError(stage="xmlsig_sign"), False),
        (SatLiveSmokeError(stage="auth_envelope_build"), False),
        (SatLiveSmokeError(stage="auth_request_readiness"), False),
        (SatLiveSmokeError(stage="auth_transport"), True),
        (SatLiveSmokeError(stage="auth_response_parse"), True),
        (SatLiveSmokeError(stage="token_extract"), True),
        (SatLiveSmokeError(stage="verify_request_build"), True),
        (SatLiveSmokeError(stage="verify_request_readiness"), True),
        (SatLiveSmokeError(stage="verify_transport"), True),
        (SatLiveSmokeError(stage="verify_response_parse"), True),
        (SatLiveSmokeError(stage="unknown"), False),
        (TimeoutError(), True),
        (ConnectionError(), True),
        (SatPackageDownloadError(
            operation=SatOperation.DOWNLOAD, code="synthetic", message="safe",
        ), False),
    ],
)
def test_verify_contact_requires_explicit_stage_or_matching_contract(
    tmp_path, failure, contacted,
) -> None:  # type: ignore[no-untyped-def]
    _saved(tmp_path)

    outcome = _advance(tmp_path, _Verifier(failure), _Downloader(), NOW + timedelta(minutes=5))

    assert (outcome.sat_contacted, outcome.verify_count) == (contacted, 1)


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
    ("result", "expected", "contacted"),
    [(TimeoutError("PRIVATE"), "download_uncertain", True),
     (_DefinitiveError("PRIVATE"), "download_failed", True),
     (_download(PACKAGES[0], b"not-a-zip"), "download_failed", True)],
)
def test_download_failures_are_terminal_and_redacted(tmp_path, result, expected, contacted) -> None:  # type: ignore[no-untyped-def]
    _saved(tmp_path)
    outcome = _advance(
        tmp_path, _Verifier(_verification(packages=(PACKAGES[0],))),
        _Downloader({PACKAGES[0]: result}), NOW + timedelta(minutes=5),
    )
    assert outcome.recovery["status"] == expected
    assert (outcome.sat_contacted, outcome.download_attempts) == (contacted, 1)
    assert "PRIVATE" not in repr(outcome)


@pytest.mark.parametrize(
    ("failure", "contacted"),
    [
        (SatLiveSmokeError(stage="private_key_load", effect_unknown=False), False),
        (SatLiveSmokeError(stage="auth_transport", effect_unknown=True), True),
        (SatLiveSmokeError(stage="package_download_build", effect_unknown=False), True),
        (SatLiveSmokeError(stage="package_download_transport", effect_unknown=True), True),
        (SatLiveSmokeError(stage="package_download_parse", effect_unknown=True), True),
        (ConnectionError(), True),
        (SatPackageDownloadError(
            operation=SatOperation.DOWNLOAD, code="synthetic", message="safe",
        ), True),
        (SatVerificationError(
            operation=SatOperation.VERIFY, code="synthetic", message="safe",
        ), False),
        (_DefinitiveError("PRIVATE"), False),
    ],
)
def test_download_contact_requires_explicit_stage_or_matching_contract(
    tmp_path, failure, contacted,
) -> None:  # type: ignore[no-untyped-def]
    record = _saved(tmp_path)
    package_ref = state.package_ref(PACKAGES[0])
    ready = lifecycle.record_finished_verification(
        record.recovery, checked_at=NOW + timedelta(minutes=5),
        package_refs=(package_ref,), record_count=None,
    )
    state.save_metadata_recovery_state(tmp_path, replace(
        record, recovery=ready,
        package_bindings=(state.PackageIdBinding(package_ref, PACKAGES[0]),),
    ))

    outcome = _advance(
        tmp_path, _Verifier(ValueError()), _Downloader({PACKAGES[0]: failure}),
        NOW + timedelta(minutes=6),
    )

    assert (outcome.sat_contacted, outcome.download_attempts) == (contacted, 1)


def test_download_audit_survives_artifact_persistence_failure(tmp_path) -> None:
    class FailingStorage:
        def write_bytes_idempotent(self, key: str, content: bytes):  # type: ignore[no-untyped-def]
            raise RuntimeError("PRIVATE")

    _saved(tmp_path)
    outcome = _advance(
        tmp_path, _Verifier(_verification(packages=(PACKAGES[0],))),
        _Downloader({PACKAGES[0]: _download(PACKAGES[0])}),
        NOW + timedelta(minutes=5), storage=FailingStorage(),
    )

    assert outcome.error_kind == "download_failed"
    assert (outcome.sat_contacted, outcome.verify_count, outcome.download_attempts) == (True, 1, 1)
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


def test_verify_audit_survives_state_save_failure_after_contact(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _saved(tmp_path)
    verifier = _Verifier(_verification())

    def fail_save(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise state.MetadataRecoveryStateError("synthetic-save-failed")

    monkeypatch.setattr(state, "save_metadata_recovery_state", fail_save)
    outcome = _advance(tmp_path, verifier, _Downloader(), NOW + timedelta(minutes=5))

    assert outcome.error_kind == "state_failed"
    assert (outcome.sat_contacted, outcome.verify_count, outcome.download_attempts) == (True, 1, 0)
    assert verifier.calls == [REQUEST]
    assert "synthetic-save-failed" not in repr(outcome)
    assert REQUEST not in repr(outcome)


def test_download_audit_survives_state_save_failure_after_contact(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    record = _saved(tmp_path)
    package_ref = state.package_ref(PACKAGES[0])
    ready = lifecycle.record_finished_verification(
        record.recovery, checked_at=NOW + timedelta(minutes=5),
        package_refs=(package_ref,), record_count=None,
    )
    state.save_metadata_recovery_state(tmp_path, replace(
        record, recovery=ready,
        package_bindings=(state.PackageIdBinding(package_ref, PACKAGES[0]),),
    ))
    downloader = _Downloader({PACKAGES[0]: _download(PACKAGES[0])})
    real_save = state.save_metadata_recovery_state
    calls = 0

    def fail_second_save(*args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        if calls == 2:
            raise state.MetadataRecoveryStateError("synthetic-save-failed")
        return real_save(*args, **kwargs)

    monkeypatch.setattr(state, "save_metadata_recovery_state", fail_second_save)
    outcome = _advance(tmp_path, _Verifier(ValueError()), downloader, NOW + timedelta(minutes=6))

    assert outcome.error_kind == "state_failed"
    assert (outcome.sat_contacted, outcome.verify_count, outcome.download_attempts) == (True, 0, 1)
    assert downloader.calls == [PACKAGES[0]]
    assert "synthetic-save-failed" not in repr(outcome)
    assert PACKAGES[0] not in repr(outcome)


def test_pre_contact_state_failure_has_zero_audit_counts(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fail_load(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise state.MetadataRecoveryStateError("synthetic-load-failed")

    monkeypatch.setattr(state, "load_metadata_recovery_state", fail_load)
    outcome = _advance(tmp_path, _Verifier(ValueError()), _Downloader(), NOW)

    assert outcome.error_kind == "state_failed"
    assert (outcome.sat_contacted, outcome.verify_count, outcome.download_attempts) == (False, 0, 0)
