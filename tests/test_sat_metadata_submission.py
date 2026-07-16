import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Event
from unittest.mock import Mock

import pytest

import cfdi_vault.sat_live_request_state as legacy_state
import cfdi_vault.sat_metadata_recovery as lifecycle
import cfdi_vault.sat_metadata_recovery_state as recovery_state
import cfdi_vault.sat_metadata_submission as subject
from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_contract import SatOutcomeAction, SatRequestResult
from cfdi_vault.sat_v15_adapter import SatV15AdapterError

NOW = datetime(2026, 6, 30, tzinfo=timezone.utc)
COMMIT = "f" * 40


def test_campaign_request_uses_preallocated_recovery_ref_and_restarts_idempotently(tmp_path) -> None:
    query = _query()
    expected = recovery_state.campaign_metadata_recovery_ref(
        "profile-synthetic", query.criteria_hash(),
    )

    def submit(_: DownloadQuery) -> SatRequestResult:
        private = json.loads(subject.metadata_submission_claim_path(tmp_path).read_text())
        assert private["claims"][0]["recoveryRef"] == expected
        return _result()

    requester = Mock(submit_request=Mock(side_effect=submit))

    first = _submit_campaign(tmp_path, requester, query, expected)
    restarted = _submit_campaign(tmp_path, requester, query, expected)

    assert first == restarted
    assert first.status is subject.SubmissionStatus.ACCEPTED
    assert first.recovery_ref == expected
    assert requester.submit_request.call_count == 1
    saved = recovery_state.load_metadata_recovery_state(tmp_path, expected)
    assert saved.id_solicitud == "synthetic-request-alpha"
    assert saved.recovery.recovery_ref == expected
    assert saved.observation_provenance.entry_point == "sat-campaign"


@pytest.mark.parametrize("expected", (None, "", "run-invalid", "run-000000000000"))
def test_campaign_missing_or_wrong_preallocated_ref_is_rejected_before_contact(
    tmp_path, expected,
) -> None:
    query = _query()
    requester = Mock()

    with pytest.raises(subject.MetadataSubmissionError, match="submission-input-invalid"):
        _submit_campaign(tmp_path, requester, query, expected)

    assert requester.submit_request.call_count == 0
    assert not subject.metadata_submission_claim_path(tmp_path).exists()


def test_campaign_rejects_existing_same_criteria_under_different_ref_before_contact(
    tmp_path,
) -> None:
    query = _query()
    legacy_ref = recovery_state.recovery_ref(
        "profile-synthetic", query.criteria_hash(), "synthetic-request-alpha",
    )
    record = recovery_state.new_metadata_recovery_state(
        recovery=lifecycle.start_metadata_recovery(legacy_ref, created_at=NOW),
        id_solicitud="synthetic-request-alpha", profile_id="profile-synthetic",
        direction="received", kind="metadata", fecha_inicial="2026-06-30",
        fecha_final="2026-06-30", criteria_hash=query.criteria_hash(),
        authorization_ref="authorization-synthetic",
    )
    recovery_state.save_metadata_recovery_state(tmp_path, record)
    requester = Mock()
    expected = recovery_state.campaign_metadata_recovery_ref(
        "profile-synthetic", query.criteria_hash(),
    )

    with pytest.raises(subject.MetadataSubmissionError, match="submission-recovery-ref-conflict"):
        _submit_campaign(tmp_path, requester, query, expected)

    assert requester.submit_request.call_count == 0
    assert not subject.metadata_submission_claim_path(tmp_path).exists()


@pytest.mark.parametrize(
    ("outcome", "status"),
    ((RuntimeError("private"), subject.SubmissionStatus.SUBMIT_UNCERTAIN),
     (SatRequestResult("", "5003", "rejected", SatOutcomeAction.PERMANENT_FAILURE),
      subject.SubmissionStatus.SUBMIT_FAILED)),
)
def test_campaign_terminal_submission_retains_preallocated_lineage(
    tmp_path, outcome, status,
) -> None:
    query = _query()
    expected = recovery_state.campaign_metadata_recovery_ref(
        "profile-synthetic", query.criteria_hash(),
    )
    requester = Mock()
    requester.submit_request.side_effect = outcome if isinstance(outcome, Exception) else None
    if not isinstance(outcome, Exception):
        requester.submit_request.return_value = outcome

    claim = _submit_campaign(tmp_path, requester, query, expected)
    restarted = _submit_campaign(tmp_path, requester, query, expected)

    assert claim == restarted
    assert claim.status is status and claim.recovery_ref == expected
    assert requester.submit_request.call_count == 1
    assert recovery_state.list_metadata_recovery_states(tmp_path) == ()


def test_accepted_request_is_claimed_before_network_and_reused_with_new_authorization(tmp_path) -> None:
    query = _query()

    def submit(_: DownloadQuery) -> SatRequestResult:
        path = subject.metadata_submission_claim_path(tmp_path)
        assert json.loads(path.read_text(encoding="utf-8"))["claims"][0]["status"] == "claimed"
        with recovery_state._exclusive_state_lock(recovery_state._resolved_state_path(
            tmp_path, repo_root=None, create_parent=True
        )):
            pass  # The transaction lock is not held during network I/O.
        return _result()

    requester = Mock(submit_request=Mock(side_effect=submit))
    accepted = subject.submit_metadata_recovery_once(
        requester=requester, query=query, now=NOW, storage_root=tmp_path,
        profile_id="profile-synthetic", criteria_hash=query.criteria_hash(),
        authorization_ref="authorization-synthetic-a",
        tested_commit=COMMIT, entry_point="metadata-recover-live",
    )
    repeated = subject.submit_metadata_recovery_once(
        requester=requester, query=query, now=NOW, storage_root=tmp_path,
        profile_id="profile-synthetic", criteria_hash=query.criteria_hash(),
        authorization_ref="authorization-synthetic-b",
        tested_commit=COMMIT, entry_point="metadata-recover-live",
    )

    assert accepted.status == repeated.status == subject.SubmissionStatus.ACCEPTED and requester.submit_request.call_count == 1
    saved = recovery_state.load_metadata_recovery_state(tmp_path, accepted.recovery_ref)
    assert saved.recovery.record_count is None
    assert saved.observation_provenance == recovery_state.MetadataObservationProvenance(
        1, COMMIT, NOW, "metadata-recover-live",
    )
    assert saved.to_redacted_document()["recordCount"] == "not_reported"
    serialized = repr(accepted.to_redacted_document())
    for private in ("profile-synthetic", query.criteria_hash(), "authorization-synthetic-a", "synthetic-request-alpha"):
        assert private not in serialized


@pytest.mark.parametrize(
    ("outcome", "expected"),
    (
        (RuntimeError("private failure"), subject.SubmissionStatus.SUBMIT_UNCERTAIN),
        (SatRequestResult("", "5000", "accepted", SatOutcomeAction.ACCEPTED), subject.SubmissionStatus.SUBMIT_UNCERTAIN),
        (object(), subject.SubmissionStatus.SUBMIT_UNCERTAIN),
        (SatRequestResult("", "5003", "rejected", SatOutcomeAction.PERMANENT_FAILURE), subject.SubmissionStatus.SUBMIT_FAILED),
    ),
)
def test_terminal_outcomes_never_submit_again(tmp_path, outcome, expected) -> None:
    query = _query()
    requester = Mock()
    requester.submit_request.side_effect = outcome if isinstance(outcome, Exception) else None
    if not isinstance(outcome, Exception):
        requester.submit_request.return_value = outcome
    first = _submit(tmp_path, requester, query)
    second = _submit(tmp_path, requester, query, authorization="authorization-replacement")
    assert first.status == second.status == expected
    assert requester.submit_request.call_count == 1


@pytest.mark.parametrize(
    ("sat_code", "category"),
    (
        ("5003", "sat_too_many_results"),
        (" 5003\t", "sat_too_many_results"),
        (5003, "sat_rejected"),
        ("5004", "sat_rejected"),
    ),
)
def test_sat_rejection_category_is_persisted_without_raw_response(
    tmp_path, sat_code: object, category: str,
) -> None:
    private = f"synthetic-private:{tmp_path.resolve()}"
    requester = Mock(submit_request=Mock(return_value=SatRequestResult(
        "", sat_code, private, SatOutcomeAction.PERMANENT_FAILURE,
        raw_response={"private": private},
    )))

    first = _submit(tmp_path, requester, _query())
    restarted = _submit(tmp_path, requester, _query())

    assert first == restarted
    assert first.status is subject.SubmissionStatus.SUBMIT_FAILED
    assert first.failure_category.value == category
    assert first.to_redacted_document()["failureCategory"] == category
    persisted = subject.metadata_submission_claim_path(tmp_path).read_text(encoding="utf-8")
    assert private not in persisted


@pytest.mark.parametrize("action", (SatOutcomeAction.RETRY, object()))
def test_retry_or_unexpected_action_remains_uncertain(tmp_path, action: object) -> None:
    requester = Mock(submit_request=Mock(return_value=SatRequestResult(
        "", "5004", "private", action,
    )))

    claim = _submit(tmp_path, requester, _query())

    assert claim.status is subject.SubmissionStatus.SUBMIT_UNCERTAIN
    assert claim.failure_category is subject.SubmissionFailureCategory.SUBMIT_UNCERTAIN


def test_internal_outcome_repr_never_exposes_request_id() -> None:
    private_id = "synthetic-private-request-id"
    requester = Mock(submit_request=Mock(return_value=SatRequestResult(
        private_id, "5000", "accepted", SatOutcomeAction.ACCEPTED,
    )))

    outcome = subject._call_requester(requester=requester, query=_query())

    assert private_id not in repr(outcome)


@pytest.mark.parametrize(
    ("stage", "kind", "category"),
    (
        ("preflight", "guard_failed", "configuration_invalid"),
        ("credential_load", "credential_load_failed", "credential_invalid"),
        ("auth_envelope_build", "xmlsig_failed", "signature_invalid"),
        ("token_extract", "token_missing", "identity_invalid"),
        ("auth_transport", "connect_timeout", "endpoint_failed"),
    ),
)
def test_precontact_adapter_failure_persists_only_safe_category(
    tmp_path, stage: str, kind: str, category: str,
) -> None:
    private = f"synthetic-private:{tmp_path.resolve()}"
    requester = Mock(submit_request=Mock(side_effect=SatV15AdapterError(
        private, stage=stage, error_kind=kind, safe_hint=private,
    )))

    claim = _submit(tmp_path, requester, _query())

    assert claim.status is subject.SubmissionStatus.SUBMIT_FAILED
    assert claim.failure_category.value == category
    assert private not in subject.metadata_submission_claim_path(tmp_path).read_text()


@pytest.mark.parametrize(
    "failure",
    (
        SatV15AdapterError(
            "private", stage="metadata_request_transport", error_kind="timeout",
            effect_unknown=True,
        ),
        SatV15AdapterError(
            "private", stage="unknown", error_kind="unknown_live_adapter_failure",
        ),
        RuntimeError("private"),
    ),
)
def test_unknown_or_effect_unknown_failure_is_terminal_uncertain(tmp_path, failure) -> None:
    claim = _submit(tmp_path, Mock(submit_request=Mock(side_effect=failure)), _query())

    assert claim.status is subject.SubmissionStatus.SUBMIT_UNCERTAIN
    assert claim.failure_category is subject.SubmissionFailureCategory.SUBMIT_UNCERTAIN


@pytest.mark.parametrize(
    ("status", "category"),
    (
        ("accepted", "sat_too_many_results"),
        ("submit_uncertain", "sat_too_many_results"),
        ("submit_failed", "submit_uncertain"),
        ("submit_failed", "forged-5003"),
    ),
)
def test_claim_codec_rejects_forged_or_incoherent_category(
    tmp_path, status: str, category: str,
) -> None:
    _submit(tmp_path, Mock(submit_request=Mock(return_value=_result())), _query())
    path = subject.metadata_submission_claim_path(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["claims"][0]["status"] = status
    document["claims"][0]["failureCategory"] = category
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(subject.MetadataSubmissionError, match="submission-state-invalid"):
        _submit(tmp_path, Mock(), _query())


def test_legacy_failure_without_category_loads_conservatively(tmp_path) -> None:
    requester = Mock(submit_request=Mock(return_value=SatRequestResult(
        "", "5003", "private", SatOutcomeAction.PERMANENT_FAILURE,
    )))
    _submit(tmp_path, requester, _query())
    path = subject.metadata_submission_claim_path(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["schemaVersion"] = 1
    document["claims"][0].pop("failureCategory")
    path.write_text(json.dumps(document), encoding="utf-8")

    loaded = _submit(tmp_path, requester, _query())

    assert loaded.status is subject.SubmissionStatus.SUBMIT_FAILED
    assert loaded.failure_category is subject.SubmissionFailureCategory.LEGACY_FAILURE
    assert loaded.failure_category is not subject.SubmissionFailureCategory.SAT_TOO_MANY_RESULTS
    assert requester.submit_request.call_count == 1


def test_schema2_rejects_forged_legacy_failure_category(tmp_path) -> None:
    requester = Mock(submit_request=Mock(return_value=SatRequestResult(
        "", "5004", "private", SatOutcomeAction.PERMANENT_FAILURE,
    )))
    _submit(tmp_path, requester, _query())
    path = subject.metadata_submission_claim_path(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["claims"][0]["failureCategory"] = "legacy_failure"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(subject.MetadataSubmissionError, match="submission-state-invalid"):
        _submit(tmp_path, Mock(), _query())


def test_rewriting_schema1_failure_normalizes_it_to_conservative_schema2(tmp_path) -> None:
    first_query = _query()
    requester = Mock(submit_request=Mock(return_value=SatRequestResult(
        "", "5003", "private", SatOutcomeAction.PERMANENT_FAILURE,
    )))
    _submit(tmp_path, requester, first_query)
    path = subject.metadata_submission_claim_path(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["schemaVersion"] = 1
    document["claims"][0].pop("failureCategory")
    path.write_text(json.dumps(document), encoding="utf-8")
    legacy = _submit(tmp_path, requester, first_query)
    assert legacy.failure_category is subject.SubmissionFailureCategory.LEGACY_FAILURE

    second_query = replace(
        first_query,
        period=DateTimePeriod(NOW - timedelta(days=1), NOW - timedelta(minutes=1)),
    )
    _submit(tmp_path, requester, second_query)
    migrated = _submit(tmp_path, requester, first_query)

    assert migrated.status is subject.SubmissionStatus.SUBMIT_UNCERTAIN
    assert migrated.failure_category is subject.SubmissionFailureCategory.SUBMIT_UNCERTAIN
    assert migrated.failure_category is not subject.SubmissionFailureCategory.SAT_TOO_MANY_RESULTS


def test_crash_after_recovery_write_reconciles_without_second_post(tmp_path, monkeypatch) -> None:
    query = _query()
    requester = Mock(submit_request=Mock(return_value=_result()))
    original = subject._write_claims
    writes = 0

    def crash_on_accept(*args, **kwargs):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise subject.MetadataSubmissionError("synthetic-crash")
        return original(*args, **kwargs)

    monkeypatch.setattr(subject, "_write_claims", crash_on_accept)
    with pytest.raises(subject.MetadataSubmissionError, match="synthetic-crash"):
        _submit(tmp_path, requester, query)
    assert len(recovery_state.list_metadata_recovery_states(tmp_path)) == 1
    monkeypatch.setattr(subject, "_write_claims", original)
    assert _submit(tmp_path, requester, query).status == subject.SubmissionStatus.ACCEPTED and requester.submit_request.call_count == 1


def test_concurrent_callers_make_at_most_one_request(tmp_path) -> None:
    query = _query()
    entered, release = Event(), Event()

    def submit(_: DownloadQuery) -> SatRequestResult:
        entered.set()
        assert release.wait(5)
        return _result()

    requester = Mock(submit_request=Mock(side_effect=submit))
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(_submit, tmp_path, requester, query)
        assert entered.wait(5)
        second = pool.submit(_submit, tmp_path, requester, query)
        concurrent = second.result(timeout=5)
        release.set()
        first.result(timeout=5)
    assert concurrent.status == subject.SubmissionStatus.SUBMIT_UNCERTAIN and requester.submit_request.call_count == 1


def test_claim_store_rejects_duplicate_json_keys(tmp_path) -> None:
    path = subject.metadata_submission_claim_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('{"schemaVersion":1,"claims":[],"claims":[]}', encoding="utf-8")
    with pytest.raises(subject.MetadataSubmissionError):
        _submit(tmp_path, Mock(), _query())


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("profile_id", " "), ("profile_id", 1),
        ("authorization_ref", "\n"), ("authorization_ref", None),
        ("criteria_hash", "A" * 64), ("criteria_hash", 7),
        ("now", datetime(2026, 6, 30)), ("now", "2026-06-30"),
        ("tested_commit", "F" * 40), ("tested_commit", None),
        ("entry_point", "metadata-recovery-status"),
    ),
)
def test_invalid_identity_never_creates_claim_or_calls_requester(tmp_path, field, value) -> None:
    query = _query()
    arguments = {
        "requester": Mock(), "query": query, "now": NOW, "storage_root": tmp_path,
        "profile_id": "profile-synthetic", "criteria_hash": query.criteria_hash(),
        "authorization_ref": "authorization-synthetic",
        "tested_commit": COMMIT, "entry_point": "metadata-recover-live",
    }
    arguments[field] = value

    with pytest.raises(subject.MetadataSubmissionError, match="submission-input-invalid"):
        subject.submit_metadata_recovery_once(**arguments)

    assert arguments["requester"].submit_request.call_count == 0
    assert not subject.metadata_submission_claim_path(tmp_path).exists()


@pytest.mark.parametrize("variant", ("query-type", "direction", "kind", "period-naive", "period-reversed", "blank-tenant"))
def test_invalid_query_scope_never_creates_claim_or_calls_requester(tmp_path, variant: str) -> None:
    query = _query()
    if variant == "query-type":
        query = object()
    elif variant == "direction":
        query = replace(query, direction="received")
    elif variant == "kind":
        query = replace(query, request_type=RequestType.CFDI)
    elif variant == "period-naive":
        query = replace(query, period=DateTimePeriod(NOW.replace(tzinfo=None), NOW.replace(tzinfo=None)))
    elif variant == "period-reversed":
        period = DateTimePeriod(NOW, NOW)
        object.__setattr__(period, "end", NOW - timedelta(seconds=1))
        query = replace(query, period=period)
    else:
        query = replace(query, tenant_id=" ")
    requester = Mock()

    with pytest.raises(subject.MetadataSubmissionError, match="submission-input-invalid"):
        subject.submit_metadata_recovery_once(
            requester=requester, query=query, now=NOW, storage_root=tmp_path,
            profile_id="profile-synthetic", criteria_hash="a" * 64,
            authorization_ref="authorization-synthetic",
            tested_commit=COMMIT, entry_point="metadata-recover-live",
        )

    assert requester.submit_request.call_count == 0
    assert not subject.metadata_submission_claim_path(tmp_path).exists()


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("schemaVersion",), True), (("claims", 0, "claimRef"), 9),
        (("claims", 0, "createdAt"), "2026-06-30T00:00:00"),
        (("claims", 0, "updatedAt"), "2026-06-29T00:00:00+00:00"),
        (("claims", 0, "profileId"), " "), (("claims", 0, "ownerRef"), " "),
        (("claims", 0, "criteriaHash"), "b" * 64),
        (("claims", 0, "query", "direction"), "folio"),
        (("claims", 0, "query", "requestType"), "cfdi"),
        (("claims", 0, "query", "tenantId"), 3),
        (("claims", 0, "query", "receiverRfcs"), [7]),
        (("claims", 0, "query", "period", "start"), "not-a-date"),
        (("claims", 0, "status"), "claimed"),
    ),
)
def test_claim_store_rejects_non_native_or_incoherent_private_state(tmp_path, path, value) -> None:
    _submit(tmp_path, Mock(submit_request=Mock(return_value=_result())), _query())
    claim_path = subject.metadata_submission_claim_path(tmp_path)
    document = json.loads(claim_path.read_text(encoding="utf-8"))
    _set_path(document, path, value)
    claim_path.write_text(json.dumps(document), encoding="utf-8")
    requester = Mock()

    with pytest.raises(subject.MetadataSubmissionError, match="submission-state-invalid") as captured:
        _submit(tmp_path, requester, _query())

    assert requester.submit_request.call_count == 0
    assert captured.value.__cause__ is captured.value.__context__ is None


def test_claim_store_rejects_duplicate_nested_json_keys(tmp_path) -> None:
    path = subject.metadata_submission_claim_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('{"schemaVersion":1,"claims":[{"query":{"period":{},"period":{}}}]}', encoding="utf-8")

    with pytest.raises(subject.MetadataSubmissionError, match="submission-state-invalid") as captured:
        _submit(tmp_path, Mock(), _query())

    assert captured.value.__cause__ is captured.value.__context__ is None


def test_claim_write_error_has_no_private_exception_context(tmp_path, monkeypatch) -> None:
    private = f"synthetic-private:{tmp_path.resolve()}"
    monkeypatch.setattr(subject.os, "replace", Mock(side_effect=OSError(private)))

    with pytest.raises(subject.MetadataSubmissionError, match="submission-state-write-failed") as captured:
        _submit(tmp_path, Mock(), _query())

    assert private not in repr(captured.value)
    assert captured.value.__cause__ is captured.value.__context__ is None


def test_exact_legacy_request_blocks_new_claim_even_with_new_authorization(tmp_path) -> None:
    query = _query()
    legacy_state.persist_live_metadata_request(
        storage_root=tmp_path, profile_id="profile-synthetic", query=query,
        operation="metadata", id_solicitud="synthetic-legacy-request", sat_code="5000",
        sat_message="accepted", source_command="legacy-synthetic", permit_ref="permit-synthetic",
        now=NOW,
    )
    requester = Mock()

    for authorization in ("authorization-synthetic", "authorization-replacement"):
        with pytest.raises(subject.MetadataSubmissionError, match="submission-legacy-existing"):
            _submit(tmp_path, requester, query, authorization=authorization)

    assert requester.submit_request.call_count == 0
    assert not subject.metadata_submission_claim_path(tmp_path).exists()


def test_legacy_scan_runs_while_recovery_state_lock_is_held(tmp_path, monkeypatch) -> None:
    recovery_path = recovery_state._resolved_state_path(tmp_path, repo_root=None, create_parent=True)

    def inspect_while_locked(_):
        with pytest.raises(recovery_state.MetadataRecoveryStateError, match="recovery-state-busy"):
            with recovery_state._exclusive_state_lock(recovery_path):
                pass
        return ()

    monkeypatch.setattr(legacy_state, "list_live_metadata_requests", inspect_while_locked)

    assert _submit(tmp_path, Mock(), _query()).status is subject.SubmissionStatus.SUBMIT_UNCERTAIN


@pytest.mark.parametrize("legacy_document", ("{", "ambiguous"))
def test_invalid_or_ambiguous_legacy_state_fails_closed(tmp_path, legacy_document: str) -> None:
    query = _query()
    path = legacy_state.live_metadata_state_path(tmp_path)
    path.parent.mkdir(parents=True)
    if legacy_document == "{":
        path.write_text("{", encoding="utf-8")
    else:
        legacy_state.persist_live_metadata_request(
            storage_root=tmp_path, profile_id="profile-synthetic", query=query,
            operation="metadata", id_solicitud="synthetic-legacy-request", sat_code="5000",
            sat_message="accepted", source_command="legacy-synthetic", permit_ref="permit-synthetic",
            now=NOW,
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        document["requests"][0]["criteriaHash"] = "b" * 64
        path.write_text(json.dumps(document), encoding="utf-8")
    requester = Mock()

    with pytest.raises(subject.MetadataSubmissionError, match="submission-legacy-state-invalid") as captured:
        _submit(tmp_path, requester, query)

    assert requester.submit_request.call_count == 0
    assert not subject.metadata_submission_claim_path(tmp_path).exists()
    assert captured.value.__cause__ is captured.value.__context__ is None


def _submit(tmp_path, requester, query: DownloadQuery, authorization: str = "authorization-synthetic"):
    return subject.submit_metadata_recovery_once(
        requester=requester, query=query, now=NOW, storage_root=tmp_path,
        profile_id="profile-synthetic", criteria_hash=query.criteria_hash(),
        authorization_ref=authorization,
        tested_commit=COMMIT, entry_point="metadata-recover-live",
    )


def _submit_campaign(tmp_path, requester, query: DownloadQuery, expected: str | None):
    return subject.submit_metadata_recovery_once(
        requester=requester, query=query, now=NOW, storage_root=tmp_path,
        profile_id="profile-synthetic", criteria_hash=query.criteria_hash(),
        authorization_ref="authorization-synthetic", expected_recovery_ref=expected,
        tested_commit=COMMIT, entry_point="sat-campaign",
    )


def _query() -> DownloadQuery:
    return DownloadQuery(
        tenant_id="tenant-synthetic", requester_rfc="XAXX010101000",
        direction=DownloadDirection.RECEIVED, request_type=RequestType.METADATA,
        period=DateTimePeriod(NOW, NOW.replace(hour=23, minute=59)),
    )


def _result() -> SatRequestResult:
    return SatRequestResult("synthetic-request-alpha", "5000", "accepted", SatOutcomeAction.ACCEPTED)


def _set_path(document, path, value) -> None:
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
