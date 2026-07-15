import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Event
from unittest.mock import Mock

import pytest

import cfdi_vault.sat_metadata_recovery_state as recovery_state
import cfdi_vault.sat_metadata_submission as subject
from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_contract import SatOutcomeAction, SatRequestResult

NOW = datetime(2026, 6, 30, tzinfo=timezone.utc)


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
    )
    repeated = subject.submit_metadata_recovery_once(
        requester=requester, query=query, now=NOW, storage_root=tmp_path,
        profile_id="profile-synthetic", criteria_hash=query.criteria_hash(),
        authorization_ref="authorization-synthetic-b",
    )

    assert accepted.status == repeated.status == subject.SubmissionStatus.ACCEPTED and requester.submit_request.call_count == 1
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


def _submit(tmp_path, requester, query: DownloadQuery, authorization: str = "authorization-synthetic"):
    return subject.submit_metadata_recovery_once(
        requester=requester, query=query, now=NOW, storage_root=tmp_path,
        profile_id="profile-synthetic", criteria_hash=query.criteria_hash(),
        authorization_ref=authorization,
    )


def _query() -> DownloadQuery:
    return DownloadQuery(
        tenant_id="tenant-synthetic", requester_rfc="XAXX010101000",
        direction=DownloadDirection.RECEIVED, request_type=RequestType.METADATA,
        period=DateTimePeriod(NOW, NOW.replace(hour=23, minute=59)),
    )


def _result() -> SatRequestResult:
    return SatRequestResult("synthetic-request-alpha", "5000", "accepted", SatOutcomeAction.ACCEPTED)
