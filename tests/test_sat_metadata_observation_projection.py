from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import date, datetime, timedelta, timezone

import pytest

import cfdi_vault.sat_metadata_observation as ledger
import cfdi_vault.sat_metadata_observation_projection as subject

START = datetime(2026, 7, 15, 12, tzinfo=timezone.utc)
COMMIT = "a" * 40


def _facts(**changes: object) -> subject.MetadataObservationFacts:
    values = {
        "reducer_scope": object(),
        "tested_commit": COMMIT,
        "execution_started_at": START,
        "observed_at": START + timedelta(minutes=30),
        "sat_version": "v1.5",
        "kind": "Metadata",
        "direction": "received",
        "date_from": date(2026, 6, 30),
        "date_to": date(2026, 6, 30),
        "entry_point": "metadata-recover-live",
        "executed_stages": ("authenticate", "submit", "wait", "verify"),
        "lifecycle_status": "verify_scheduled",
        "lifecycle_transitioned": True,
        "sat_contacted": True,
        "authentication_accepted": True,
        "request_accepted": True,
        "terminal_status_received": False,
        "verify_attempts": 1,
        "verify_contacts": 1,
        "verify_contacts_not_before_due": 1,
        "verify_contacts_before_due": 0,
        "verify_contacts_due_unknown": 0,
        "package_count": 0,
        "downloaded_package_count": 0,
        "zip_valid_count": 0,
        "txt_count": 0,
        "column_count": None,
        "has_records": None,
        "utf8_sig": None,
        "delimiter_tilde": None,
        "parser_compatible": None,
    }
    values.update(changes)
    return subject.MetadataObservationFacts(**values)


def _by_code(events: tuple[ledger.NewMetadataObservation, ...]):
    return {event.hypothesis_code: event for event in events}


def test_completed_direct_evidence_confirms_all_hypotheses_and_is_append_ready(tmp_path) -> None:
    facts = _facts(
        executed_stages=("authenticate", "submit", "wait", "verify", "download", "extract", "inspect"),
        lifecycle_status="completed", terminal_status_received=True,
        verify_attempts=2, verify_contacts=2, verify_contacts_not_before_due=2,
        package_count=1, downloaded_package_count=1, zip_valid_count=1, txt_count=1,
        column_count=12, has_records=True, utf8_sig=True, delimiter_tilde=True,
        parser_compatible=True,
    )
    events = subject.project_metadata_observations(facts)
    assert {event.hypothesis_code: event.conclusion for event in events} == {
        code: "confirmed" for code in ("H1", "H2", "H3", "H4", "H5")
    }
    assert all(event.stability == "observed_once" for event in events)
    assert all(ledger.append_metadata_observation(tmp_path, event)[1] for event in events)


def test_partial_or_no_data_evidence_stays_inconclusive() -> None:
    accepted = _by_code(subject.project_metadata_observations(_facts()))
    no_data = _by_code(subject.project_metadata_observations(_facts(
        lifecycle_status="no_data", terminal_status_received=True,
    )))
    structural_unknown = _by_code(subject.project_metadata_observations(_facts(
        executed_stages=("authenticate", "submit", "wait", "verify", "download", "extract", "inspect"),
        lifecycle_status="completed", terminal_status_received=True,
        package_count=1, downloaded_package_count=1,
        zip_valid_count=1, txt_count=1, utf8_sig=True,
    )))
    assert (accepted["H1"].conclusion, accepted["H1"].next_correction_code,
            accepted["H5"].conclusion) == ("inconclusive", "observe-again", "inconclusive")
    assert (no_data["H1"].conclusion, no_data["H2"].conclusion,
            structural_unknown["H4"].conclusion) == ("inconclusive", "inconclusive", "inconclusive")


def test_direct_negative_evidence_refutes_only_supported_hypotheses() -> None:
    h3 = _by_code(subject.project_metadata_observations(_facts(
        executed_stages=("authenticate", "submit", "wait", "verify", "download", "extract", "inspect"),
        lifecycle_status="download_failed", terminal_status_received=True,
        verify_contacts_not_before_due=0, verify_contacts_before_due=1,
        package_count=1, downloaded_package_count=1, zip_valid_count=1, txt_count=0,
    )))
    h4 = _by_code(subject.project_metadata_observations(_facts(
        executed_stages=("authenticate", "submit", "wait", "verify", "download", "extract", "inspect"),
        lifecycle_status="completed", terminal_status_received=True,
        verify_contacts_not_before_due=0, verify_contacts_before_due=1,
        package_count=1, downloaded_package_count=1, zip_valid_count=1, txt_count=1,
        utf8_sig=False, delimiter_tilde=False, parser_compatible=False,
    )))
    assert (h3["H1"].conclusion, h3["H2"].conclusion,
            h3["H3"].conclusion, h3["H3"].next_correction_code) == (
                "inconclusive", "confirmed", "refuted", "package")
    assert (h4["H3"].conclusion, h4["H4"].conclusion, h4["H4"].next_correction_code,
            h4["H5"].conclusion, h4["H5"].next_correction_code) == (
                "confirmed", "refuted", "parser", "refuted", "scheduler")


def test_h5_requires_explicit_due_evidence_and_completion() -> None:
    unknown = _by_code(subject.project_metadata_observations(_facts(
        verify_contacts_not_before_due=0, verify_contacts_due_unknown=1,
    )))["H5"]
    due_but_pending = _by_code(subject.project_metadata_observations(_facts()))["H5"]
    completed = _by_code(subject.project_metadata_observations(_facts(
        lifecycle_status="no_data", terminal_status_received=True,
    )))["H5"]
    assert unknown.conclusion == due_but_pending.conclusion == "inconclusive"
    assert "contactNotBeforeDue" not in unknown.observed_result
    assert completed.conclusion == "confirmed"
    assert completed.observed_result["contactNotBeforeDue"] is True


@pytest.mark.parametrize(
    "changes",
    (
        {"lifecycle_transitioned": False},
        {"sat_contacted": False, "verify_contacts": 0, "verify_contacts_not_before_due": 0},
        {"lifecycle_transitioned": False, "sat_contacted": False, "executed_stages": (),
         "authentication_accepted": None, "request_accepted": None, "verify_attempts": 0,
         "verify_contacts": 0, "verify_contacts_not_before_due": 0},
    ),
)
def test_idle_no_due_or_no_contact_projects_no_event(changes) -> None:
    assert subject.project_metadata_observations(_facts(**changes)) == ()


def test_schema_is_immutable_redacted_and_rejects_scope_or_aggregate_mixing() -> None:
    scope_marker = object()
    facts = _facts(reducer_scope=scope_marker)
    with pytest.raises(FrozenInstanceError):
        facts.kind = "private"
    assert "metadata-recover-live" not in repr(facts)
    with pytest.raises(subject.MetadataObservationProjectionError, match="facts-invalid"):
        _facts(executed_stages=("inspect", "raw-row"))
    with pytest.raises(subject.MetadataObservationProjectionError, match="facts-invalid"):
        _facts(verify_contacts=1, verify_contacts_not_before_due=1, verify_contacts_due_unknown=1)
    with pytest.raises(subject.MetadataObservationProjectionError, match="history-scope-invalid"):
        subject.project_metadata_observations(facts, prior_facts=(_facts(),))
    with pytest.raises(TypeError):
        subject.MetadataObservationFacts(private_id="forbidden")


@pytest.mark.parametrize(
    "changes",
    (
        {"lifecycle_status": "completed", "terminal_status_received": True,
         "authentication_accepted": False, "package_count": 1, "downloaded_package_count": 1,
         "zip_valid_count": 1, "txt_count": 1,
         "executed_stages": ("authenticate", "submit", "wait", "verify", "download", "extract", "inspect")},
        {"lifecycle_status": "completed", "terminal_status_received": True,
         "request_accepted": False, "package_count": 1, "downloaded_package_count": 1,
         "zip_valid_count": 1, "txt_count": 1,
         "executed_stages": ("authenticate", "submit", "wait", "verify", "download", "extract", "inspect")},
        {"lifecycle_status": "completed", "terminal_status_received": True},
        {"lifecycle_status": "completed", "terminal_status_received": True,
         "package_count": 1, "downloaded_package_count": 1, "zip_valid_count": 1, "txt_count": 1,
         "executed_stages": ("authenticate", "submit", "wait", "verify", "download")},
        {"lifecycle_status": "download_failed", "terminal_status_received": True,
         "package_count": 1, "downloaded_package_count": 1, "zip_valid_count": 1, "txt_count": 1,
         "executed_stages": ("authenticate", "submit", "wait", "verify", "download", "extract", "inspect")},
        {"lifecycle_status": "no_data", "terminal_status_received": True, "package_count": 1},
        {"terminal_status_received": True, "verify_attempts": 0, "verify_contacts": 0,
         "verify_contacts_not_before_due": 0},
        {"verify_contacts": 0, "verify_contacts_not_before_due": 0,
         "verify_contacts_due_unknown": 1},
        {"verify_contacts_before_due": 1, "verify_contacts_not_before_due": 0,
         "executed_stages": ("authenticate", "submit", "verify")},
        {"package_count": 1},
        {"package_count": 1, "downloaded_package_count": 1, "zip_valid_count": 1},
        {"package_count": 1, "downloaded_package_count": 1, "zip_valid_count": 1,
         "txt_count": 1, "executed_stages": ("authenticate", "submit", "wait", "verify", "download")},
        {"utf8_sig": True, "delimiter_tilde": True, "parser_compatible": True,
         "executed_stages": ("authenticate", "submit", "wait", "verify", "download", "extract", "inspect")},
        {"authentication_accepted": False, "request_accepted": True},
    ),
)
def test_impossible_cross_field_facts_fail_closed(changes) -> None:
    with pytest.raises(subject.MetadataObservationProjectionError, match="facts-invalid"):
        _facts(**changes)


def test_incomplete_but_possible_error_and_pending_evidence_remains_inconclusive() -> None:
    download_error = _by_code(subject.project_metadata_observations(_facts(
        lifecycle_status="download_failed", terminal_status_received=True, package_count=1,
        executed_stages=("authenticate", "submit", "wait", "verify", "download"),
    )))
    pending_unknown = _by_code(subject.project_metadata_observations(_facts(
        verify_contacts_not_before_due=0, verify_contacts_due_unknown=1,
    )))
    auth_failure = _by_code(subject.project_metadata_observations(_facts(
        executed_stages=("authenticate",), authentication_accepted=False, request_accepted=None,
        verify_attempts=0, verify_contacts=0, verify_contacts_not_before_due=0,
    )))
    assert download_error["H3"].conclusion == "inconclusive"
    assert pending_unknown["H5"].conclusion == "inconclusive"
    assert auth_failure["H1"].conclusion == "inconclusive"


def test_stability_needs_distinct_execution_with_exact_reproducible_identity() -> None:
    scope_marker = object()
    prior = _facts(reducer_scope=scope_marker)
    current = replace(
        prior, execution_started_at=START + timedelta(days=1),
        observed_at=START + timedelta(days=1, minutes=30),
    )
    same_execution = replace(prior, observed_at=prior.observed_at + timedelta(minutes=1))
    assert all(event.stability == "stable" for event in subject.project_metadata_observations(
        current, prior_facts=(prior,),
    ))
    assert all(event.stability == "observed_once" for event in subject.project_metadata_observations(
        same_execution, prior_facts=(prior,),
    ))
    for changed in (
        replace(current, tested_commit="b" * 40),
        replace(current, entry_point="metadata-recovery-runner"),
        replace(current, direction="issued"),
        replace(current, lifecycle_status="pending_after_budget"),
    ):
        assert all(event.stability == "observed_once" for event in subject.project_metadata_observations(
            changed, prior_facts=(prior,),
        ))
