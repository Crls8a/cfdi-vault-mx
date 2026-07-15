"""Pure internal projection of sanitized recovery facts into ledger events.

This module owns no persistence, credentials, identifiers, paths, or live SAT access.
An opaque per-storage token prevents histories from different roots being combined.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from cfdi_vault.sat_metadata_observation import NewMetadataObservation

_STAGES = ("authenticate", "submit", "wait", "verify", "download", "extract", "inspect")
_ENTRY_POINTS = {"metadata-recover-live", "metadata-recovery-runner"}
_STATUS_OUTCOME = {
    "verify_scheduled": "pending",
    "packages_ready": "completed",
    "downloading": "completed",
    "completed": "completed",
    "no_data": "no_data",
    "pending_after_budget": "pending_after_budget",
    "verify_failed": "failed",
    "download_uncertain": "download_uncertain",
    "download_failed": "download_failed",
}
_TERMINAL_SUCCESS = {"completed", "no_data"}
_MAX_COUNT = 1_000_000


class MetadataObservationProjectionError(ValueError):
    """Report a sanitized fact or reducer-history validation failure."""


@dataclass(frozen=True, repr=False)
class MetadataObservationFacts:
    """Immutable allowlisted aggregate snapshot for one recovery execution."""

    reducer_scope: object
    tested_commit: str
    execution_started_at: datetime
    observed_at: datetime
    sat_version: str
    kind: str
    direction: str
    date_from: date
    date_to: date
    entry_point: str
    executed_stages: tuple[str, ...]
    lifecycle_status: str
    lifecycle_transitioned: bool
    sat_contacted: bool
    authentication_accepted: bool | None
    request_accepted: bool | None
    terminal_status_received: bool
    verify_attempts: int
    verify_contacts: int
    verify_contacts_not_before_due: int
    verify_contacts_before_due: int
    verify_contacts_due_unknown: int
    package_count: int
    downloaded_package_count: int
    zip_valid_count: int
    txt_count: int
    column_count: int | None
    has_records: bool | None
    utf8_sig: bool | None
    delimiter_tilde: bool | None
    parser_compatible: bool | None

    def __post_init__(self) -> None:
        _validate_facts(self)


def project_metadata_observations(
    facts: MetadataObservationFacts, *, prior_facts: tuple[MetadataObservationFacts, ...] = (),
) -> tuple[NewMetadataObservation, ...]:
    """Project meaningful evidence and reduce reproducibility to stability."""

    if type(facts) is not MetadataObservationFacts or type(prior_facts) is not tuple:
        raise MetadataObservationProjectionError("facts-invalid")
    if any(type(item) is not MetadataObservationFacts for item in prior_facts):
        raise MetadataObservationProjectionError("history-invalid")
    if any(item.reducer_scope is not facts.reducer_scope for item in prior_facts):
        raise MetadataObservationProjectionError("history-scope-invalid")
    if not facts.lifecycle_transitioned or not facts.sat_contacted:
        return ()
    events = []
    for code, result, conclusion, correction in _candidates(facts):
        stable = any(_reproduces(item, facts, code, result, conclusion) for item in prior_facts)
        events.append(NewMetadataObservation(
            execution_started_at=facts.execution_started_at,
            observed_at=facts.observed_at,
            tested_commit=facts.tested_commit,
            hypothesis_code=code,
            direction=facts.direction,
            kind="metadata",
            date_from=facts.date_from,
            date_to=facts.date_to,
            executed_stages=facts.executed_stages,
            observed_result=result,
            conclusion=conclusion,
            next_correction_code=correction,
            stability="stable" if stable else "observed_once",
            sat_version=facts.sat_version,
            entry_point=facts.entry_point,
        ))
    return tuple(events)


def _candidates(facts: MetadataObservationFacts) -> tuple[tuple[str, dict[str, object], str, str], ...]:
    outcome = _STATUS_OUTCOME[facts.lifecycle_status]
    items: list[tuple[str, dict[str, object], str, str]] = []
    h1 = {"outcome": outcome, "terminalStatusReceived": facts.terminal_status_received}
    _known(h1, "authenticationAccepted", facts.authentication_accepted)
    _known(h1, "requestAccepted", facts.request_accepted)
    if facts.authentication_accepted is not None or facts.request_accepted is not None or facts.terminal_status_received:
        confirmed = facts.terminal_status_received and facts.lifecycle_status == "completed"
        items.append(("H1", h1, "confirmed" if confirmed else "inconclusive",
                      "none" if confirmed else "observe-again"))
    if facts.terminal_status_received:
        found = facts.package_count > 0
        items.append(("H2", {"outcome": outcome, "terminalStatusReceived": True,
                             "hasPackages": found, "packageCount": facts.package_count},
                      "confirmed" if found else "inconclusive", "none" if found else "observe-again"))
    if "download" in facts.executed_stages:
        all_once = facts.package_count > 0 and facts.downloaded_package_count == facts.package_count
        zip_valid = facts.downloaded_package_count > 0 and facts.zip_valid_count == facts.downloaded_package_count
        result = {"outcome": outcome, "allPackagesDownloadedOnce": all_once, "zipValid": zip_valid,
                  "hasTxt": facts.txt_count > 0, "packageCount": facts.package_count,
                  "zipValidCount": facts.zip_valid_count, "txtCount": facts.txt_count}
        confirmed = facts.zip_valid_count > 0 and facts.txt_count > 0
        refuted = facts.downloaded_package_count > 0 and (
            facts.zip_valid_count == 0 or all_once and facts.txt_count == 0)
        conclusion = "confirmed" if confirmed else "refuted" if refuted else "inconclusive"
        items.append(("H3", result, conclusion, "none" if confirmed else "package" if refuted else "observe-again"))
    structural = (facts.utf8_sig, facts.delimiter_tilde, facts.parser_compatible)
    if "inspect" in facts.executed_stages and any(value is not None for value in structural):
        result = {"outcome": outcome}
        for key, value in (("utf8Sig", facts.utf8_sig), ("delimiterTilde", facts.delimiter_tilde),
                           ("parserCompatible", facts.parser_compatible), ("hasRecords", facts.has_records),
                           ("columnCount", facts.column_count)):
            _known(result, key, value)
        conclusion = "confirmed" if all(value is True for value in structural) \
            else "refuted" if any(value is False for value in structural) else "inconclusive"
        items.append(("H4", result, conclusion, "none" if conclusion == "confirmed" else
                      "parser" if conclusion == "refuted" else "observe-again"))
    if facts.verify_contacts:
        result = {"outcome": outcome, "verifyAttempts": facts.verify_attempts,
                  "terminalStatusReceived": facts.terminal_status_received}
        if facts.verify_contacts_before_due:
            result["contactNotBeforeDue"] = False
            conclusion = "refuted"
        elif not facts.verify_contacts_due_unknown:
            result["contactNotBeforeDue"] = True
            conclusion = "confirmed" if facts.terminal_status_received and facts.lifecycle_status in _TERMINAL_SUCCESS \
                else "inconclusive"
        else:
            conclusion = "inconclusive"
        items.append(("H5", result, conclusion, "none" if conclusion == "confirmed" else
                      "scheduler" if conclusion == "refuted" else "observe-again"))
    return tuple(items)


def _reproduces(prior, current, code, result, conclusion) -> bool:
    candidate = next((item for item in _candidates(prior) if item[0] == code), None)
    return bool(
        prior.lifecycle_transitioned and prior.sat_contacted
        and prior.execution_started_at < current.execution_started_at
        and prior.observed_at < current.observed_at
        and prior.tested_commit == current.tested_commit
        and _scope(prior) == _scope(current)
        and candidate is not None and candidate[1] == result and candidate[2] == conclusion
    )


def _scope(facts: MetadataObservationFacts) -> tuple[object, ...]:
    return (facts.sat_version, facts.kind, facts.direction, facts.date_from, facts.date_to, facts.entry_point)


def _known(target: dict[str, object], key: str, value: object | None) -> None:
    if value is not None:
        target[key] = value


def _validate_facts(facts: MetadataObservationFacts) -> None:
    times = (facts.execution_started_at, facts.observed_at)
    valid_times = all(type(value) is datetime and value.utcoffset() == timedelta(0) for value in times)
    scope_valid = (
        type(facts.reducer_scope) is object and type(facts.tested_commit) is str
        and re.fullmatch(r"[0-9a-f]{40}", facts.tested_commit)
        and valid_times and facts.observed_at >= facts.execution_started_at
        and facts.sat_version == "v1.5" and facts.kind == "Metadata"
        and type(facts.direction) is str and facts.direction in {"issued", "received"}
        and type(facts.date_from) is date and type(facts.date_to) is date and facts.date_from <= facts.date_to
        and type(facts.entry_point) is str and facts.entry_point in _ENTRY_POINTS
        and type(facts.lifecycle_status) is str and facts.lifecycle_status in _STATUS_OUTCOME
    )
    indexes = tuple(_STAGES.index(value) for value in facts.executed_stages if value in _STAGES) \
        if type(facts.executed_stages) is tuple else ()
    stages_valid = (
        type(facts.executed_stages) is tuple
        and all(type(value) is str for value in facts.executed_stages)
        and len(indexes) == len(facts.executed_stages)
        and facts.executed_stages == _STAGES[:len(facts.executed_stages)]
        and (bool(facts.executed_stages) or not facts.lifecycle_transitioned or not facts.sat_contacted)
    )
    controls = (facts.lifecycle_transitioned, facts.sat_contacted, facts.terminal_status_received)
    evidence = (facts.authentication_accepted, facts.request_accepted, facts.has_records,
                facts.utf8_sig, facts.delimiter_tilde, facts.parser_compatible)
    bools_valid = all(type(value) is bool for value in controls) \
        and all(value is None or type(value) is bool for value in evidence)
    counts = (facts.verify_attempts, facts.verify_contacts, facts.verify_contacts_not_before_due,
              facts.verify_contacts_before_due, facts.verify_contacts_due_unknown, facts.package_count,
              facts.downloaded_package_count, facts.zip_valid_count, facts.txt_count)
    counts_valid = all(type(value) is int and 0 <= value <= _MAX_COUNT for value in counts)
    aggregates_valid = (
        facts.verify_contacts <= facts.verify_attempts
        and facts.verify_contacts == facts.verify_contacts_not_before_due
        + facts.verify_contacts_before_due + facts.verify_contacts_due_unknown
        and facts.downloaded_package_count <= facts.package_count
        and facts.zip_valid_count <= facts.downloaded_package_count
        and (facts.column_count is None or type(facts.column_count) is int
             and 0 <= facts.column_count <= _MAX_COUNT)
    )
    if not (scope_valid and stages_valid and bools_valid and counts_valid and aggregates_valid
            and _valid_semantics(facts)):
        raise MetadataObservationProjectionError("facts-invalid")


def _valid_semantics(facts: MetadataObservationFacts) -> bool:
    stages = set(facts.executed_stages)
    status = facts.lifecycle_status
    structural = (facts.utf8_sig, facts.delimiter_tilde, facts.parser_compatible,
                  facts.has_records, facts.column_count)
    has_structure = any(value is not None for value in structural)
    positive_contact_evidence = (
        facts.authentication_accepted is True or facts.request_accepted is True
        or facts.terminal_status_received or facts.verify_contacts > 0
        or any((facts.package_count, facts.downloaded_package_count, facts.zip_valid_count, facts.txt_count))
        or has_structure
    )
    if positive_contact_evidence and not facts.sat_contacted:
        return False
    downstream = (
        facts.terminal_status_received or facts.verify_attempts > 0 or facts.package_count > 0
        or status != "verify_scheduled"
    )
    if facts.authentication_accepted is not None and "authenticate" not in stages:
        return False
    if facts.request_accepted is not None and "submit" not in stages:
        return False
    if facts.request_accepted is True and facts.authentication_accepted is not True:
        return False
    if downstream and (facts.authentication_accepted is not True or facts.request_accepted is not True):
        return False
    verify_evidence = facts.verify_attempts > 0 or facts.verify_contacts > 0 or facts.terminal_status_received
    if verify_evidence and not {"wait", "verify"}.issubset(stages):
        return False
    if "verify" in stages and facts.verify_attempts == 0:
        return False
    if facts.verify_contacts > 0 and not facts.sat_contacted:
        return False
    persisted_package_terminal = (facts.lifecycle_transitioned and facts.package_count > 0
                                  and status in {"packages_ready", "downloading", "completed",
                                                 "download_uncertain", "download_failed"})
    if facts.terminal_status_received and facts.verify_contacts == 0 and not persisted_package_terminal:
        return False
    terminal_required = {"packages_ready", "downloading", "completed", "no_data",
                         "download_uncertain", "download_failed"}
    if status in terminal_required and not facts.terminal_status_received:
        return False
    if facts.terminal_status_received and status in {"verify_scheduled", "pending_after_budget"}:
        return False
    stage_cap = {
        "verify_scheduled": 4, "pending_after_budget": 4, "verify_failed": 4, "no_data": 4,
        "packages_ready": 4, "downloading": 5, "download_uncertain": 5,
        "download_failed": 7, "completed": 7,
    }
    if len(facts.executed_stages) > stage_cap[status]:
        return False
    package_required = {"packages_ready", "downloading", "completed",
                        "download_uncertain", "download_failed"}
    if status in package_required and facts.package_count == 0:
        return False
    package_forbidden = {"verify_scheduled", "pending_after_budget", "verify_failed", "no_data"}
    if status in package_forbidden and any((facts.package_count, facts.downloaded_package_count,
                                           facts.zip_valid_count, facts.txt_count)):
        return False
    if status == "packages_ready" and any((facts.downloaded_package_count, facts.zip_valid_count, facts.txt_count)):
        return False
    if status == "verify_failed" and facts.verify_attempts == 0:
        return False
    if status == "completed" and not (
        facts.package_count == facts.downloaded_package_count == facts.zip_valid_count > 0
        and facts.txt_count > 0
    ):
        return False
    if status in {"downloading", "download_uncertain"} and any(
        (facts.downloaded_package_count, facts.zip_valid_count, facts.txt_count)
    ):
        return False
    if status == "download_failed" and (
        facts.package_count == facts.downloaded_package_count == facts.zip_valid_count
        and facts.txt_count > 0
    ):
        return False
    download_evidence = (
        facts.downloaded_package_count > 0 or facts.zip_valid_count > 0 or facts.txt_count > 0
        or status in {"downloading", "completed", "download_uncertain", "download_failed"}
    )
    if download_evidence and "download" not in stages:
        return False
    if facts.txt_count > 0 and (
        facts.zip_valid_count == 0 or not {"extract", "inspect"}.issubset(stages)
    ):
        return False
    if "extract" in stages and facts.zip_valid_count == 0:
        return False
    if "inspect" in stages and facts.txt_count == 0:
        return False
    if has_structure and not (
        facts.package_count > 0 and facts.downloaded_package_count > 0
        and facts.zip_valid_count > 0 and facts.txt_count > 0
        and {"download", "extract", "inspect"}.issubset(stages)
    ):
        return False
    if facts.utf8_sig is False and (
        facts.delimiter_tilde is True or facts.parser_compatible is True
        or facts.has_records is True or facts.column_count not in {None, 0}
    ):
        return False
    if facts.delimiter_tilde is True and facts.utf8_sig is not True:
        return False
    if facts.parser_compatible is True and facts.column_count == 0:
        return False
    return True
