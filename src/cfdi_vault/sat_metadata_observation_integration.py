"""Bridge durable metadata recovery state to sanitized observation events."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime
from pathlib import Path

import cfdi_vault.sat_metadata_recovery_state as state
from cfdi_vault.live_permit import current_repo_identity
from cfdi_vault.metadata_parser import _has_required_headers
from cfdi_vault.sat_metadata_observation import (
    MetadataObservationError,
    _read_metadata_observations,
    append_metadata_observation,
)
from cfdi_vault.sat_metadata_observation_projection import (
    MetadataObservationFacts,
    project_metadata_observations,
)
from cfdi_vault.sat_metadata_recovery import PackageRecoveryStatus, RecoveryStatus
from cfdi_vault.sat_metadata_recovery_runner import MetadataRecoveryAdvanceOutcome
from cfdi_vault.sat_metadata_recovery_state import MetadataRecoveryStateRecord

_STAGES = ("authenticate", "submit", "wait", "verify", "download", "extract", "inspect")
_VERIFIED = {RecoveryStatus.PACKAGES_READY, RecoveryStatus.DOWNLOADING, RecoveryStatus.COMPLETED,
             RecoveryStatus.NO_DATA, RecoveryStatus.DOWNLOAD_UNCERTAIN, RecoveryStatus.DOWNLOAD_FAILED}
_DOWNLOADING = {RecoveryStatus.DOWNLOADING, RecoveryStatus.COMPLETED,
                RecoveryStatus.DOWNLOAD_UNCERTAIN, RecoveryStatus.DOWNLOAD_FAILED}
@dataclass(frozen=True, repr=False)
class MetadataObservationContext:
    """Hold one validated same-root ledger snapshot without exposing its path."""
    storage_root: str | Path
    repo_root: str | Path | None
    tested_commit: str
    reducer_scope: object
    prior_events: tuple[dict[str, object], ...]
def prepare_metadata_observation_context(
    storage_root: str | Path, *, repo_root: str | Path | None = None,
) -> MetadataObservationContext:
    """Validate and read the private-root ledger before any SAT side effect."""
    state._canonical_storage_root(storage_root, repo_root=repo_root)
    try:
        prior = _read_metadata_observations(storage_root, repo_root=repo_root)
    except MetadataObservationError:
        raise MetadataObservationError("observation-ledger-unreadable") from None
    return MetadataObservationContext(
        storage_root, repo_root, current_repo_identity(Path(repo_root) if repo_root else None),
        object(), prior,
    )
def observe_metadata_recovery(
    context: MetadataObservationContext, *, before: MetadataRecoveryStateRecord | None,
    after: MetadataRecoveryStateRecord, outcome: MetadataRecoveryAdvanceOutcome,
    observed_at: datetime, entry_point: str, reconcile_submission: bool = False,
) -> int:
    """Append only missing facts after the corresponding durable state update."""
    if (type(context) is not MetadataObservationContext
            or before is not None and type(before) is not MetadataRecoveryStateRecord
            or type(after) is not MetadataRecoveryStateRecord
            or type(outcome) is not MetadataRecoveryAdvanceOutcome):
        raise MetadataObservationError("observation-facts-invalid")
    changed = before is None or before != after
    missing_submission = reconcile_submission and not _has_submission(context.prior_events, after, entry_point)
    contacted = outcome.sat_contacted
    if not changed and not contacted and not missing_submission:
        return 0
    facts = _facts(context, after, outcome, observed_at, entry_point,
                   transitioned=changed or missing_submission or contacted)
    events = project_metadata_observations(facts)
    appended = 0
    for event in events:
        if _already_recorded(context.prior_events, event):
            continue
        stable = any(_reproduces(item, event) for item in context.prior_events)
        _, created = append_metadata_observation(
            context.storage_root,
            replace(event, observed_result=dict(event.observed_result), stability="stable") if stable else event,
            repo_root=context.repo_root,
        )
        appended += int(created)
    return appended
def _facts(context, record, outcome, observed_at, entry_point, *, transitioned):
    recovery = record.recovery
    texts = tuple(text for artifact in record.artifact_bindings for text in artifact.texts)
    utf8, tilde, compatible, columns, records = _structure(texts)
    not_before = outcome.verify_contacts_not_before_due
    before_due = outcome.verify_contacts_before_due
    unknown = outcome.verify_contacts_due_unknown
    terminal = outcome.terminal_status_received or recovery.status in _VERIFIED
    contacts = not_before + before_due + unknown
    completed = sum(item.status is PackageRecoveryStatus.COMPLETED for item in recovery.packages)
    zip_valid = sum(item.zip_valid is True for item in recovery.packages)
    return MetadataObservationFacts(
        reducer_scope=context.reducer_scope, tested_commit=context.tested_commit,
        execution_started_at=recovery.created_at, observed_at=observed_at,
        sat_version="v1.5", kind="Metadata", direction=record.direction,
        date_from=date.fromisoformat(record.fecha_inicial), date_to=date.fromisoformat(record.fecha_final),
        entry_point=entry_point, executed_stages=_stages(record),
        lifecycle_status=recovery.status.value, lifecycle_transitioned=transitioned,
        sat_contacted=bool(outcome.sat_contacted or transitioned), authentication_accepted=True,
        request_accepted=True, terminal_status_received=terminal,
        verify_attempts=recovery.verify_attempts, verify_contacts=contacts,
        verify_contacts_not_before_due=not_before, verify_contacts_before_due=before_due,
        verify_contacts_due_unknown=unknown, package_count=len(recovery.packages),
        downloaded_package_count=completed, zip_valid_count=zip_valid, txt_count=recovery.txt_count,
        column_count=columns, has_records=records, utf8_sig=utf8,
        delimiter_tilde=tilde, parser_compatible=compatible,
    )
def _stages(record: MetadataRecoveryStateRecord) -> tuple[str, ...]:
    recovery, end = record.recovery, 3
    if recovery.verify_attempts or recovery.status in _VERIFIED | {RecoveryStatus.VERIFY_FAILED}:
        end = 4
    if recovery.status in _DOWNLOADING or any(
        item.status is not PackageRecoveryStatus.PENDING for item in recovery.packages
    ):
        end = 5
    if record.artifact_bindings and recovery.txt_count:
        end = 7
    return _STAGES[:end]
def _structure(texts):  # type: ignore[no-untyped-def]
    if not texts:
        return None, None, None, None, None
    inspections = tuple(item.inspection for item in texts)
    utf8 = all(item.encoding == "utf-8-sig" for item in inspections)
    if not utf8:
        return False, False, False, 0, False
    columns = max(item.column_count for item in inspections)
    return (True, all(item.delimiter == "~" for item in inspections),
            all(_has_required_headers(list(item.headers)) for item in inspections),
            columns, any(item.records_present for item in inspections))
def _scope(event) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return {"satVersion": event.sat_version, "entryPoint": event.entry_point,
            "direction": event.direction, "kind": event.kind,
            "dateFrom": event.date_from.isoformat(), "dateTo": event.date_to.isoformat()}
def _same(item, event) -> bool:  # type: ignore[no-untyped-def]
    return bool(item.get("testedCommit") == event.tested_commit
                and item.get("actualScope") == _scope(event)
                and item.get("hypothesis", {}).get("code") == event.hypothesis_code
                and item.get("observedResult") == dict(event.observed_result)
                and item.get("conclusion") == event.conclusion)
def _already_recorded(prior, event) -> bool:  # type: ignore[no-untyped-def]
    started = event.execution_started_at.isoformat().replace("+00:00", "Z")
    return any(item.get("executionStartedAt") == started and _same(item, event) for item in prior)
def _reproduces(item, event) -> bool:  # type: ignore[no-untyped-def]
    try:
        started = datetime.fromisoformat(str(item["executionStartedAt"]).replace("Z", "+00:00"))
        observed = datetime.fromisoformat(str(item["observedAt"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return False
    return started < event.execution_started_at and observed < event.observed_at and _same(item, event)
def _has_submission(prior, record, entry_point) -> bool:  # type: ignore[no-untyped-def]
    scope = {"satVersion": "v1.5", "entryPoint": entry_point, "direction": record.direction,
             "kind": "metadata", "dateFrom": record.fecha_inicial, "dateTo": record.fecha_final}
    return any(item.get("actualScope") == scope and item.get("hypothesis", {}).get("code") == "H1"
               and item.get("observedResult", {}).get("requestAccepted") is True for item in prior)
