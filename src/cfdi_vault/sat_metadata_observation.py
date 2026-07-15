"""Internal append-only ledger for sanitized SAT metadata observations.

Storage ACLs must prevent hostile parent swaps after final path validation; a
dependency-free implementation cannot close that last Windows filesystem race.
"""
from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from types import MappingProxyType

import cfdi_vault.sat_metadata_recovery_state as state

_SCHEMA_VERSION = 2
_MAX_AGGREGATE_VALUE = 1_000_000  # Conservative bound for every sanitized count.
_DIRECTORY_FSYNC_REQUIRED = os.name != "nt"
_EVENT_KEYS = {"schemaVersion", "observationId", "executionStartedAt", "observedAt",
               "testedCommit", "hypothesis", "actualScope", "executedStages",
               "observedResult", "conclusion", "nextCorrection", "stability"}
_HYPOTHESES = dict(
    H1="SAT v1.5 permits the flow to complete without portal access.", H2="A completed Metadata request returns downloadable packages.",
    H3="A downloaded package is a valid ZIP containing at least one TXT.",
    H4="The TXT uses ~, decodes as utf-8-sig, and is parser-compatible.",
    H5="Due-aware next_check_at waiting completes without aggressive polling.")
_CORRECTIONS = {
    "none": "No correction is required.", "observe-again": "Repeat the exact authorized observation.",
    "transport": "Correct the SAT transport boundary.", "request": "Correct the Metadata request boundary.",
    "verify": "Correct the verification boundary.", "download": "Correct the package download boundary.",
    "package": "Correct ZIP or TXT processing.", "parser": "Correct TXT structural compatibility.",
    "scheduler": "Correct due-aware scheduling.",
}
_STAGES = ("authenticate", "submit", "wait", "verify", "download", "extract", "inspect")
_BOOL_RESULTS = {"authenticationAccepted", "requestAccepted", "terminalStatusReceived",
                 "hasPackages", "allPackagesDownloadedOnce", "zipValid", "hasTxt",
                 "hasRecords", "delimiterTilde", "utf8Sig", "parserCompatible",
                 "contactNotBeforeDue"}
_INT_RESULTS = {"verifyAttempts", "packageCount", "zipValidCount", "txtCount", "columnCount"}
_OUTCOMES = {"accepted", "pending", "completed", "no_data", "failed", "uncertain", "pending_after_budget",
             "download_failed", "download_uncertain", "unsupported_encoding"}
class MetadataObservationError(ValueError):
    """Report a sanitized ledger failure without echoing event data or paths."""
@dataclass(frozen=True, repr=False)
class NewMetadataObservation:
    execution_started_at: datetime
    observed_at: datetime
    tested_commit: str
    hypothesis_code: str
    direction: str
    kind: str
    date_from: date
    date_to: date
    executed_stages: tuple[str, ...]
    observed_result: Mapping[str, object]
    conclusion: str
    next_correction_code: str
    stability: str
    sat_version: str = "v1.5"
    entry_point: str = "metadata-recover-live"
    def __post_init__(self) -> None:
        if type(self.observed_result) is not dict:
            raise MetadataObservationError("observation-result-invalid")
        snapshot = self.observed_result.copy()
        object.__setattr__(self, "observed_result", snapshot)
        _validate_input(self)
        object.__setattr__(self, "observed_result", MappingProxyType(snapshot))
def metadata_observation_path(storage_root: str | Path, *, repo_root: str | Path | None = None) -> Path:
    return _resolved_path(storage_root, repo_root=repo_root, create_parent=False)
def append_metadata_observation(
    storage_root: str | Path, event: NewMetadataObservation, *, repo_root: str | Path | None = None,
) -> tuple[str, bool]:
    """Append one durable event; write uncertainty is terminal for the caller."""
    if type(event) is not NewMetadataObservation:
        raise MetadataObservationError("observation-invalid")
    _resolved_path(storage_root, repo_root=repo_root, create_parent=True)
    root = _canonical_root(storage_root, repo_root=repo_root)
    with _ledger_lock(root):
        path = _resolved_path(storage_root, repo_root=repo_root, create_parent=True)
        if not state._is_within(path, root):
            raise MetadataObservationError("observation-path-invalid")
        created = not path.exists()
        descriptor = _open_append(path, root=root)
        try:
            events = _read_events(path, expected_descriptor=descriptor)
            candidate = _event_document(event, "obs-000000")
            key = _event_key(candidate)
            for current in events:
                if _event_key(current) == key:
                    return str(current["observationId"]), False
            next_number = len(events) + 1
            if next_number > 999999:
                raise MetadataObservationError("observation-id-exhausted")
            candidate["observationId"] = f"obs-{next_number:06d}"
            payload = json.dumps(candidate, separators=(",", ":"), sort_keys=True).encode() + b"\n"
            try:
                if os.write(descriptor, payload) != len(payload):
                    raise OSError
                os.fsync(descriptor)
                if created and _DIRECTORY_FSYNC_REQUIRED:
                    _fsync_directory(path.parent)
            except OSError:
                raise MetadataObservationError("observation-write-uncertain") from None
            return str(candidate["observationId"]), True
        finally:
            try:
                os.close(descriptor)
            except OSError:
                raise MetadataObservationError("observation-write-uncertain") from None
def read_metadata_observation_summary(
    storage_root: str | Path, *, repo_root: str | Path | None = None,
) -> dict[str, object]:
    events = _read_metadata_observations(storage_root, repo_root=repo_root)
    return {"total": len(events),
            "lastObservationId": str(events[-1]["observationId"]) if events else None}
def _read_metadata_observations(
    storage_root: str | Path, *, repo_root: str | Path | None = None,
) -> tuple[dict[str, object], ...]:
    initial = _resolved_path(storage_root, repo_root=repo_root, create_parent=False)
    if not initial.exists():
        return ()
    root = _canonical_root(storage_root, repo_root=repo_root)
    with _ledger_lock(root):
        path = _resolved_path(storage_root, repo_root=repo_root, create_parent=False)
        if not state._is_within(path, root):
            raise MetadataObservationError("observation-path-invalid")
        return _read_events(path)
def _validate_input(event: NewMetadataObservation) -> None:
    times = (event.execution_started_at, event.observed_at)
    if (any(type(value) is not datetime or value.utcoffset() != timezone.utc.utcoffset(value) for value in times)
            or event.observed_at < event.execution_started_at or type(event.tested_commit) is not str
            or not re.fullmatch(r"[0-9a-f]{40}", event.tested_commit)):
        raise MetadataObservationError("observation-invalid")
    if (type(event.hypothesis_code) is not str or type(event.next_correction_code) is not str
            or event.hypothesis_code not in _HYPOTHESES or event.next_correction_code not in _CORRECTIONS):
        raise MetadataObservationError("observation-code-invalid")
    if type(event.direction) is not str or type(event.kind) is not str or event.direction not in {"issued", "received"} or event.kind != "metadata":
        raise MetadataObservationError("observation-scope-invalid")
    if event.sat_version != "v1.5" or event.entry_point not in {"metadata-recover-live", "metadata-recovery-runner"}:
        raise MetadataObservationError("observation-scope-invalid")
    if type(event.date_from) is not date or type(event.date_to) is not date or event.date_from > event.date_to:
        raise MetadataObservationError("observation-scope-invalid")
    if (type(event.executed_stages) is not tuple or not event.executed_stages
            or any(type(value) is not str for value in event.executed_stages)):
        raise MetadataObservationError("observation-stages-invalid")
    indexes = tuple(_STAGES.index(value) for value in event.executed_stages if value in _STAGES)
    if len(indexes) != len(event.executed_stages) or indexes != tuple(sorted(set(indexes))):
        raise MetadataObservationError("observation-stages-invalid")
    _validate_result(event.observed_result)
    if (type(event.conclusion) is not str or type(event.stability) is not str
            or event.conclusion not in {"confirmed", "refuted", "inconclusive"}
            or event.stability not in {"observed_once", "stable"}):
        raise MetadataObservationError("observation-code-invalid")
def _validate_result(value: object) -> None:
    if (type(value) is not dict or not value
            or not set(value).issubset(_BOOL_RESULTS | _INT_RESULTS | {"outcome"})):
        raise MetadataObservationError("observation-result-invalid")
    for key, item in value.items():
        valid = (
            key in _BOOL_RESULTS and type(item) is bool
            or key in _INT_RESULTS and type(item) is int and 0 <= item <= _MAX_AGGREGATE_VALUE
            or key == "outcome" and type(item) is str and item in _OUTCOMES
        )
        if not valid:
            raise MetadataObservationError("observation-result-invalid")
def _event_document(event: NewMetadataObservation, observation_id: str) -> dict[str, object]:
    return {
        "schemaVersion": _SCHEMA_VERSION, "observationId": observation_id,
        "executionStartedAt": event.execution_started_at.isoformat().replace("+00:00", "Z"),
        "observedAt": event.observed_at.isoformat().replace("+00:00", "Z"),
        "testedCommit": event.tested_commit,
        "hypothesis": {"code": event.hypothesis_code, "text": _HYPOTHESES[event.hypothesis_code]},
        "actualScope": {"satVersion": event.sat_version, "entryPoint": event.entry_point,
                        "direction": event.direction, "kind": event.kind,
                        "dateFrom": event.date_from.isoformat(), "dateTo": event.date_to.isoformat()},
        "executedStages": list(event.executed_stages), "observedResult": dict(event.observed_result),
        "conclusion": event.conclusion,
        "nextCorrection": {"code": event.next_correction_code,
                           "text": _CORRECTIONS[event.next_correction_code]},
        "stability": event.stability,
}
def _validate_document(value: object, expected_number: int) -> dict[str, object]:
    if type(value) is not dict or set(value) != _EVENT_KEYS:
        raise MetadataObservationError("observation-schema-invalid")
    identifier = value["observationId"]
    if type(value["schemaVersion"]) is not int or value["schemaVersion"] != _SCHEMA_VERSION or type(identifier) is not str:
        raise MetadataObservationError("observation-schema-invalid")
    if not re.fullmatch(r"obs-[0-9]{6}", identifier) or identifier != f"obs-{expected_number:06d}":
        raise MetadataObservationError("observation-id-invalid")
    for name, source in (("hypothesis", _HYPOTHESES), ("nextCorrection", _CORRECTIONS)):
        pair = value[name]
        if type(pair) is not dict or set(pair) != {"code", "text"}:
            raise MetadataObservationError("observation-schema-invalid")
        code, text = pair["code"], pair["text"]
        if type(code) is not str or type(text) is not str or source.get(code) != text:
            raise MetadataObservationError("observation-schema-invalid")
    scope = value["actualScope"]
    if type(scope) is not dict or set(scope) != {"satVersion", "entryPoint", "direction", "kind", "dateFrom", "dateTo"}:
        raise MetadataObservationError("observation-schema-invalid")
    try:
        event = NewMetadataObservation(
            datetime.fromisoformat(value["executionStartedAt"].replace("Z", "+00:00")),
            datetime.fromisoformat(value["observedAt"].replace("Z", "+00:00")),
            value["testedCommit"], value["hypothesis"]["code"], scope["direction"], scope["kind"],
            date.fromisoformat(scope["dateFrom"]), date.fromisoformat(scope["dateTo"]),
            tuple(value["executedStages"]) if type(value["executedStages"]) is list else (),
            value["observedResult"], value["conclusion"], value["nextCorrection"]["code"],
            value["stability"], scope["satVersion"], scope["entryPoint"],
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        raise MetadataObservationError("observation-schema-invalid") from None
    if _event_document(event, identifier) != value:
        raise MetadataObservationError("observation-schema-invalid")
    return dict(value)
def _event_key(value: Mapping[str, object]) -> str:
    copy = {key: item for key, item in value.items() if key != "observationId"}
    return json.dumps(copy, separators=(",", ":"), sort_keys=True)
def _read_events(path: Path, *, expected_descriptor: int | None = None) -> tuple[dict[str, object], ...]:
    try:
        with path.open("rb") as stream:
            descriptor = stream.fileno()
            _validate_descriptor(path, descriptor)
            if expected_descriptor is not None and not os.path.samestat(
                os.fstat(descriptor), os.fstat(expected_descriptor)):
                raise MetadataObservationError("observation-path-invalid")
            contents = stream.read()
    except MetadataObservationError:
        raise
    except OSError:
        raise MetadataObservationError("observation-unreadable") from None
    if contents and not contents.endswith(b"\n"):
        raise MetadataObservationError("observation-partial-tail")
    events: list[dict[str, object]] = []
    for number, line in enumerate(contents.splitlines(), start=1):
        try:
            value = json.loads(line, object_pairs_hook=_unique_object)
        except MetadataObservationError:
            raise
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            raise MetadataObservationError("observation-unreadable") from None
        events.append(_validate_document(value, number))
    if len({_event_key(item) for item in events}) != len(events):
        raise MetadataObservationError("observation-duplicate")
    return tuple(events)
def _resolved_path(storage_root: str | Path, *, repo_root: str | Path | None, create_parent: bool) -> Path:
    try:
        state_path = state._resolved_state_path(storage_root, repo_root=repo_root, create_parent=create_parent)
        path = state_path.with_name("sat-metadata-observations.jsonl")
        _reject_named_reparse(path)
        resolved = path.resolve(strict=False)
    except (state.MetadataRecoveryStateError, OSError, RuntimeError):
        raise MetadataObservationError("observation-path-invalid") from None
    if not state._is_within(resolved, state_path.parent):
        raise MetadataObservationError("observation-path-invalid")
    return resolved
def _reject_named_reparse(path: Path) -> None:
    try:
        named = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError:
        raise MetadataObservationError("observation-path-invalid") from None
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if stat.S_ISLNK(named.st_mode) or reparse and getattr(named, "st_file_attributes", 0) & reparse:
        raise MetadataObservationError("observation-path-invalid")
def _canonical_root(storage_root: str | Path, *, repo_root: str | Path | None) -> Path:
    try:
        return state._canonical_storage_root(storage_root, repo_root=repo_root)
    except state.MetadataRecoveryStateError:
        raise MetadataObservationError("observation-path-invalid") from None
@contextmanager
def _ledger_lock(root: Path):
    anchor = root / "sat-metadata-observation-ledger"
    lock = root / ".sat-metadata-observation-ledger.lock"
    try:
        if lock.exists():
            existing = os.stat(lock, follow_symlinks=False)
            if not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
                raise MetadataObservationError("observation-lock-invalid")
        with state._exclusive_state_lock(anchor):
            details = os.stat(lock, follow_symlinks=False)
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise MetadataObservationError("observation-lock-invalid")
            yield
    except MetadataObservationError:
        raise
    except state.MetadataRecoveryStateError as error:
        reason = "observation-busy" if error.reason == "recovery-state-busy" else "observation-lock-failed"
        raise MetadataObservationError(reason) from None
    except OSError:
        raise MetadataObservationError("observation-lock-failed") from None
def _open_append(path: Path, *, root: Path) -> int:
    try:
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        _validate_descriptor(path, descriptor)
        try:
            resolved = path.resolve(strict=False)
        except (OSError, RuntimeError):
            raise MetadataObservationError("observation-path-invalid") from None
        if not state._is_within(resolved, root):
            raise MetadataObservationError("observation-path-invalid")
        return descriptor
    except MetadataObservationError:
        try:
            os.close(descriptor)
        except OSError:
            raise MetadataObservationError("observation-open-failed") from None
        raise
    except OSError:
        raise MetadataObservationError("observation-open-failed") from None
def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
def _validate_descriptor(path: Path, descriptor: int) -> None:
    try:
        named, opened = os.stat(path, follow_symlinks=False), os.fstat(descriptor)
    except OSError:
        raise MetadataObservationError("observation-path-invalid") from None
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(named, "st_file_attributes", 0)
    if (
        not stat.S_ISREG(named.st_mode) or not stat.S_ISREG(opened.st_mode)
        or named.st_nlink != 1 or opened.st_nlink != 1
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        or reparse and attributes & reparse
    ):
        raise MetadataObservationError("observation-path-invalid")
def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise MetadataObservationError("observation-duplicate-key")
        value[key] = item
    return value
