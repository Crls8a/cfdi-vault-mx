"""Private strict codec and atomic store for SAT campaign manifests."""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from cfdi_vault.domain import DownloadDirection
from cfdi_vault.sat_campaign_manifest import (
    CampaignManifestError,
    CampaignWorkItem,
    CampaignWorkState,
    SatCampaignManifest,
    apply_campaign_submission_failure,
    bind_campaign_recovery,
    campaign_redacted_summary,
    record_campaign_result,
    reserve_campaign_work,
    split_campaign_work,
)
from cfdi_vault.secure_state_file import (
    SecureStateFileError,
    secure_state_path,
    secure_state_transaction,
)

_MAX_BYTES, _REF_RE = 1024 * 1024, re.compile(r"cmp-[0-9a-f]{12}")
_DOCUMENT_KEYS = {"schemaVersion", "campaignRef", "profileId", "items"}
_ITEM_KEYS = {"workRef", "direction", "start", "end", "depth", "parentRef", "state", "recoveryRef", "evidence"}
_PATH_ERRORS = {"storage-root-not-absolute", "storage-root-inside-repository", "state-file-name-invalid", "state-file-path-invalid"}
_ERROR_MAP = {
    "state-file-busy": "campaign-state-busy",
    "state-file-too-large": "campaign-state-too-large",
    "state-file-unreadable": "campaign-state-unreadable",
    "state-file-write-failed": "campaign-state-write-failed",
    "state-file-transition-already-committed": "campaign-state-write-failed",
    "state-file-commit-uncertain": "campaign-state-commit-uncertain",
    "state-file-lock-failed": "campaign-state-lock-failed",
    "state-file-lock-release-failed": "campaign-state-lock-failed",
}


class CampaignManifestStoreError(ValueError):
    """Report private campaign storage failures using fixed reason codes."""
    def __init__(self, reason: str, *, committed: bool = False, uncertain: bool = False) -> None:
        self.reason, self.committed, self.uncertain = reason, committed, uncertain
        super().__init__(reason)

    @property
    def retry_safe(self) -> bool:
        """Return whether retry is safe without first reconciling persisted state."""
        return not self.committed and not self.uncertain


@dataclass(frozen=True)
class CampaignCapacityReservation:
    """Return one atomic manifest snapshot and only refs reserved by it."""

    manifest: SatCampaignManifest
    new_work_refs: tuple[str, ...]


def campaign_manifest_state_path(
    storage_root: str | Path, campaign_ref: str, *, repo_root: str | Path | None = None,
) -> Path:
    """Return the canonical external path for one opaque campaign reference."""
    _validate_ref(campaign_ref)
    return _protect(lambda: secure_state_path(
        storage_root, _filename(campaign_ref), repo_root=repo_root,
    ))


def initialize_campaign_manifest(
    storage_root: str | Path, manifest: SatCampaignManifest, *,
    repo_root: str | Path | None = None,
) -> SatCampaignManifest:
    """Create state once; an identical existing document is an idempotent no-op."""
    _validate_manifest(manifest)
    return _protect(lambda: _initialize(storage_root, manifest, repo_root))


def load_campaign_manifest(
    storage_root: str | Path, campaign_ref: str, *, repo_root: str | Path | None = None,
) -> SatCampaignManifest:
    """Load and fully validate one immutable campaign snapshot."""
    _validate_ref(campaign_ref)
    return _protect(lambda: _load(storage_root, campaign_ref, repo_root))


def reserve_campaign_manifest(
    storage_root: str | Path, campaign_ref: str, *,
    repo_root: str | Path | None = None,
) -> SatCampaignManifest:
    """Atomically reserve campaign capacity using the fixed domain policy."""
    _validate_ref(campaign_ref)
    return _protect(lambda: _transaction(
        storage_root, campaign_ref, reserve_campaign_work, repo_root,
    ))


def reserve_campaign_manifest_capacity(
    storage_root: str | Path,
    campaign_ref: str,
    max_outstanding: int,
    *,
    repo_root: str | Path | None = None,
) -> CampaignCapacityReservation:
    """Atomically count and reserve chronological work under one store lock."""
    _validate_ref(campaign_ref)
    return _protect(lambda: _reserve_capacity(
        storage_root, campaign_ref, max_outstanding, repo_root,
    ))


def bind_campaign_manifest_recovery(
    storage_root: str | Path, campaign_ref: str, work_ref: str, recovery_ref: str, *,
    repo_root: str | Path | None = None,
) -> SatCampaignManifest:
    """Atomically bind one outstanding work item before external contact."""
    _validate_ref(campaign_ref)
    return _protect(lambda: _transaction(
        storage_root, campaign_ref,
        lambda manifest: bind_campaign_recovery(manifest, work_ref, recovery_ref=recovery_ref),
        repo_root,
    ))


def record_campaign_manifest_result(
    storage_root: str | Path, campaign_ref: str, work_ref: str,
    state: CampaignWorkState, recovery_ref: str, evidence: str | None = None, *,
    repo_root: str | Path | None = None,
) -> SatCampaignManifest:
    """Atomically record one terminal domain result for bound campaign work."""
    _validate_ref(campaign_ref)
    return _protect(lambda: _transaction(
        storage_root, campaign_ref,
        lambda manifest: record_campaign_result(
            manifest, work_ref, state, recovery_ref=recovery_ref, evidence=evidence,
        ),
        repo_root,
    ))


def split_campaign_manifest_work(
    storage_root: str | Path, campaign_ref: str, work_ref: str, *,
    repo_root: str | Path | None = None,
) -> SatCampaignManifest:
    """Atomically split one threshold-blocked base window using domain policy."""
    _validate_ref(campaign_ref)
    return _protect(lambda: _transaction(
        storage_root, campaign_ref,
        lambda manifest: split_campaign_work(manifest, work_ref), repo_root,
    ))


def project_campaign_manifest_submission_failure(
    storage_root: str | Path, campaign_ref: str, work_ref: str,
    recovery_ref: str, category: str, *, repo_root: str | Path | None = None,
) -> SatCampaignManifest:
    """Atomically project one failure and any approved split under one state lock."""
    _validate_ref(campaign_ref)
    return _protect(lambda: _transaction(
        storage_root, campaign_ref,
        lambda manifest: apply_campaign_submission_failure(
            manifest, work_ref, recovery_ref, category), repo_root))


def _initialize(root: str | Path, manifest: SatCampaignManifest, repo: str | Path | None) -> SatCampaignManifest:
    with secure_state_transaction(root, _filename(manifest.campaign_ref), repo_root=repo) as transaction:
        payload = transaction.read(max_bytes=_MAX_BYTES)
        if payload is None:
            _replace(transaction, manifest)
            return manifest
        existing = _decode(payload, manifest.campaign_ref)
        if existing != manifest:
            raise CampaignManifestStoreError("campaign-state-conflict")
        return existing


def _load(root: str | Path, campaign_ref: str, repo: str | Path | None) -> SatCampaignManifest:
    with secure_state_transaction(root, _filename(campaign_ref), repo_root=repo) as transaction:
        payload = transaction.read(max_bytes=_MAX_BYTES)
        if payload is None:
            raise CampaignManifestStoreError("campaign-state-not-found")
        return _decode(payload, campaign_ref)


def _transaction(
    root: str | Path, campaign_ref: str,
    transition: Callable[[SatCampaignManifest], SatCampaignManifest], repo: str | Path | None,
) -> SatCampaignManifest:
    with secure_state_transaction(root, _filename(campaign_ref), repo_root=repo) as transaction:
        payload = transaction.read(max_bytes=_MAX_BYTES)
        if payload is None:
            raise CampaignManifestStoreError("campaign-state-not-found")
        before = _decode(payload, campaign_ref)
        after = transition(before)
        _validate_manifest(after)
        if (after.campaign_ref, after.profile_id) != (before.campaign_ref, before.profile_id):
            raise CampaignManifestStoreError("campaign-state-identity-change")
        if after != before:
            _replace(transaction, after)
        return after


def _reserve_capacity(
    root: str | Path,
    campaign_ref: str,
    max_outstanding: int,
    repo: str | Path | None,
) -> CampaignCapacityReservation:
    with secure_state_transaction(root, _filename(campaign_ref), repo_root=repo) as transaction:
        payload = transaction.read(max_bytes=_MAX_BYTES)
        if payload is None:
            raise CampaignManifestStoreError("campaign-state-not-found")
        before = _decode(payload, campaign_ref)
        if type(max_outstanding) is not int or max_outstanding != before.max_outstanding:
            raise CampaignManifestStoreError("campaign-capacity-mismatch")
        existing = {
            item.work_ref for item in before.items
            if item.state is CampaignWorkState.OUTSTANDING
        }
        after = reserve_campaign_work(before)
        new_refs = tuple(
            item.work_ref for item in after.items
            if item.state is CampaignWorkState.OUTSTANDING and item.work_ref not in existing
        )
        if after != before:
            _replace(transaction, after)
        return CampaignCapacityReservation(after, new_refs)


def _replace(transaction: Any, manifest: SatCampaignManifest) -> None:
    transaction.replace(_encode(manifest))


def _encode(manifest: SatCampaignManifest) -> bytes:
    _validate_manifest(manifest)
    document = {"schemaVersion": 1, "campaignRef": manifest.campaign_ref,
                "profileId": manifest.profile_id, "items": [_encode_item(item) for item in manifest.items]}
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > _MAX_BYTES:
        raise CampaignManifestStoreError("campaign-state-too-large")
    return payload


def _encode_item(item: CampaignWorkItem) -> dict[str, object]:
    return {"workRef": item.work_ref, "direction": item.direction.value, "start": item.start.isoformat(),
            "end": item.end.isoformat(), "depth": item.depth, "parentRef": item.parent_ref,
            "state": item.state.value, "recoveryRef": item.recovery_ref, "evidence": item.evidence}


def _decode(payload: bytes, campaign_ref: str) -> SatCampaignManifest:
    if type(payload) is not bytes or len(payload) > _MAX_BYTES:
        reason = "campaign-state-too-large" if type(payload) is bytes else "campaign-state-invalid"
        raise CampaignManifestStoreError(reason)
    if payload.startswith(b"\xef\xbb\xbf"):
        raise CampaignManifestStoreError("campaign-state-invalid")
    try:
        document = _mapping(json.loads(payload.decode(), object_pairs_hook=_unique), _DOCUMENT_KEYS)
        version = document["schemaVersion"]
        if type(version) is not int:
            raise CampaignManifestStoreError("campaign-state-invalid")
        if version != 1:
            raise CampaignManifestStoreError("campaign-state-unsupported")
        values = document["items"]
        if type(values) is not list:
            raise CampaignManifestStoreError("campaign-state-invalid")
        manifest = SatCampaignManifest(_string(document, "campaignRef"), _string(document, "profileId"),
                                       tuple(_decode_item(value) for value in values))
        _validate_manifest(manifest)
        if manifest.campaign_ref != campaign_ref:
            raise CampaignManifestStoreError("campaign-state-invalid")
        return manifest
    except CampaignManifestStoreError:
        raise
    except (CampaignManifestError, UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        raise CampaignManifestStoreError("campaign-state-invalid") from None


def _decode_item(value: object) -> CampaignWorkItem:
    item = _mapping(value, _ITEM_KEYS)
    return CampaignWorkItem(
        _string(item, "workRef"), DownloadDirection(_string(item, "direction")),
        _date(item, "start"), _date(item, "end"), _integer(item, "depth"),
        _optional(item, "parentRef"), CampaignWorkState(_string(item, "state")),
        _optional(item, "recoveryRef"), _optional(item, "evidence"),
    )


def _validate_manifest(manifest: object) -> None:
    try:
        campaign_redacted_summary(manifest)  # type: ignore[arg-type]
    except CampaignManifestError:
        raise CampaignManifestStoreError("campaign-state-invalid") from None


def _mapping(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise CampaignManifestStoreError("campaign-state-invalid")
    return value


def _string(document: dict[str, object], key: str) -> str:
    value = document[key]
    if type(value) is not str:
        raise CampaignManifestStoreError("campaign-state-invalid")
    return value


def _optional(document: dict[str, object], key: str) -> str | None:
    value = document[key]
    if value is not None and type(value) is not str:
        raise CampaignManifestStoreError("campaign-state-invalid")
    return value


def _integer(document: dict[str, object], key: str) -> int:
    value = document[key]
    if type(value) is not int:
        raise CampaignManifestStoreError("campaign-state-invalid")
    return value


def _date(document: dict[str, object], key: str) -> date:
    value = _string(document, key)
    parsed = date.fromisoformat(value)
    if parsed.isoformat() != value:
        raise CampaignManifestStoreError("campaign-state-invalid")
    return parsed


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise CampaignManifestStoreError("campaign-state-duplicate-key")
        document[key] = value
    return document


def _validate_ref(value: object) -> None:
    if type(value) is not str or not _REF_RE.fullmatch(value):
        raise CampaignManifestStoreError("campaign-ref-invalid")


def _filename(campaign_ref: str) -> str:
    return f"sat-campaign-{campaign_ref}.json"


def _protect(operation: Callable[[], Any]) -> Any:
    try:
        return operation()
    except SecureStateFileError as error:
        raise _translate(error) from None


def _translate(error: SecureStateFileError) -> CampaignManifestStoreError:
    reason = ("campaign-state-path-invalid" if error.reason in _PATH_ERRORS
              else _ERROR_MAP.get(error.reason, "campaign-state-storage-failed"))
    return CampaignManifestStoreError(reason, committed=error.committed, uncertain=error.uncertain)
