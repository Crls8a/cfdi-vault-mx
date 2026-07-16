"""Pure internal 2026 SAT Metadata campaign policy; owns no I/O, persistence, credentials, or SAT contact."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from datetime import date, timedelta
from enum import StrEnum

from cfdi_vault.domain import DownloadDirection, RequestType

SCHEMA_VERSION = POLICY_VERSION = 1
CAMPAIGN_START = date(2026, 1, 1)
CAMPAIGN_END = date(2026, 7, 15)
WINDOW_DAYS, MAX_OUTSTANDING, MAX_SPLIT_DEPTH = 14, 2, 1
BASE_WORK_COUNT, MAX_REQUESTS = 28, 84
THRESHOLD_EVIDENCE = "sat_too_many_results"
DIRECTIONS = (DownloadDirection.RECEIVED, DownloadDirection.ISSUED)
_PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_CAMPAIGN_RE = re.compile(r"cmp-[0-9a-f]{12}")
_WORK_RE = re.compile(r"work-[0-9a-f]{12}")
_RECOVERY_RE = re.compile(r"run-[0-9a-f]{12}")
class CampaignManifestError(ValueError):
    """Reject invalid policy or transitions using a sanitized reason code."""
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)
class CampaignWorkState(StrEnum):
    """Allowed states for one campaign request work item."""
    PLANNED = "planned"
    OUTSTANDING = "outstanding"
    COMPLETED = "completed"
    NO_DATA = "no_data"
    FAILED = "failed"
    THRESHOLD_BLOCKED = "threshold_blocked"
    SPLIT = "split"
_RESULT_STATES = frozenset({CampaignWorkState.COMPLETED, CampaignWorkState.NO_DATA,
                            CampaignWorkState.FAILED, CampaignWorkState.THRESHOLD_BLOCKED})
_TERMINAL_STATES = frozenset({CampaignWorkState.COMPLETED, CampaignWorkState.NO_DATA,
                              CampaignWorkState.FAILED, CampaignWorkState.SPLIT})
@dataclass(frozen=True)
class CampaignWorkItem:
    """Immutable private state for one base or split Metadata request."""
    work_ref: str
    direction: DownloadDirection
    start: date
    end: date
    depth: int
    parent_ref: str | None
    state: CampaignWorkState = CampaignWorkState.PLANNED
    recovery_ref: str | None = field(default=None, repr=False)
    evidence: str | None = field(default=None, repr=False)
    def __post_init__(self) -> None:
        _validate_item(self)
@dataclass(frozen=True)
class SatCampaignManifest:
    """Immutable fixed-policy campaign snapshot with private operator identity."""
    campaign_ref: str
    profile_id: str = field(repr=False)
    items: tuple[CampaignWorkItem, ...]
    schema_version: int = SCHEMA_VERSION
    policy_version: int = POLICY_VERSION
    start: date = CAMPAIGN_START
    end: date = CAMPAIGN_END
    window_days: int = WINDOW_DAYS
    directions: tuple[DownloadDirection, ...] = DIRECTIONS
    max_outstanding: int = MAX_OUTSTANDING
    max_split_depth: int = MAX_SPLIT_DEPTH
    kind: RequestType = RequestType.METADATA
    def __post_init__(self) -> None:
        _validate_manifest(self)
def build_campaign_manifest(profile_id: str) -> SatCampaignManifest:
    """Build the exact deterministic 2026 Metadata campaign base snapshot."""
    _validate_profile(profile_id)
    campaign_ref = _campaign_ref(profile_id)
    items = tuple(
        CampaignWorkItem(_work_ref(campaign_ref, direction, start, end, 0, None),
                         direction, start, end, 0, None)
        for start, end, direction in _base_specs()
    )
    return SatCampaignManifest(campaign_ref, profile_id, items)
def reserve_campaign_work(manifest: SatCampaignManifest) -> SatCampaignManifest:
    """Reserve the earliest planned work up to the two-request ceiling."""
    _validate_manifest(manifest)
    free = MAX_OUTSTANDING - sum(item.state is CampaignWorkState.OUTSTANDING for item in manifest.items)
    selected = {
        item.work_ref for item in sorted(
            (item for item in manifest.items if item.state is CampaignWorkState.PLANNED), key=_priority,
        )[:free]
    }
    if not selected:
        return manifest
    return replace(manifest, items=tuple(
        replace(item, state=CampaignWorkState.OUTSTANDING) if item.work_ref in selected else item
        for item in manifest.items
    ))
def record_campaign_result(
    manifest: SatCampaignManifest,
    work_ref: str,
    state: CampaignWorkState,
    *,
    recovery_ref: str,
    evidence: str | None = None,
) -> SatCampaignManifest:
    """Record one final request result only from its outstanding snapshot."""
    _validate_manifest(manifest)
    item = _find(manifest, work_ref)
    if item.state is not CampaignWorkState.OUTSTANDING:
        raise CampaignManifestError("work-not-outstanding")
    if type(state) is not CampaignWorkState or state not in _RESULT_STATES:
        raise CampaignManifestError("result-state-invalid")
    if type(recovery_ref) is not str or not _RECOVERY_RE.fullmatch(recovery_ref):
        raise CampaignManifestError("recovery-ref-invalid")
    if state is CampaignWorkState.THRESHOLD_BLOCKED:
        if evidence != THRESHOLD_EVIDENCE:
            raise CampaignManifestError("threshold-evidence-invalid")
    elif evidence is not None:
        raise CampaignManifestError("result-evidence-invalid")
    return _replace_item(manifest, replace(
        item, state=state, recovery_ref=recovery_ref, evidence=evidence,
    ))
def split_campaign_work(manifest: SatCampaignManifest, work_ref: str) -> SatCampaignManifest:
    """Replace one approved blocked 14-day base leaf with two 7-day children."""
    _validate_manifest(manifest)
    parent = _find(manifest, work_ref)
    if parent.state is not CampaignWorkState.THRESHOLD_BLOCKED:
        raise CampaignManifestError("split-state-invalid")
    if parent.depth != 0 or (parent.end - parent.start).days + 1 != WINDOW_DAYS:
        raise CampaignManifestError("split-depth-invalid")
    if parent.evidence != THRESHOLD_EVIDENCE:
        raise CampaignManifestError("threshold-evidence-invalid")
    ranges = ((parent.start, parent.start + timedelta(days=6)),
              (parent.start + timedelta(days=7), parent.end))
    children = tuple(CampaignWorkItem(
        _work_ref(manifest.campaign_ref, parent.direction, start, end, 1, parent.work_ref),
        parent.direction, start, end, 1, parent.work_ref) for start, end in ranges)
    items = tuple(replace(item, state=CampaignWorkState.SPLIT)
                  if item.work_ref == parent.work_ref else item for item in manifest.items) + children
    return replace(manifest, items=tuple(sorted(items, key=_priority)))
def campaign_redacted_summary(manifest: SatCampaignManifest) -> dict[str, object]:
    """Return only the opaque campaign reference and aggregate counters."""
    _validate_manifest(manifest)
    counts = {state.value: sum(item.state is state for item in manifest.items) for state in CampaignWorkState}
    split_count = counts[CampaignWorkState.SPLIT.value]
    return {
        "campaignRef": manifest.campaign_ref,
        "stateCounts": counts,
        "baseCount": BASE_WORK_COUNT,
        "splitCount": split_count,
        "leafCount": BASE_WORK_COUNT + split_count,
        "totalCount": len(manifest.items),
        "outstandingCount": counts[CampaignWorkState.OUTSTANDING.value],
        "terminalCount": sum(counts[state.value] for state in _TERMINAL_STATES),
    }
def _validate_manifest(manifest: SatCampaignManifest) -> None:
    if type(manifest) is not SatCampaignManifest:
        raise CampaignManifestError("manifest-type-invalid")
    _validate_profile(manifest.profile_id)
    types = tuple(type(value) for value in (manifest.schema_version, manifest.policy_version, manifest.start,
                  manifest.end, manifest.window_days, manifest.directions, manifest.max_outstanding,
                  manifest.max_split_depth, manifest.kind))
    if types != (int, int, date, date, int, tuple, int, int, RequestType) or any(type(x) is not DownloadDirection for x in manifest.directions):
        raise CampaignManifestError("campaign-policy-invalid")
    exact = (manifest.schema_version, manifest.policy_version, manifest.start, manifest.end, manifest.window_days,
             manifest.directions, manifest.max_outstanding, manifest.max_split_depth, manifest.kind)
    if exact != (1, 1, CAMPAIGN_START, CAMPAIGN_END, 14, DIRECTIONS, 2, 1, RequestType.METADATA):
        raise CampaignManifestError("campaign-policy-invalid")
    if manifest.campaign_ref != _campaign_ref(manifest.profile_id) or not _CAMPAIGN_RE.fullmatch(manifest.campaign_ref):
        raise CampaignManifestError("campaign-ref-invalid")
    if type(manifest.items) is not tuple or len(manifest.items) > MAX_REQUESTS:
        raise CampaignManifestError("campaign-items-invalid")
    for item in manifest.items:
        _validate_item(item)
        if item.work_ref != _work_ref(
            manifest.campaign_ref, item.direction, item.start, item.end, item.depth, item.parent_ref,
        ):
            raise CampaignManifestError("work-ref-invalid")
    by_ref = {item.work_ref: item for item in manifest.items}
    if len(by_ref) != len(manifest.items):
        raise CampaignManifestError("work-ref-duplicate")
    bases = tuple(item for item in manifest.items if item.depth == 0)
    if tuple((item.start, item.end, item.direction) for item in bases) != _base_specs():
        raise CampaignManifestError("campaign-base-invalid")
    splits = tuple(item for item in bases if item.state is CampaignWorkState.SPLIT)
    if len(manifest.items) != BASE_WORK_COUNT + 2 * len(splits):
        raise CampaignManifestError("campaign-count-invalid")
    for base in bases:
        children = tuple(item for item in manifest.items if item.parent_ref == base.work_ref)
        expected = ((base.start, base.start + timedelta(days=6)),
                    (base.start + timedelta(days=7), base.end))
        if base.state is CampaignWorkState.SPLIT:
            if tuple((item.start, item.end) for item in children) != expected:
                raise CampaignManifestError("split-children-invalid")
        elif children:
            raise CampaignManifestError("split-parent-invalid")
    if sum(item.state is CampaignWorkState.OUTSTANDING for item in manifest.items) > MAX_OUTSTANDING:
        raise CampaignManifestError("outstanding-limit-exceeded")
    _validate_leaf_coverage(manifest.items)
def _validate_item(item: CampaignWorkItem) -> None:
    if type(item) is not CampaignWorkItem or type(item.work_ref) is not str or type(item.direction) is not DownloadDirection:
        raise CampaignManifestError("work-item-type-invalid")
    if type(item.start) is not date or type(item.end) is not date or type(item.depth) is not int:
        raise CampaignManifestError("work-item-type-invalid")
    if type(item.state) is not CampaignWorkState or item.depth not in {0, 1}:
        raise CampaignManifestError("work-item-invalid")
    if not _WORK_RE.fullmatch(item.work_ref) or (item.end - item.start).days + 1 != (14 if item.depth == 0 else 7):
        raise CampaignManifestError("work-item-invalid")
    if (item.depth == 0 and item.parent_ref is not None) or (
        item.depth == 1 and (type(item.parent_ref) is not str or not _WORK_RE.fullmatch(item.parent_ref))
    ):
        raise CampaignManifestError("work-parent-invalid")
    waiting = item.state in {CampaignWorkState.PLANNED, CampaignWorkState.OUTSTANDING}
    if waiting and (item.recovery_ref is not None or item.evidence is not None):
        raise CampaignManifestError("work-result-invalid")
    if not waiting and (type(item.recovery_ref) is not str or not _RECOVERY_RE.fullmatch(item.recovery_ref)):
        raise CampaignManifestError("work-result-invalid")
    if item.state in {CampaignWorkState.THRESHOLD_BLOCKED, CampaignWorkState.SPLIT}:
        if item.evidence != THRESHOLD_EVIDENCE:
            raise CampaignManifestError("threshold-evidence-invalid")
    elif item.evidence is not None:
        raise CampaignManifestError("work-evidence-invalid")
def _validate_leaf_coverage(items: tuple[CampaignWorkItem, ...]) -> None:
    for direction in DIRECTIONS:
        cursor = CAMPAIGN_START
        leaves = sorted((item for item in items if item.direction is direction
                         and item.state is not CampaignWorkState.SPLIT), key=lambda item: item.start)
        for item in leaves:
            if item.start != cursor:
                raise CampaignManifestError("leaf-coverage-invalid")
            cursor = item.end + timedelta(days=1)
        if cursor != CAMPAIGN_END + timedelta(days=1):
            raise CampaignManifestError("leaf-coverage-invalid")
def _base_specs() -> tuple[tuple[date, date, DownloadDirection], ...]:
    return tuple(
        (CAMPAIGN_START + timedelta(days=14 * index),
         CAMPAIGN_START + timedelta(days=14 * index + 13), direction)
        for index in range(14) for direction in DIRECTIONS
    )
def _validate_profile(profile_id: object) -> None:
    if type(profile_id) is not str or not _PROFILE_RE.fullmatch(profile_id):
        raise CampaignManifestError("profile-id-invalid")
def _digest(prefix: str, *parts: str) -> str:
    return f"{prefix}-{hashlib.sha256(chr(31).join(parts).encode()).hexdigest()[:12]}"
def _campaign_ref(profile_id: str) -> str:
    return _digest("cmp", profile_id, "2026-01-01", "2026-07-15", "14", "received,issued", "2", "1", "metadata")
def _work_ref(campaign_ref: str, direction: DownloadDirection, start: date, end: date,
              depth: int, parent_ref: str | None) -> str:
    return _digest("work", campaign_ref, direction.value, start.isoformat(), end.isoformat(),
                   str(depth), parent_ref or "-")
def _priority(item: CampaignWorkItem) -> tuple[date, int, int, date]:
    return item.start, DIRECTIONS.index(item.direction), item.depth, item.end
def _find(manifest: SatCampaignManifest, work_ref: str) -> CampaignWorkItem:
    if type(work_ref) is not str or not _WORK_RE.fullmatch(work_ref):
        raise CampaignManifestError("work-ref-invalid")
    for item in manifest.items:
        if item.work_ref == work_ref:
            return item
    raise CampaignManifestError("work-ref-not-found")
def _replace_item(manifest: SatCampaignManifest, updated: CampaignWorkItem) -> SatCampaignManifest:
    return replace(manifest, items=tuple(
        updated if item.work_ref == updated.work_ref else item for item in manifest.items
    ))
