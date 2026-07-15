"""Internal metadata-led planning for bounded SAT live diagnostics.

This reference-system helper consumes operator-supplied metadata bytes only. It
does not perform network calls, persist source rows, or expose fiscal fields in
its result.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

from cfdi_vault.metadata_parser import parse_metadata_bytes

WINDOW_DAYS = 7
MAX_SELECTED_WINDOWS = 2
VALID_DIRECTIONS = frozenset({"received", "issued"})
ACTIVE_STATUSES = frozenset({"active", "vigente"})
CANCELLED_STATUSES = frozenset({"canceled", "cancelled", "cancelado"})


class MetadataPathPolicyError(ValueError):
    """A sanitized external-metadata path policy failure."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("metadata path rejected by policy")


@dataclass(frozen=True)
class MetadataDiagnosticWindow:
    """One sanitized date window and its eligible deduplicated UUID count."""

    start: date
    end: date
    eligible_count: int


@dataclass(frozen=True)
class MetadataWindowPlan:
    """Sanitized offline plan derived from metadata held only in memory."""

    status: str
    reason: str
    direction: str
    start: date
    end: date
    accepted_rows: int
    rejected_rows: int
    unique_uuids: int
    duplicate_rows: int
    eligible_uuids: int
    in_range_eligible_uuids: int
    cancelled_no_xml_expected: int
    manual_review_uuids: int
    conflicting_uuids: int
    selected_windows: tuple[MetadataDiagnosticWindow, ...]
    live_action: str


def resolve_external_metadata_path(candidate: Path, *, checkout_root: Path) -> Path:
    """Resolve a metadata path and reject any lexical or real checkout descendant."""

    if _is_windows_namespace_path(candidate):
        raise MetadataPathPolicyError("metadata_namespace_path_rejected")
    candidate_absolute = Path(os.path.abspath(candidate.expanduser()))
    checkout_absolute = Path(os.path.abspath(checkout_root.expanduser()))
    try:
        candidate_resolved = candidate_absolute.resolve(strict=False)
        checkout_resolved = checkout_absolute.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise MetadataPathPolicyError("metadata_path_resolution_failed") from exc

    if candidate_absolute.is_relative_to(checkout_absolute) or candidate_resolved.is_relative_to(checkout_resolved):
        raise MetadataPathPolicyError("metadata_inside_checkout")
    return candidate_resolved


def _is_windows_namespace_path(candidate: Path) -> bool:
    """Detect extended/device namespace spellings before path normalization."""

    spelling = os.fspath(candidate).replace("/", "\\")
    return spelling.startswith(("\\\\?\\", "\\\\.\\"))


def build_metadata_window_plan(
    content: bytes,
    *,
    start: date,
    end: date,
    direction: str = "received",
) -> MetadataWindowPlan:
    """Classify XML eligibility and select two low-volume weekly windows.

    Invalid rows fail closed because silently ignoring them could select a live
    request window from an incomplete inventory. Unknown or contradictory UUID
    evidence also fails closed. Entries outside the inclusive planning range do
    not influence selection.
    """

    if start > end:
        raise ValueError("start must be before or equal to end")
    normalized_direction = direction.strip().casefold()
    if normalized_direction not in VALID_DIRECTIONS:
        raise ValueError("direction must be received or issued")

    parsed = parse_metadata_bytes(content, allow_empty_status=True)
    if not parsed.header_valid or parsed.invalid_rows:
        return _plan(
            status="invalid_metadata", reason="invalid_header_or_row", direction=normalized_direction,
            start=start, end=end, accepted_rows=parsed.accepted_count, rejected_rows=parsed.rejected_count,
        )

    entries_by_uuid: dict[str, list] = {}
    for entry in parsed.entries:
        entries_by_uuid.setdefault(entry.uuid.strip().upper(), []).append(entry)

    duplicate_rows = sum(len(entries) - 1 for entries in entries_by_uuid.values())
    eligible_dates: list[date] = []
    cancelled_no_xml_expected = 0
    manual_review_uuids = 0
    conflicting_uuids = 0
    for entries in entries_by_uuid.values():
        statuses = {_normalize_status(entry.status) for entry in entries}
        issue_dates = {entry.issue_date.date() for entry in entries}
        if len(statuses) != 1 or len(issue_dates) != 1:
            conflicting_uuids += 1
            manual_review_uuids += 1
            continue
        status = statuses.pop()
        if status == "unknown":
            manual_review_uuids += 1
        elif status == "active" or (status == "cancelled" and normalized_direction == "issued"):
            eligible_dates.append(issue_dates.pop())
        else:
            cancelled_no_xml_expected += 1

    common = dict(
        direction=normalized_direction,
        start=start,
        end=end,
        accepted_rows=parsed.accepted_count,
        rejected_rows=parsed.rejected_count,
        unique_uuids=len(entries_by_uuid),
        duplicate_rows=duplicate_rows,
        eligible_uuids=len(eligible_dates),
        cancelled_no_xml_expected=cancelled_no_xml_expected,
        manual_review_uuids=manual_review_uuids,
        conflicting_uuids=conflicting_uuids,
    )
    if manual_review_uuids:
        return _plan(
            status="metadata_requires_manual_review",
            reason="unknown_or_conflicting_metadata",
            **common,
        )

    buckets = _build_buckets(start, end)
    counts = [0] * len(buckets)
    in_range_eligible_uuids = 0
    for issued_on in eligible_dates:
        if issued_on < start or issued_on > end:
            continue
        in_range_eligible_uuids += 1
        bucket_index = (issued_on - start).days // WINDOW_DAYS
        counts[bucket_index] += 1

    positive = tuple(
        MetadataDiagnosticWindow(window_start, window_end, count)
        for (window_start, window_end), count in zip(buckets, counts, strict=True)
        if count > 0
    )
    selected = tuple(sorted(positive, key=lambda window: (window.eligible_count, window.start))[:MAX_SELECTED_WINDOWS])
    status = "ready" if selected else "no_xml_eligible_metadata_in_range"
    return MetadataWindowPlan(
        status=status,
        reason="eligibility_ready" if selected else "no_eligible_uuid_in_range",
        in_range_eligible_uuids=in_range_eligible_uuids,
        selected_windows=selected,
        live_action="none",
        **common,
    )


def _normalize_status(value: str) -> str:
    """Reduce SAT metadata status variants to eligibility states."""

    normalized = " ".join(value.split()).casefold()
    if normalized in ACTIVE_STATUSES:
        return "active"
    if normalized in CANCELLED_STATUSES:
        return "cancelled"
    return "unknown"


def _plan(
    *,
    status: str,
    reason: str,
    direction: str,
    start: date,
    end: date,
    accepted_rows: int,
    rejected_rows: int,
    unique_uuids: int = 0,
    duplicate_rows: int = 0,
    eligible_uuids: int = 0,
    cancelled_no_xml_expected: int = 0,
    manual_review_uuids: int = 0,
    conflicting_uuids: int = 0,
) -> MetadataWindowPlan:
    """Build a fail-closed plan without selectable windows."""

    return MetadataWindowPlan(
        status=status,
        reason=reason,
        direction=direction,
        start=start,
        end=end,
        accepted_rows=accepted_rows,
        rejected_rows=rejected_rows,
        unique_uuids=unique_uuids,
        duplicate_rows=duplicate_rows,
        eligible_uuids=eligible_uuids,
        in_range_eligible_uuids=0,
        cancelled_no_xml_expected=cancelled_no_xml_expected,
        manual_review_uuids=manual_review_uuids,
        conflicting_uuids=conflicting_uuids,
        selected_windows=(),
        live_action="none",
    )


def _build_buckets(start: date, end: date) -> tuple[tuple[date, date], ...]:
    """Build inclusive fixed windows, allowing a final partial window."""

    buckets: list[tuple[date, date]] = []
    cursor = start
    while cursor <= end:
        window_end = min(cursor + timedelta(days=WINDOW_DAYS - 1), end)
        buckets.append((cursor, window_end))
        cursor = window_end + timedelta(days=1)
    return tuple(buckets)
