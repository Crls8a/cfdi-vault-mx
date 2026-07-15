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


class MetadataPathPolicyError(ValueError):
    """A sanitized external-metadata path policy failure."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("metadata path rejected by policy")


@dataclass(frozen=True)
class MetadataDiagnosticWindow:
    """One sanitized date window and its positive metadata row count."""

    start: date
    end: date
    metadata_count: int


@dataclass(frozen=True)
class MetadataWindowPlan:
    """Sanitized offline plan derived from metadata held only in memory."""

    status: str
    start: date
    end: date
    accepted_rows: int
    rejected_rows: int
    in_range_rows: int
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
) -> MetadataWindowPlan:
    """Select up to two low-volume seven-day windows from metadata bytes.

    Invalid rows fail closed because silently ignoring them could select a live
    request window from an incomplete inventory. Entries outside the inclusive
    planning range do not influence selection.
    """

    if start > end:
        raise ValueError("start must be before or equal to end")

    parsed = parse_metadata_bytes(content)
    if not parsed.header_valid or parsed.invalid_rows:
        return MetadataWindowPlan(
            status="invalid_metadata",
            start=start,
            end=end,
            accepted_rows=parsed.accepted_count,
            rejected_rows=parsed.rejected_count,
            in_range_rows=0,
            selected_windows=(),
            live_action="none",
        )

    buckets = _build_buckets(start, end)
    counts = [0] * len(buckets)
    in_range_rows = 0
    for entry in parsed.entries:
        issued_on = entry.issue_date.date()
        if issued_on < start or issued_on > end:
            continue
        in_range_rows += 1
        bucket_index = (issued_on - start).days // WINDOW_DAYS
        counts[bucket_index] += 1

    positive = tuple(
        MetadataDiagnosticWindow(window_start, window_end, count)
        for (window_start, window_end), count in zip(buckets, counts, strict=True)
        if count > 0
    )
    selected = tuple(sorted(positive, key=lambda window: (window.metadata_count, window.start))[:MAX_SELECTED_WINDOWS])
    status = "ready" if selected else "no_received_metadata_in_range"
    return MetadataWindowPlan(
        status=status,
        start=start,
        end=end,
        accepted_rows=parsed.accepted_count,
        rejected_rows=parsed.rejected_count,
        in_range_rows=in_range_rows,
        selected_windows=selected,
        live_action="bounded_metadata_requests" if selected else "none",
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
