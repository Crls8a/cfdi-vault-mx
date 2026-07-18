"""Window portion of the legacy JSON importer."""

from __future__ import annotations

from typing import Any, Callable

from sqlalchemy import select

from cfdi_vault.recovery_db import SatCampaignRecord, SatCampaignWindowRecord


def import_windows(
    session: Any, campaign: SatCampaignRecord, items: list[Any], stamp: Any,
    *, error_cls: type[ValueError], parse_date: Callable[[Any, str], Any],
    parse_int: Callable[[Any, str, int], int], status_map: dict[str, str],
) -> int:
    imported = 0
    by_ref: dict[str, SatCampaignWindowRecord] = {}
    pending: list[tuple[SatCampaignWindowRecord, str | None]] = []
    expected: list[tuple[SatCampaignWindowRecord, str | None]] = []
    seen_refs: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or not item.get("workRef"):
            raise error_cls("legacy-window-invalid")
        work_ref = str(item["workRef"])
        if work_ref in seen_refs:
            raise error_cls("legacy-window-duplicate")
        seen_refs.add(work_ref)
        existing = session.scalar(select(SatCampaignWindowRecord).where(SatCampaignWindowRecord.work_ref == work_ref))
        direction = str(item.get("direction", "received"))
        start = parse_date(item.get("start"), "window-start")
        end = parse_date(item.get("end"), "window-end")
        depth = parse_int(item.get("depth", 0), "window-depth", 0)
        state = status_map.get(str(item.get("state", "planned")), "manual_review")
        days = (end - start).days + 1
        recovery_ref = str(item["recoveryRef"]) if item.get("recoveryRef") else None
        parent_ref = str(item["parentRef"]) if item.get("parentRef") else None
        if (direction not in {"received", "issued"} or start > end or days not in {7, 14} or
                depth not in {0, 1} or (depth == 0 and days != 14) or (depth == 1 and days != 7)
                or (depth == 1 and not parent_ref)):
            raise error_cls("legacy-window-invalid")
        if existing is not None:
            if (existing.campaign_id != campaign.id or existing.direction != direction or
                    existing.start_date != start or existing.end_date != end or
                    existing.split_depth != depth or existing.recovery_ref != recovery_ref or
                    existing.status != state):
                raise error_cls("legacy-import-conflict")
            by_ref[work_ref] = existing
            expected.append((existing, parent_ref))
            continue
        record = SatCampaignWindowRecord(
            campaign_id=campaign.id, work_ref=work_ref, parent_window_id=None,
            direction=direction, start_date=start, end_date=end, split_depth=depth,
            recovery_ref=recovery_ref, status=state, created_at=stamp, updated_at=stamp,
        )
        session.add(record)
        session.flush()
        by_ref[work_ref] = record
        pending.append((record, parent_ref))
        expected.append((record, parent_ref))
        imported += 1
    for record, parent_ref in pending:
        parent = by_ref.get(parent_ref) if parent_ref else None
        if parent_ref and (parent is None or parent.id == record.id):
            raise error_cls("legacy-window-parent-unresolved")
        record.parent_window_id = parent.id if parent is not None else None
    for record, parent_ref in expected:
        parent = by_ref.get(parent_ref) if parent_ref else None
        if parent_ref and parent is None:
            raise error_cls("legacy-window-parent-unresolved")
        if parent is not None:
            if (record.direction != parent.direction or record.split_depth != 1 or
                    parent.split_depth != 0 or record.start_date < parent.start_date or
                    record.end_date > parent.end_date):
                raise error_cls("legacy-window-parent-invalid")
        if record.parent_window_id != (parent.id if parent is not None else None):
            raise error_cls("legacy-import-conflict")
    session.flush()
    return imported
