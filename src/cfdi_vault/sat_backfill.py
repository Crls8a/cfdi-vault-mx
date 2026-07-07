"""Historical SAT metadata backfill planning."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_live_request_state import LiveMetadataRequestRecord, list_live_metadata_requests


@dataclass(frozen=True)
class BackfillWindowPlan:
    """One safe historical metadata request candidate."""

    index: int
    query: DownloadQuery
    operation: str
    criteria_hash: str
    existing_request_ref: str = ""
    existing_status: str = ""


@dataclass(frozen=True)
class BackfillPlan:
    """Safe dry-run plan for a historical metadata backfill."""

    profile_id: str
    direction: DownloadDirection
    kind: RequestType
    window: str
    start_date: date
    end_date: date
    windows: tuple[BackfillWindowPlan, ...]

    @property
    def existing_count(self) -> int:
        return sum(1 for window in self.windows if window.existing_request_ref)

    @property
    def new_count(self) -> int:
        return len(self.windows) - self.existing_count


def build_backfill_plan(
    *,
    storage_root: str | Path,
    profile_id: str,
    requester_rfc: str,
    start_date: date,
    end_date: date,
    direction: DownloadDirection,
    kind: RequestType,
    window: str = "weekly",
) -> BackfillPlan:
    """Build a metadata-only dry-run plan without touching SAT."""

    if kind != RequestType.METADATA:
        raise ValueError("backfill only supports metadata requests")
    operation = _operation_for_direction(direction)
    existing = _existing_by_criteria(storage_root, profile_id)
    windows: list[BackfillWindowPlan] = []
    for index, period in enumerate(generate_backfill_periods(start_date, end_date, window=window), start=1):
        query = DownloadQuery(
            tenant_id=profile_id,
            requester_rfc=requester_rfc,
            direction=direction,
            request_type=kind,
            period=period,
        )
        criteria_hash = query.criteria_hash()
        record = existing.get(criteria_hash)
        windows.append(
            BackfillWindowPlan(
                index=index,
                query=query,
                operation=operation,
                criteria_hash=criteria_hash,
                existing_request_ref=record.request_ref if record else "",
                existing_status=record.status if record else "",
            )
        )
    return BackfillPlan(
        profile_id=profile_id,
        direction=direction,
        kind=kind,
        window=_normalize_window(window),
        start_date=start_date,
        end_date=end_date,
        windows=tuple(windows),
    )


def generate_backfill_periods(start_date: date, end_date: date, *, window: str = "weekly") -> tuple[DateTimePeriod, ...]:
    """Split an inclusive date range into daily or weekly UTC periods."""

    if end_date < start_date:
        raise ValueError("backfill end date must be on or after start date")
    step_days = 1 if _normalize_window(window) == "daily" else 7
    periods: list[DateTimePeriod] = []
    current = start_date
    while current <= end_date:
        current_end = min(current + timedelta(days=step_days - 1), end_date)
        start_dt = datetime.combine(current, time.min, tzinfo=timezone.utc)
        end_dt = datetime.combine(current_end, time.max, tzinfo=timezone.utc)
        if (end_dt - start_dt).total_seconds() < 2:
            raise ValueError("backfill window must span at least 2 seconds")
        periods.append(DateTimePeriod(start=start_dt, end=end_dt))
        current = current_end + timedelta(days=1)
    return tuple(periods)


def _existing_by_criteria(storage_root: str | Path, profile_id: str) -> dict[str, LiveMetadataRequestRecord]:
    records = (record for record in list_live_metadata_requests(storage_root) if record.profile_id == profile_id)
    return {record.criteria_hash: record for record in records}


def _operation_for_direction(direction: DownloadDirection) -> str:
    if direction == DownloadDirection.RECEIVED:
        return "SolicitaDescargaRecibidos"
    if direction == DownloadDirection.ISSUED:
        return "SolicitaDescargaEmitidos"
    raise ValueError("backfill direction must be received or issued")


def _normalize_window(window: str) -> str:
    normalized = window.strip().lower()
    if normalized in {"weekly", "daily"}:
        return normalized
    raise ValueError("backfill window must be weekly or daily")
