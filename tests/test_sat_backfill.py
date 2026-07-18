from __future__ import annotations

from datetime import date
from pathlib import Path

from cfdi_vault.domain import DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_backfill import build_backfill_plan, generate_backfill_periods
from cfdi_vault.sat_live_request_state import (
    persist_live_metadata_request,
)


def test_backfill_weekly_plan_marks_existing_window(tmp_path: Path) -> None:
    storage_root = tmp_path / "storage"
    first_period = generate_backfill_periods(date(2026, 1, 1), date(2026, 1, 15), window="weekly")[0]
    first_query = _metadata_query(first_period)
    existing = persist_live_metadata_request(
        storage_root=storage_root,
        profile_id="dummy-profile",
        query=first_query,
        operation="SolicitaDescargaRecibidos",
        id_solicitud="SYNTHETIC-BACKFILL-REQUEST-0001",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat backfill submit",
        permit_ref=None,
    )

    plan = build_backfill_plan(
        storage_root=storage_root,
        profile_id="dummy-profile",
        requester_rfc="XAXX010101000",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 15),
        direction=DownloadDirection.RECEIVED,
        kind=RequestType.METADATA,
        window="weekly",
    )

    assert len(plan.windows) == 3
    assert plan.existing_count == 1
    assert plan.new_count == 2
    assert plan.windows[0].criteria_hash == first_query.criteria_hash()
    assert plan.windows[0].existing_request_ref == existing.request_ref
    assert {window.operation for window in plan.windows} == {"SolicitaDescargaRecibidos"}


def test_backfill_supports_daily_windows_and_issued_operation(tmp_path: Path) -> None:
    plan = build_backfill_plan(
        storage_root=tmp_path,
        profile_id="dummy-profile",
        requester_rfc="XAXX010101000",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 2),
        direction=DownloadDirection.ISSUED,
        kind=RequestType.METADATA,
        window="daily",
    )

    assert len(plan.windows) == 2
    assert {window.operation for window in plan.windows} == {"SolicitaDescargaEmitidos"}


def _metadata_query(period) -> DownloadQuery:
    return DownloadQuery(
        "dummy-profile",
        "XAXX010101000",
        DownloadDirection.RECEIVED,
        RequestType.METADATA,
        period,
    )
