"""Shared helpers for SAT CLI subfamilies."""

from __future__ import annotations

from .common import *


def _is_backfill_submit_range(query: DownloadQuery) -> bool:
    if query.period is None:
        return False
    elapsed_seconds = (query.period.end - query.period.start).total_seconds()
    elapsed_days = (query.period.end.date() - query.period.start.date()).days + 1
    return 2 <= elapsed_seconds and elapsed_days <= MAX_BACKFILL_RANGE_DAYS

def _run_live_metadata_request_smoke(
    profile_id: str,
    query: DownloadQuery,
    *,
    live_permit_verified: bool = False,
    permit_ref: str | None = None,
    source_command: str = "sat metadata-request-smoke",
    status: str = "accepted",
    max_range_days: int = 1,
) -> LiveSmokeCliResult:
    profile = _load_download_profile(profile_id)
    adapter = SatLiveMetadataSmokeAdapter(
        profile=profile,
        provider=_setup_provider(profile_id),
        transport=_live_smoke_transport(live_permit_verified=live_permit_verified),
    )
    result = adapter.metadata_request_smoke(query, max_range_days=max_range_days)
    request_ref = ""
    if getattr(result, "request", "") == "accepted" and getattr(result, "id_solicitud", ""):
        stored = persist_live_metadata_request(
            storage_root=profile.storage_root,
            profile_id=profile_id,
            query=query,
            operation=getattr(result, "operation", ""),
            id_solicitud=getattr(result, "id_solicitud"),
            sat_code=getattr(result, "sat_code", ""),
            sat_message=getattr(result, "sat_message", ""),
            source_command=source_command,
            permit_ref=permit_ref,
            status=status,
        )
        request_ref = stored.request_ref
    return _live_smoke_cli_result(result, request_ref=request_ref)

def _query_from_live_request_record(requester_rfc: str, record: LiveMetadataRequestRecord) -> DownloadQuery:
    try:
        start = _parse_state_datetime(record.fecha_inicial)
        end = _parse_state_datetime(record.fecha_final)
        direction = DownloadDirection(record.direction)
        request_type = RequestType(record.kind)
    except (ValueError, TypeError) as exc:
        typer.echo("error=request_state_invalid", err=True)
        typer.echo("reason=request-state-query-invalid", err=True)
        raise typer.Exit(code=1) from exc
    return DownloadQuery(
        record.profile_id,
        requester_rfc,
        direction,
        request_type,
        DateTimePeriod(start, end),
    )

def _parse_state_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)

def _join_lint_values(values: tuple[str, ...]) -> str:
    return ",".join(values) if values else "none"
