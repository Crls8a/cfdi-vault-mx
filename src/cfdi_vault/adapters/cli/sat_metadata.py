"""SAT metadata request CLI commands."""

from __future__ import annotations

from .common import *
from .sat_common import _run_live_metadata_request_smoke


def _run_live_diagnose(profile_id: str, query: DownloadQuery) -> LiveSmokeCliResult:
    return _run_live_metadata_smoke(profile_id, query)

def _print_live_metadata_request_state(
    *,
    profile_id: str,
    records: tuple[LiveMetadataRequestRecord, ...],
) -> None:
    summary = summarize_live_metadata_requests(records)
    typer.echo("mode=metadata-request-state")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"pending_count={len(records)}")
    typer.echo(f"pending_verify_count={summary.pending_verify_count}")
    typer.echo(f"due_verify_count={summary.due_verify_count}")
    typer.echo(f"next_due_verification={summary.next_due_verification}")
    typer.echo(f"package_ready_count={summary.package_ready_count}")
    typer.echo(f"failed_requests={summary.failed_requests}")
    for record in records:
        fields = [
            f"request_ref={record.request_ref}",
            f"kind={record.kind}",
            f"direction={record.direction}",
            f"operation={record.operation}",
            f"status={record.status}",
            f"attempt_count={record.attempt_count}",
            f"next_check_at={record.next_check_at}",
            f"last_checked_at={record.last_checked_at}",
            f"id_solicitud_redacted={record.id_solicitud_redacted}",
            f"criteria_hash_prefix={record.criteria_hash[:12]}",
            f"created_at={record.created_at}",
            "full_id_printed=no",
        ]
        typer.echo("request_state=" + "|".join(fields))

def _print_live_diagnose_result(
    *,
    profile_id: str,
    kind: str,
    direction: str,
    result: LiveSmokeCliResult | None,
    failed: SatLiveSmokeError | None = None,
) -> None:
    typer.echo("mode=diagnose-live")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"kind={kind}")
    typer.echo(f"direction={direction}")
    typer.echo(f"diagnostic_status={'failed' if failed else 'ok'}")
    typer.echo(f"stages={_diagnostic_stage_summary(failed.failed_stage if failed else None)}")
    if result is not None:
        typer.echo(f"result={result.result}")
        typer.echo(f"auth={result.auth}")
        typer.echo(f"request={result.request}")
        typer.echo(f"verification={result.verification}")
    typer.echo("xml_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("package_downloaded=no")
    typer.echo("recurrent_automation=no")
    if failed is not None:
        _print_live_adapter_error(failed)

def _diagnostic_stage_summary(failed_stage: str | None) -> str:
    statuses: list[str] = []
    failed_seen = False
    for stage in DIAGNOSTIC_STAGES:
        if stage in {"package_download", "package_process"}:
            status = "skipped"
        elif failed_stage == stage:
            status = "failed"
            failed_seen = True
        else:
            status = "skipped" if failed_seen else "ok"
        statuses.append(f"{stage}:{status}")
    if failed_stage and failed_stage not in DIAGNOSTIC_STAGES:
        statuses.append(f"{failed_stage}:failed")
    return ",".join(statuses)

def sat_metadata_request_smoke(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    direction: str = typer.Option("received", "--direction", help="received or issued."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT request smoke."),
    permit: str | None = typer.Option(None, "--permit", help="One-time local metadata_live_smoke permit id."),
) -> None:
    """Run guarded auth + SAT v1.5 metadata request only; no verify or package download."""

    query, _ = _build_profile_download_query_with_profile(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=RequestType.METADATA.value,
        direction=direction,
    )
    permit_verified = _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=query,
        metadata_only=True,
        range_within_limit=_is_minimal_live_smoke_range(query),
        mode="metadata-request-smoke",
        permit_ref=permit,
    )
    try:
        result = _run_live_metadata_request_smoke(profile, query, live_permit_verified=permit_verified, permit_ref=permit)
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_persist_failed", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    except LiveSmokeAdapterUnavailable as exc:
        typer.echo("error=live_adapter_unavailable", err=True)
        raise typer.Exit(code=1) from exc
    except SatLiveSmokeError as exc:
        _print_live_adapter_error(exc)
        raise typer.Exit(code=1) from exc
    _print_live_smoke_result(profile_id=profile, kind=query.request_type.value, direction=query.direction.value, result=result)

def sat_metadata_request_state(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
) -> None:
    """List redacted locally persisted live metadata requests pending verify."""

    local_profile = _load_download_profile(profile)
    try:
        records = list_live_metadata_requests(local_profile.storage_root, pending_only=True)
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_unavailable", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    _print_live_metadata_request_state(profile_id=profile, records=records)

def sat_diagnose_live(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    kind: str = typer.Option(..., "--kind", help="metadata only in this version."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT diagnostic."),
) -> None:
    """Run a human-gated metadata-only live SAT diagnostic command."""

    query, _ = _build_profile_download_query_with_profile(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=query,
        metadata_only=query.request_type == RequestType.METADATA,
        range_within_limit=_is_minimal_live_smoke_range(query),
        mode="diagnose-live",
    )
    try:
        result = _run_live_diagnose(profile, query)
    except LiveSmokeAdapterUnavailable as exc:
        typer.echo("error=live_adapter_unavailable", err=True)
        raise typer.Exit(code=1) from exc
    except SatLiveSmokeError as exc:
        _print_live_diagnose_result(profile_id=profile, kind=query.request_type.value, direction=query.direction.value, result=None, failed=exc)
        raise typer.Exit(code=1) from exc
    _print_live_diagnose_result(profile_id=profile, kind=query.request_type.value, direction=query.direction.value, result=result)
