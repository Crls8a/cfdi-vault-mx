"""SAT backfill CLI commands."""

from __future__ import annotations

from .common import *
from .sat_common import _is_backfill_submit_range, _run_live_metadata_request_smoke


def _deny_backfill_submit(reason: str) -> None:
    typer.echo("error=backfill_submit_denied", err=True)
    typer.echo(f"reason={reason}", err=True)
    raise typer.Exit(code=1)

def _print_backfill_plan(plan: BackfillPlan) -> None:
    typer.echo("mode=backfill-plan")
    typer.echo(f"profile={plan.profile_id}")
    typer.echo(f"kind={plan.kind.value}")
    typer.echo(f"direction={plan.direction.value}")
    typer.echo(f"window={plan.window}")
    typer.echo(f"from={plan.start_date.isoformat()}")
    typer.echo(f"to={plan.end_date.isoformat()}")
    typer.echo(f"window_count={len(plan.windows)}")
    typer.echo(f"existing_count={plan.existing_count}")
    typer.echo(f"new_count={plan.new_count}")
    typer.echo("sat_real_execution=no")
    typer.echo("package_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("xml_downloaded=no")
    typer.echo("pdf_generated=no")
    typer.echo("redacted=true")
    for window in plan.windows:
        period = window.query.period
        fields = [
            f"index={window.index}",
            f"from={period.start.isoformat() if period else ''}",
            f"to={period.end.isoformat() if period else ''}",
            f"operation={window.operation}",
            f"criteria_hash={window.criteria_hash}",
            f"exists={str(bool(window.existing_request_ref)).lower()}",
            f"request_ref={window.existing_request_ref}",
            f"status={window.existing_status}",
        ]
        typer.echo("window_plan=" + "|".join(fields))

def _print_backfill_submit_result(
    *,
    plan: BackfillPlan,
    selected: tuple[object, ...],
    result: LiveSmokeCliResult | None,
) -> None:
    typer.echo("mode=backfill-submit")
    typer.echo(f"profile={plan.profile_id}")
    typer.echo(f"kind={plan.kind.value}")
    typer.echo(f"direction={plan.direction.value}")
    typer.echo(f"window={plan.window}")
    typer.echo(f"window_count={len(plan.windows)}")
    typer.echo(f"existing_count={plan.existing_count}")
    typer.echo(f"selected_count={len(selected)}")
    typer.echo(f"submitted_count={1 if result and result.request == 'accepted' else 0}")
    typer.echo(f"sat_real_execution={'adapter_enabled' if selected else 'no'}")
    typer.echo("verification=not_run")
    typer.echo("package_downloaded=no")
    typer.echo("zip_downloaded=no")
    typer.echo("xml_downloaded=no")
    typer.echo("pdf_generated=no")
    if result is not None:
        typer.echo(f"criteria_hash={getattr(selected[0], 'criteria_hash', '')}")
        typer.echo(f"operation={result.operation}")
        typer.echo(f"request={result.request}")
        typer.echo(f"request_ref={result.request_ref}")
        typer.echo(f"id_solicitud_redacted={result.id_solicitud_redacted}")
        typer.echo(f"scheduler_status={VERIFY_SCHEDULED}")

def _parse_backfill_date(value: str, *, label: str) -> date:
    try:
        return datetime.fromisoformat(value.strip()).date()
    except ValueError as exc:
        raise typer.BadParameter(f"{label} must be a valid YYYY-MM-DD date") from exc

def sat_backfill_plan(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    direction: str = typer.Option("received", "--direction", help="received or issued."),
    kind: str = typer.Option("metadata", "--kind", help="metadata only in this version."),
    window: str = typer.Option("weekly", "--window", help="weekly or daily."),
) -> None:
    """Plan historical metadata windows without calling SAT."""

    local_profile = _load_download_profile(profile)
    request_type = _parse_download_kind(kind)
    download_direction = _parse_download_direction(direction)
    try:
        plan = build_backfill_plan(
            storage_root=local_profile.storage_root,
            profile_id=local_profile.profile_id,
            requester_rfc=local_profile.rfc,
            start_date=_parse_backfill_date(from_date, label="--from"),
            end_date=_parse_backfill_date(to_date, label="--to"),
            direction=download_direction,
            kind=request_type,
            window=window,
        )
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_unavailable", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        typer.echo("error=invalid_backfill_plan", err=True)
        typer.echo(f"reason={exc}", err=True)
        raise typer.Exit(code=1) from exc
    _print_backfill_plan(plan)

def sat_backfill_submit(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    direction: str = typer.Option("received", "--direction", help="received or issued."),
    kind: str = typer.Option("metadata", "--kind", help="metadata only in this version."),
    window: str = typer.Option("weekly", "--window", help="weekly or daily."),
    limit_windows: int | None = typer.Option(None, "--limit-windows", min=1, help="Required; first live version allows exactly 1."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT backfill submit."),
    permit: str | None = typer.Option(None, "--permit", help="One-time local metadata_backfill_submit permit id."),
) -> None:
    """Submit one planned historical metadata request; no verify or package download."""

    if not manual_real_sat:
        _deny_backfill_submit("manual-real-sat-required")
    if permit is None:
        _deny_backfill_submit("permit-required-for-live")
    if limit_windows is None:
        _deny_backfill_submit("limit-windows-required")
    if limit_windows != 1:
        _deny_backfill_submit("limit-one-required")
    local_profile = _load_download_profile(profile)
    try:
        plan = build_backfill_plan(
            storage_root=local_profile.storage_root,
            profile_id=local_profile.profile_id,
            requester_rfc=local_profile.rfc,
            start_date=_parse_backfill_date(from_date, label="--from"),
            end_date=_parse_backfill_date(to_date, label="--to"),
            direction=_parse_download_direction(direction),
            kind=_parse_download_kind(kind),
            window=window,
        )
    except LiveRequestStateError as exc:
        typer.echo("error=request_state_unavailable", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        typer.echo("error=invalid_backfill_submit", err=True)
        typer.echo(f"reason={exc}", err=True)
        raise typer.Exit(code=1) from exc
    pending = tuple(window_plan for window_plan in plan.windows if not window_plan.existing_request_ref)
    selected = pending[:limit_windows]
    if not selected:
        _print_backfill_submit_result(plan=plan, selected=(), result=None)
        return
    selected_window = selected[0]
    permit_verified = _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=selected_window.query,
        metadata_only=True,
        range_within_limit=_is_backfill_submit_range(selected_window.query),
        mode="backfill-submit",
        permit_ref=permit,
        permit_scope=BACKFILL_SUBMIT_SCOPE,
    )
    try:
        result = _run_live_metadata_request_smoke(
            profile,
            selected_window.query,
            live_permit_verified=permit_verified,
            permit_ref=permit,
            source_command="sat backfill submit",
            status=VERIFY_SCHEDULED,
            max_range_days=MAX_BACKFILL_RANGE_DAYS,
        )
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
    _print_backfill_submit_result(plan=plan, selected=selected, result=result)
