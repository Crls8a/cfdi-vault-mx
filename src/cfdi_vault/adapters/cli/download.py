"""Download CLI commands."""

from __future__ import annotations

from .common import *


def _require_queue_for_enqueue(enqueue: bool) -> None:
    if enqueue and not os.getenv("RABBITMQ_URL"):
        typer.echo("--enqueue requires RABBITMQ_URL so another worker process can consume the job.", err=True)
        raise typer.Exit(code=1)

def _build_profile_download_query(
    *,
    profile_id: str,
    from_date: str,
    to_date: str,
    kind: str,
    direction: str,
) -> DownloadQuery:
    query, _ = _build_profile_download_query_with_profile(
        profile_id=profile_id,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    return query

def _print_live_metadata_scheduler_status(*, profile_id: str, summary: LiveMetadataRequestSummary) -> None:
    typer.echo("mode=metadata-verify-scheduler")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"pending_verify_count={summary.pending_verify_count}")
    typer.echo(f"due_verify_count={summary.due_verify_count}")
    typer.echo(f"next_due_verification={summary.next_due_verification}")
    typer.echo(f"finished_requests={summary.finished_requests}")
    typer.echo(f"failed_requests={summary.failed_requests}")
    typer.echo(f"package_ready_count={summary.package_ready_count}")
    typer.echo("redacted=true")

def _print_download_status(*, profile_id: str, status: DownloadStatus) -> None:
    typer.echo("mode=fake")
    typer.echo(f"profile={profile_id}")
    typer.echo(f"job_id={status.job_id}")
    typer.echo(f"request_id={status.request_id}")
    typer.echo(f"status={status.status}")
    typer.echo(f"sat_state={status.sat_state}")
    typer.echo(f"kind={status.kind}")
    typer.echo(f"direction={status.direction}")
    typer.echo(f"criteria_hash={status.criteria_hash}")
    typer.echo(f"metadata_count={status.metadata_count}")
    typer.echo(f"package_count={status.package_count}")
    typer.echo(f"downloaded_package_count={status.downloaded_package_count}")
    typer.echo(f"xml_count={status.xml_count}")

def queue_status(
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Show durable queue/job event counts."""

    rows = _service(database_url, storage).queue_status()
    typer.echo("queue,status,count")
    if not rows:
        typer.echo("(no queue events)")
        return
    for row in rows:
        typer.echo(f"{row['queue']},{row['status']},{row['count']}")

def worker_run(
    loop: bool = typer.Option(False, "--loop", help="Keep polling the configured queue instead of running once."),
    poll_seconds: float = typer.Option(5.0, "--poll-seconds", min=0.5, help="Polling interval when --loop is used."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Run the recovery worker shell."""

    worker = RecoveryWorker(_service(database_url, storage))
    if loop:
        worker.run_forever(poll_seconds=poll_seconds)
        return
    report = worker.run_once()
    typer.echo(f"processed={report.processed} detail={report.detail}")

def sync_metadata(
    rfc: str = typer.Option(..., "--rfc", help="Requester RFC."),
    tenant_id: str = typer.Option("default", "--tenant-id", help="Tenant identifier."),
    start: str = typer.Option(..., "--start", help="Start date/datetime, e.g. 2024-01-01."),
    end: str = typer.Option(..., "--end", help="End date/datetime, e.g. 2024-01-31."),
    direction: DownloadDirection = typer.Option(DownloadDirection.RECEIVED, "--direction", help="Download direction."),
    live: bool = typer.Option(False, "--live", help="Use live SAT SOAP. Not implemented in this slice."),
    enqueue: bool = typer.Option(False, "--enqueue", help="Publish the job for a worker instead of processing synchronously."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Submit a metadata sync. Fake SAT is used unless --live is passed."""

    query = build_default_query(
        tenant_id=tenant_id,
        rfc=rfc,
        direction=direction,
        request_type=RequestType.METADATA,
        start=_parse_cli_datetime(start, end_of_day=False),
        end=_parse_cli_datetime(end, end_of_day=True),
    )
    _require_queue_for_enqueue(enqueue)
    result = _service(database_url, storage).sync_metadata(query, live=live, enqueue=enqueue)
    typer.echo(f"job_id={result.job_id}")
    typer.echo(f"request_id={result.request_id}")
    typer.echo(f"status={result.status}")
    typer.echo(f"packages={','.join(result.packages)}")
    typer.echo(f"metadata_count={result.metadata_count}")

def sync_xml(
    rfc: str = typer.Option(..., "--rfc", help="Requester RFC."),
    tenant_id: str = typer.Option("default", "--tenant-id", help="Tenant identifier."),
    start: str = typer.Option(..., "--start", help="Start date/datetime, e.g. 2024-01-01."),
    end: str = typer.Option(..., "--end", help="End date/datetime, e.g. 2024-01-31."),
    direction: DownloadDirection = typer.Option(DownloadDirection.RECEIVED, "--direction", help="Download direction."),
    live: bool = typer.Option(False, "--live", help="Use live SAT SOAP. Not implemented in this slice."),
    enqueue: bool = typer.Option(False, "--enqueue", help="Publish the job for a worker instead of processing synchronously."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Submit an XML/package sync. Fake mode stores packages and extracted XML evidence."""

    query = build_default_query(
        tenant_id=tenant_id,
        rfc=rfc,
        direction=direction,
        request_type=RequestType.CFDI,
        start=_parse_cli_datetime(start, end_of_day=False),
        end=_parse_cli_datetime(end, end_of_day=True),
    )
    _require_queue_for_enqueue(enqueue)
    result = _service(database_url, storage).sync_metadata(query, live=live, enqueue=enqueue)
    typer.echo(f"job_id={result.job_id}")
    typer.echo(f"request_id={result.request_id}")
    typer.echo(f"status={result.status}")
    typer.echo(f"packages={','.join(result.packages)}")
    typer.echo(f"metadata_count={result.metadata_count}")

def download_plan(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    kind: str = typer.Option(..., "--kind", help="metadata or cfdi."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
) -> None:
    """Validate and print a safe fake/offline SAT download plan."""

    query = _build_profile_download_query(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    _print_download_query(profile_id=profile, query=query, will_submit=False)

def download_request(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    kind: str = typer.Option(..., "--kind", help="metadata or cfdi."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
) -> None:
    """Submit one fake/offline SAT download request without live SAT access."""

    query = _build_profile_download_query(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    client = FakeSatScenarioClient(FakeSatScenario.REQUEST_ACCEPTED)
    registered = DownloadRequestOrchestrator(requester=client, verifier=client).submit_once(query)
    _print_download_query(profile_id=profile, query=query, will_submit=True)
    typer.echo(f"request_id={registered.request_id}")
    typer.echo(f"action={registered.request_result.action.value}")
    typer.echo(f"sat_code={registered.request_result.sat_code}")
    typer.echo(f"message={registered.request_result.message}")

def download_sync(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    kind: str = typer.Option(..., "--kind", help="metadata or cfdi."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
) -> None:
    """Run one fake/offline SAT download sync using the setup profile storage root."""

    query, loaded_profile = _build_profile_download_query_with_profile(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    service = _download_profile_service(loaded_profile, database_url)
    try:
        result = service.sync_metadata(query, live=False, enqueue=False)
    finally:
        service.close()

    _print_download_query(profile_id=profile, query=query, will_submit=True)
    typer.echo(f"job_id={result.job_id}")
    typer.echo(f"request_id={result.request_id}")
    typer.echo(f"status={result.status}")
    typer.echo(f"metadata_count={result.metadata_count}")

def download_live_smoke(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    from_date: str = typer.Option(..., "--from", help="Start date: YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="End date: YYYY-MM-DD."),
    kind: str = typer.Option(..., "--kind", help="metadata only in this version."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
    manual_real_sat: bool = typer.Option(False, "--manual-real-sat", help="Required human gate for real SAT smoke."),
    permit: str | None = typer.Option(None, "--permit", help="One-time local live execution permit id."),
) -> None:
    """Run a human-gated metadata-only live SAT smoke command."""

    query, _ = _build_profile_download_query_with_profile(
        profile_id=profile,
        from_date=from_date,
        to_date=to_date,
        kind=kind,
        direction=direction,
    )
    permit_verified = _validate_live_smoke_guard(
        profile_id=profile,
        manual_real_sat=manual_real_sat,
        query=query,
        metadata_only=query.request_type == RequestType.METADATA,
        range_within_limit=_is_minimal_live_smoke_range(query),
        permit_ref=permit,
    )
    try:
        if permit_verified:
            result = _run_live_metadata_smoke(profile, query, live_permit_verified=True)
        else:
            result = _run_live_metadata_smoke(profile, query)
    except LiveSmokeAdapterUnavailable as exc:
        typer.echo("error=live_adapter_unavailable", err=True)
        raise typer.Exit(code=1) from exc
    except SatLiveSmokeError as exc:
        _print_live_adapter_error(exc)
        raise typer.Exit(code=1) from exc
    _print_live_smoke_result(profile_id=profile, kind=query.request_type.value, direction=query.direction.value, result=result)

def download_status(
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    job_id: str | None = typer.Option(None, "--job-id", help="Local download job id from download sync."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
) -> None:
    """Read safe fake download status or async verify scheduler aggregates."""

    loaded_profile = _load_download_profile(profile)
    if job_id is None:
        try:
            records = tuple(record for record in list_live_metadata_requests(loaded_profile.storage_root) if record.profile_id == profile)
        except LiveRequestStateError as exc:
            typer.echo("error=request_state_unavailable", err=True)
            typer.echo(f"reason={exc.reason}", err=True)
            raise typer.Exit(code=1) from exc
        _print_live_metadata_scheduler_status(
            profile_id=profile,
            summary=summarize_live_metadata_requests(records),
        )
        return

    status = read_download_status(
        _require_database_url(database_url),
        tenant_id=loaded_profile.profile_id,
        job_id=job_id,
    )
    if status is None:
        typer.echo("mode=fake", err=True)
        typer.echo(f"profile={profile}", err=True)
        typer.echo(f"job_id={job_id}", err=True)
        typer.echo("error=status_not_found", err=True)
        raise typer.Exit(code=1)
    _print_download_status(profile_id=profile, status=status)


def register(queue_app: typer.Typer, worker_app: typer.Typer, sync_app: typer.Typer, download_app: typer.Typer) -> None:
    """Register download commands."""

    queue_app.command("status")(queue_status)

    worker_app.command("run")(worker_run)

    sync_app.command("metadata")(sync_metadata)

    sync_app.command("xml")(sync_xml)

    download_app.command("plan")(download_plan)

    download_app.command("request")(download_request)

    download_app.command("sync")(download_sync)

    download_app.command("live-smoke")(download_live_smoke)

    download_app.command("status")(download_status)
