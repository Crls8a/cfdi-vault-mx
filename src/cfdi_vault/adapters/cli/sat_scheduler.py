"""Thin CLI adapter for the offline SAT scheduler scaffold."""

from __future__ import annotations

from pathlib import Path

import typer

from cfdi_vault.sat_contract import SatVerificationResult
from cfdi_vault.sat_live_request_state import LiveRequestStateError
from cfdi_vault.sat_scheduled_verify import run_scheduled_verify
from cfdi_vault.sat_scheduler_grant import SchedulerGrantError
from cfdi_vault.sat_scheduler_lock import SchedulerLockError
from cfdi_vault.sat_windows_task import render_windows_task_xml

from .common import _load_download_profile


class _DryRunOnlyVerifier:
    """Fail if a dry-run regression ever attempts verification."""

    def verify_request(self, request_id: str) -> SatVerificationResult:
        raise RuntimeError("scheduler-live-activation-not-enabled")


def sat_verify_due_runner(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id."),
    grant: str | None = typer.Option(None, "--grant", help="Bounded scheduler grant id for a future approved activation."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Inspect at most one due request without mutation or grant consumption."),
) -> None:
    """Inspect one due request; non-dry activation is intentionally disabled."""

    if not dry_run:
        typer.echo("mode=sat-verify-due-runner")
        typer.echo("status=blocked")
        typer.echo("reason=activation-not-enabled")
        typer.echo("grant_consumed=no")
        typer.echo("sat_real_execution=no")
        raise typer.Exit(code=1)

    local_profile = _load_download_profile(profile)
    try:
        result = run_scheduled_verify(
            storage_root=local_profile.storage_root,
            profile_id=profile,
            repo_root=Path.cwd(),
            verifier=_DryRunOnlyVerifier(),
            grant_ref=grant,
            dry_run=True,
        )
    except (LiveRequestStateError, SchedulerGrantError, SchedulerLockError) as exc:
        typer.echo("error=scheduler-runner-unavailable", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc

    report = result.report
    typer.echo("mode=sat-verify-due-runner")
    typer.echo("status=dry-run")
    typer.echo(f"profile={report.profile_id}")
    typer.echo(f"due_count={report.due_count}")
    typer.echo(f"selected_count={report.selected_count}")
    typer.echo("processed_count=0")
    typer.echo("max_requests_per_invocation=1")
    typer.echo("grant_consumed=no")
    typer.echo("sat_real_execution=no")
    typer.echo("request_created=no")
    typer.echo("package_downloaded=no")


def render_windows_task(
    profile: str = typer.Option("default", "--profile", help="Local setup profile id embedded in the XML template."),
    working_directory: str = typer.Option(
        ...,
        "--working-directory",
        help="Explicit reviewed absolute Windows repository path used for deterministic grant binding.",
    ),
) -> None:
    """Print deterministic Task Scheduler XML; never register a task."""

    try:
        document = render_windows_task_xml(profile_id=profile, working_directory=working_directory)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(document, nl=False)
