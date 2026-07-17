"""Thin productive CLI composition for one SAT campaign submission run."""
from __future__ import annotations

import os
from pathlib import Path

import typer

from cfdi_vault.sat_campaign_run import (
    CampaignRunError,
    CampaignRunResult,
    run_metadata_campaign_once,
)
from cfdi_vault.setup_core import find_repo_root

from .sat_campaign_runtime import compose_sat_campaign_windows_runtime


def campaign_run(
    profile: str = typer.Option(..., "--profile", help="Exact local profile identifier."),
    campaign_ref: str = typer.Option(..., "--campaign-ref", help="Opaque campaign reference."),
    grant: str = typer.Option(..., "--grant", help="Opaque campaign grant reference."),
) -> None:
    """Execute one bounded set of due Metadata campaign submissions."""
    try:
        repo_root = find_repo_root(Path.cwd())
        if repo_root is None:
            raise ValueError
        repo_root = repo_root.resolve(strict=True)
        runtime = compose_sat_campaign_windows_runtime(repo_root)
    except Exception:
        _fail("campaign-run-preflight-failed", retry_safe=True)
    try:
        result = run_metadata_campaign_once(
            profile_id=profile,
            campaign_ref=campaign_ref,
            grant_ref=grant,
            repo_root=repo_root,
            environ=os.environ,
            provider_factory=runtime.provider_factory,
            checks_factory=runtime.checks_factory,
        )
    except CampaignRunError as error:
        _fail(error.reason, retry_safe=error.retry_safe)
    except Exception:
        _fail("campaign-run-preflight-failed", retry_safe=True)
    _print_result(result)


def _print_result(result: CampaignRunResult) -> None:
    for key in (
        "status", "reserved_count", "outstanding_count", "submission_attempts",
        "accepted_count", "failed_count", "uncertain_count", "deferred_count", "replay_count",
        "zip_downloaded", "zip_valid", "package_count", "next_check_at", "zip_status",
    ):
        typer.echo(f"{key}={getattr(result, key)}")


def _fail(reason: str, *, retry_safe: bool) -> None:
    typer.echo("error=sat_campaign_run_failed", err=True)
    typer.echo(f"reason={reason}", err=True)
    typer.echo(f"retry_safe={str(retry_safe).lower()}", err=True)
    raise typer.Exit(code=1)
