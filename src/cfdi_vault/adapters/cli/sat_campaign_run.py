"""Thin productive CLI composition for one SAT campaign submission run."""
from __future__ import annotations

import os

import typer

from cfdi_vault.sat_campaign_db_cli import CampaignDatabaseError, run_from_environment


def campaign_run(
    profile: str = typer.Option(..., "--profile", help="Exact local profile identifier."),
    campaign_ref: str = typer.Option(..., "--campaign-ref", help="Opaque campaign reference."),
    grant: str = typer.Option(..., "--grant", help="Opaque campaign grant reference."),
) -> None:
    """Execute one bounded set of due campaign operations through PostgreSQL."""
    _require_database()
    try:
        result = run_from_environment(profile, campaign_ref, grant)
    except CampaignDatabaseError as error:
        _fail(error.reason, retry_safe=True)
    except Exception:
        _fail("campaign-database-run-failed", retry_safe=True)
    for key in ("status", "contacted_count", "next_check_at"):
        typer.echo(f"{key}={result.get(key)}")


def _fail(reason: str, *, retry_safe: bool) -> None:
    typer.echo("error=sat_campaign_run_failed", err=True)
    typer.echo(f"reason={reason}", err=True)
    typer.echo(f"retry_safe={str(retry_safe).lower()}", err=True)
    raise typer.Exit(code=1)


def _require_database() -> None:
    if not os.getenv("DATABASE_URL", "").strip():
        _fail("campaign-database-required", retry_safe=True)
