"""Commit-bound authorization for the productive SAT campaign; owns no SAT contact."""

from __future__ import annotations

import os

import typer

from cfdi_vault.sat_campaign_db_cli import CampaignDatabaseError
from cfdi_vault.sat_campaign_db_cli import authorize_campaign as db_authorize_campaign


def campaign_authorize(
    profile: str = typer.Option(..., "--profile", help="Exact local profile identifier."),
    campaign_ref: str = typer.Option(..., "--campaign-ref", help="Opaque campaign reference."),
    phase: str = typer.Option(..., "--phase", help="Authorized campaign phase."),
    expires_days: int = typer.Option(..., "--expires-days", help="Grant validity from 1 to 14 days."),
    reason: str = typer.Option(..., "--reason", help="Private operator authorization reason."),
) -> None:
    """Create one PostgreSQL grant bound to the campaign and current commit."""
    _require_database()
    try:
        result = db_authorize_campaign(profile, campaign_ref, phase, expires_days, reason)
    except CampaignDatabaseError as error:
        _fail(error.reason, retry_safe=True)
    except Exception:
        _fail("campaign-database-authorize-failed", retry_safe=True)
    for key in ("grant_ref", "phase", "expires_at", "max_open_operations"):
        typer.echo(f"{key}={result.get(key)}")


def _fail(reason: str, *, retry_safe: bool) -> None:
    typer.echo("error=campaign_authorize_failed", err=True)
    typer.echo(f"reason={reason}", err=True)
    typer.echo(f"retry_safe={str(retry_safe).lower()}", err=True)
    raise typer.Exit(code=1)


def _require_database() -> None:
    if not os.getenv("DATABASE_URL", "").strip():
        _fail("campaign-database-required", retry_safe=True)
