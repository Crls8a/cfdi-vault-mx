"""Productive SAT campaign create and aggregate status CLI commands."""

from __future__ import annotations

import os
from collections.abc import Callable

import typer

from cfdi_vault.sat_campaign_db_cli import CampaignDatabaseError
from cfdi_vault.sat_campaign_db_cli import campaign_status as db_campaign_status
from cfdi_vault.sat_campaign_db_cli import create_campaign as db_create_campaign
from cfdi_vault.setup_core import LocalProfile, SetupError, load_profile

from .sat_campaign_authorize import campaign_authorize
from .sat_campaign_run import campaign_run


class _CampaignCliError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def campaign_create(
    profile: str = typer.Option(..., "--profile", help="Exact local profile identifier."),
) -> None:
    """Create the fixed 2026 Metadata campaign idempotently in PostgreSQL."""

    _require_database()
    try:
        loaded = _load_exact_profile(profile)
    except SetupError:
        _fail("campaign-profile-invalid")
    except _CampaignCliError as error:
        _fail(error.reason)
    _run_db(lambda: db_create_campaign(profile, tenant_rfc=loaded.rfc))


def campaign_status(
    profile: str = typer.Option(..., "--profile", help="Exact local profile identifier."),
    campaign_ref: str = typer.Option(..., "--campaign-ref", help="Opaque campaign reference."),
) -> None:
    """Show only PostgreSQL-persisted campaign and recovery aggregates."""

    _require_database()
    _run_db_status(campaign_ref, lambda: db_campaign_status(profile, campaign_ref))


def _run_db(operation: Callable[[], dict[str, object]]) -> None:
    try:
        result = operation()
    except CampaignDatabaseError as error:
        _fail(error.reason)
    except Exception:
        _fail("campaign-database-operation-failed")
    _print_db_summary(result)


def _run_db_status(campaign_ref: str, operation: Callable[[], dict[str, object]]) -> None:
    try:
        result = operation()
    except CampaignDatabaseError as error:
        _fail(error.reason)
    except Exception:
        _fail("campaign-database-operation-failed")
    _print_db_status(campaign_ref, result)


def _load_exact_profile(profile_id: str) -> LocalProfile:
    loaded = load_profile(profile_id)
    if loaded.profile_id != profile_id:
        raise _CampaignCliError("campaign-profile-mismatch")
    return loaded


def _print_db_summary(result: dict[str, object]) -> None:
    for key in (
        "campaign_ref", "base_count", "split_count", "leaf_count", "total_count", "outstanding_count",
        "terminal_count", "planned_count", "completed_count", "no_data_count", "failed_count",
        "threshold_blocked_count",
    ):
        typer.echo(f"{key}={result.get(key)}")


def _print_db_status(campaign_ref: str, result: dict[str, object]) -> None:
    del campaign_ref
    for key in (
        "campaign_ref", "base_count", "split_count", "leaf_count", "total_count", "outstanding_count",
        "terminal_count", "planned_count", "completed_count", "no_data_count", "failed_count",
        "threshold_blocked_count", "verify_attempts", "next_check_at", "package_count", "zip_valid_count",
        "txt_count", "verify_history_count", "last_verify_result", "service_window_state",
    ):
        typer.echo(f"{key}={result.get(key)}")


def _fail(reason: str) -> None:
    typer.echo("error=sat_campaign_failed", err=True)
    typer.echo(f"reason={reason}", err=True)
    raise typer.Exit(code=1)


def _require_database() -> None:
    if not os.getenv("DATABASE_URL", "").strip():
        _fail("campaign-database-required")


def register(campaign_app: typer.Typer) -> None:
    """Register productive campaign commands."""

    campaign_app.command("create")(campaign_create)
    campaign_app.command("authorize")(campaign_authorize)
    campaign_app.command("run")(campaign_run)
    campaign_app.command("status")(campaign_status)
