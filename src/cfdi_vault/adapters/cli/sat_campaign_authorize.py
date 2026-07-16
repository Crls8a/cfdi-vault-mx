"""Commit-bound authorization for the productive SAT campaign; owns no SAT contact."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import typer

from cfdi_vault.sat_campaign_grant import (
    CampaignGrant,
    CampaignGrantError,
    campaign_grant_redacted_summary,
    create_campaign_grant_for_current_commit,
)
from cfdi_vault.sat_campaign_manifest_store import (
    CampaignManifestStoreError,
    load_campaign_manifest,
)
from cfdi_vault.setup_core import SetupError, load_profile

_READY_PHASE = "metadata-proof"
_FUTURE_PHASES = frozenset({"cfdi-proof", "continue"})


class _CampaignAuthorizeError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def campaign_authorize(
    profile: str = typer.Option(..., "--profile", help="Exact local profile identifier."),
    campaign_ref: str = typer.Option(..., "--campaign-ref", help="Opaque campaign reference."),
    phase: str = typer.Option(..., "--phase", help="Authorized campaign phase."),
    expires_days: int = typer.Option(..., "--expires-days", help="Grant validity from 1 to 14 days."),
    reason: str = typer.Option(..., "--reason", help="Private operator authorization reason."),
) -> None:
    """Create one private campaign grant bound to the manifest and current Git HEAD."""
    try:
        _validate_authority(phase, expires_days)
        loaded = load_profile(profile)
        if loaded.profile_id != profile:
            raise _CampaignAuthorizeError("campaign-profile-mismatch")
        manifest = load_campaign_manifest(loaded.storage_root, campaign_ref)
        grant = create_campaign_grant_for_current_commit(
            storage_root=loaded.storage_root,
            manifest=manifest,
            profile_id=profile,
            repo_root=Path.cwd(),
            reason=reason,
            expires_in=timedelta(days=expires_days),
        )
    except SetupError:
        _fail("campaign-profile-invalid", retry_safe=True)
    except OSError:
        _fail("campaign-profile-unavailable", retry_safe=True)
    except (CampaignManifestStoreError, CampaignGrantError) as error:
        _fail(error.reason, retry_safe=error.retry_safe)
    except _CampaignAuthorizeError as error:
        _fail(error.reason, retry_safe=True)
    except Exception:
        _fail("campaign-authorize-failed", retry_safe=False)
    _print_summary(grant)


def _validate_authority(phase: str, expires_days: int) -> None:
    if phase in _FUTURE_PHASES:
        raise _CampaignAuthorizeError("campaign-grant-phase-not-ready")
    if phase != _READY_PHASE:
        raise _CampaignAuthorizeError("campaign-grant-phase-invalid")
    if not 1 <= expires_days <= 14:
        raise _CampaignAuthorizeError("campaign-grant-validity-invalid")


def _print_summary(grant: CampaignGrant) -> None:
    summary = campaign_grant_redacted_summary(grant)
    for key in (
        "grant_ref", "phase", "expires_at", "max_outstanding", "max_submissions",
        "max_invocations", "invocation_count", "submission_count",
    ):
        typer.echo(f"{key}={summary[key]}")


def _fail(reason: str, *, retry_safe: bool) -> None:
    typer.echo("error=campaign_authorize_failed", err=True)
    typer.echo(f"reason={reason}", err=True)
    typer.echo(f"retry_safe={str(retry_safe).lower()}", err=True)
    raise typer.Exit(code=1)
