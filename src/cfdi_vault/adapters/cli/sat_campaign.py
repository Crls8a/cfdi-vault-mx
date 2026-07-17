"""Productive SAT campaign create and aggregate status CLI commands."""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

import typer

from cfdi_vault.sat_campaign_manifest import (
    CampaignManifestError,
    CampaignWorkState,
    SatCampaignManifest,
    build_campaign_manifest,
    campaign_redacted_summary,
)
from cfdi_vault.sat_campaign_manifest_store import (
    CampaignManifestStoreError,
    initialize_campaign_manifest,
    load_campaign_manifest,
)
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
    """Create the fixed 2026 Metadata campaign idempotently in private storage."""

    def operation() -> SatCampaignManifest:
        loaded = _load_exact_profile(profile)
        manifest = build_campaign_manifest(profile)
        return _load_or_initialize(loaded, manifest)

    _run(operation)


def campaign_status(
    profile: str = typer.Option(..., "--profile", help="Exact local profile identifier."),
    campaign_ref: str = typer.Option(..., "--campaign-ref", help="Opaque campaign reference."),
) -> None:
    """Show only persisted campaign aggregate counters."""

    def operation() -> SatCampaignManifest:
        loaded = _load_exact_profile(profile)
        manifest = load_campaign_manifest(loaded.storage_root, campaign_ref)
        return _require_profile(manifest, profile)

    _run(operation)


def _run(operation: Callable[[], SatCampaignManifest]) -> None:
    try:
        manifest = operation()
    except SetupError:
        _fail("campaign-profile-invalid")
    except OSError:
        _fail("campaign-profile-unavailable")
    except (CampaignManifestError, CampaignManifestStoreError, _CampaignCliError) as error:
        _fail(error.reason)
    except Exception:
        _fail("campaign-operation-failed")
    _print_summary(manifest)


def _load_exact_profile(profile_id: str) -> LocalProfile:
    loaded = load_profile(profile_id)
    if loaded.profile_id != profile_id:
        raise _CampaignCliError("campaign-profile-mismatch")
    return loaded


def _load_or_initialize(profile: LocalProfile, expected: SatCampaignManifest) -> SatCampaignManifest:
    try:
        return _require_profile(
            load_campaign_manifest(profile.storage_root, expected.campaign_ref), profile.profile_id,
        )
    except CampaignManifestStoreError as error:
        if error.reason != "campaign-state-not-found":
            raise
    try:
        return initialize_campaign_manifest(profile.storage_root, expected)
    except CampaignManifestStoreError as error:
        if error.reason != "campaign-state-conflict":
            raise
        return _require_profile(
            load_campaign_manifest(profile.storage_root, expected.campaign_ref), profile.profile_id,
        )


def _require_profile(manifest: SatCampaignManifest, profile_id: str) -> SatCampaignManifest:
    if manifest.profile_id != profile_id:
        raise _CampaignCliError("campaign-profile-mismatch")
    return manifest


def _print_summary(manifest: SatCampaignManifest) -> None:
    summary = campaign_redacted_summary(manifest)
    counts = cast(dict[str, int], summary["stateCounts"])
    output = {
        "campaign_ref": summary["campaignRef"],
        "base_count": summary["baseCount"],
        "split_count": summary["splitCount"],
        "leaf_count": summary["leafCount"],
        "total_count": summary["totalCount"],
        "outstanding_count": summary["outstandingCount"],
        "terminal_count": summary["terminalCount"],
        "planned_count": counts[CampaignWorkState.PLANNED.value],
        "completed_count": counts[CampaignWorkState.COMPLETED.value],
        "no_data_count": counts[CampaignWorkState.NO_DATA.value],
        "failed_count": counts[CampaignWorkState.FAILED.value],
        "threshold_blocked_count": counts[CampaignWorkState.THRESHOLD_BLOCKED.value],
    }
    for key, value in output.items():
        typer.echo(f"{key}={value}")


def _fail(reason: str) -> None:
    typer.echo("error=sat_campaign_failed", err=True)
    typer.echo(f"reason={reason}", err=True)
    raise typer.Exit(code=1)


def register(campaign_app: typer.Typer) -> None:
    """Register productive campaign commands."""

    campaign_app.command("create")(campaign_create)
    campaign_app.command("authorize")(campaign_authorize)
    campaign_app.command("run")(campaign_run)
    campaign_app.command("status")(campaign_status)
