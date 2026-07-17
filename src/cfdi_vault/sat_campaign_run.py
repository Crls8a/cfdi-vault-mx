"""Neutral one-shot application service for productive Metadata campaigns."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import cfdi_vault.sat_campaign_grant as grants
import cfdi_vault.sat_campaign_preflight as preflight
import cfdi_vault.sat_campaign_submission_effects as submission
from cfdi_vault.sat_campaign_adapter import build_campaign_metadata_request_factory
from cfdi_vault.sat_campaign_manifest import SatCampaignManifest
from cfdi_vault.sat_campaign_manifest_store import load_campaign_manifest
from cfdi_vault.sat_campaign_query import build_outstanding_metadata_queries
from cfdi_vault.sat_campaign_runner import reserve_metadata_campaign_capacity_once
from cfdi_vault.setup_core import ExistenceProvider, LocalProfile, load_profile

ProviderFactory = Callable[[LocalProfile], ExistenceProvider]
ChecksFactory = Callable[[LocalProfile], Mapping[preflight.CampaignPreflightCheck, preflight.NeutralCheck]]


class CampaignRunError(ValueError):
    """Report only fixed retry policy and a sanitized campaign-run reason."""

    error = "sat_campaign_run_failed"

    def __init__(self, reason: str, *, retry_safe: bool) -> None:
        self.reason = reason
        self.retry_safe = retry_safe
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class CampaignRunResult:
    """Ref-free aggregate outcome of one bounded application invocation."""

    status: Literal["completed", "attention_required"]
    reserved_count: int
    outstanding_count: int
    submission_attempts: int
    accepted_count: int
    failed_count: int
    uncertain_count: int
    deferred_count: int
    replay_count: int


def run_metadata_campaign_once(
    *, profile_id: str, campaign_ref: str, grant_ref: str, repo_root: Path,
    environ: Mapping[str, str], provider_factory: ProviderFactory,
    checks_factory: ChecksFactory,
    now: datetime | None = None,
) -> CampaignRunResult:
    """Preflight, reserve, and submit at most two due Metadata operations once."""
    try:
        current = _current_time(now)
        profile = load_profile(profile_id)
        storage_root = profile.storage_root
        manifest = load_campaign_manifest(
            storage_root, campaign_ref, repo_root=repo_root,
        )
        grant = grants.load_campaign_grant(
            storage_root, grant_ref, repo_root, now=current,
        )
        _validate_authority(
            profile, manifest, grant, profile_id, campaign_ref, grant_ref, current,
        )
        provider = provider_factory(profile)
        checks = checks_factory(profile)
        evidence = preflight.verify_campaign_preflight(
            environ=environ,
            profile=profile,
            provider=provider,
            repo_root=repo_root,
            checks=checks,
        )
    except Exception:
        raise CampaignRunError(
            "campaign-run-preflight-failed", retry_safe=True,
        ) from None

    try:
        capacity = reserve_metadata_campaign_capacity_once(
            storage_root=storage_root,
            repo_root=repo_root,
            campaign_ref=campaign_ref,
            grant_ref=grant_ref,
            profile_id=profile_id,
            now=current,
        )
        current_manifest = load_campaign_manifest(
            storage_root, campaign_ref, repo_root=repo_root,
        )
        queries = build_outstanding_metadata_queries(current_manifest, profile)
        adapter_factory = build_campaign_metadata_request_factory(
            storage_root=storage_root,
            repo_root=repo_root,
            manifest=current_manifest,
            grant_ref=grant_ref,
            evidence=evidence,
            environ=environ,
            provider_selector=provider_factory,
            now=lambda: current,
        )
        effects = submission.execute_metadata_submission_effects_once(
            storage_root=storage_root,
            repo_root=repo_root,
            campaign_ref=campaign_ref,
            grant_ref=grant_ref,
            profile_id=profile_id,
            queries_by_work=queries,
            adapter_factory=adapter_factory,
            now=current,
            invocation_ref=capacity.invocation_ref,
        )
        return _aggregate(capacity.actions, queries, effects)
    except CampaignRunError:
        raise
    except Exception:
        raise CampaignRunError(
            "campaign-run-reconciliation-required", retry_safe=False,
        ) from None


def _aggregate(reservations: tuple[object, ...], queries: Mapping[str, object],
               effects: submission.CampaignSubmissionEffectsResult) -> CampaignRunResult:
    if (type(effects) is not submission.CampaignSubmissionEffectsResult
            or type(effects.events) is not tuple
            or type(effects.submission_attempts) is not int
            or not 0 <= effects.submission_attempts <= 2):
        _reconciliation_required()
    action_type = submission.CampaignSubmissionEffectAction
    terminal = {
        action_type.SUBMISSION_ACCEPTED, action_type.SUBMISSION_FAILED,
        action_type.SUBMISSION_UNCERTAIN, action_type.SUBMISSION_ERROR,
    }
    nonterminal = {
        action_type.RECOVERY_LINKED, action_type.SUBMISSION_DEFERRED,
        action_type.CLAIMED_REPLAY, action_type.ORPHAN_UNCERTAIN,
        action_type.ADAPTER_FAILED, action_type.SUBMISSION_FAILED_REPLAY,
    }
    final: dict[str, submission.CampaignSubmissionEffectAction] = {}
    attempt_events = 0
    for event in effects.events:
        if (type(event) is not submission.CampaignSubmissionEffectEvent
                or type(event.work_ref) is not str or not event.work_ref
                or event.work_ref not in queries
                or type(event.action) is not action_type
                or event.action not in terminal | nonterminal):
            _reconciliation_required()
        attempt_events += event.action in terminal
        final[event.work_ref] = event.action
    if attempt_events != effects.submission_attempts:
        _reconciliation_required()
    actions = tuple(final.values())
    uncertain = {
        action_type.ORPHAN_UNCERTAIN, action_type.SUBMISSION_UNCERTAIN,
        action_type.ADAPTER_FAILED, action_type.SUBMISSION_ERROR,
    }
    if any(action in uncertain for action in actions):
        _reconciliation_required()
    accepted = actions.count(action_type.SUBMISSION_ACCEPTED)
    failed = sum(actions.count(action) for action in (
        action_type.SUBMISSION_FAILED, action_type.SUBMISSION_FAILED_REPLAY,
    ))
    deferred = actions.count(action_type.SUBMISSION_DEFERRED)
    replay = actions.count(action_type.CLAIMED_REPLAY)
    attention = failed + deferred + replay
    return CampaignRunResult(
        "attention_required" if attention else "completed", len(reservations),
        len(queries), effects.submission_attempts, accepted, failed, 0, deferred, replay,
    )


def _validate_authority(
    profile: object, manifest: object, grant: object, profile_id: str,
    campaign_ref: str, grant_ref: str, now: datetime,
) -> None:
    if type(profile) is not LocalProfile or type(manifest) is not SatCampaignManifest:
        raise ValueError("campaign-run-lineage-invalid")
    if type(grant) is not grants.CampaignGrant:
        raise ValueError("campaign-run-authority-invalid")
    valid = (
        profile.profile_id == profile_id
        and manifest.profile_id == profile_id
        and manifest.campaign_ref == campaign_ref
        and grant.grant_ref == grant_ref
        and grant.campaign_ref == campaign_ref
        and grant.profile_id == profile_id
        and grant.phase == "metadata-proof"
        and grant.max_outstanding == manifest.max_outstanding
        and grant.redaction_required is True
        and grant.manifest_digest == grants.campaign_manifest_digest(manifest)
        and grant.created_at <= now < grant.expires_at
    )
    if not valid:
        raise ValueError("campaign-run-authority-invalid")


def _current_time(value: datetime | None) -> datetime:
    current = datetime.now(timezone.utc) if value is None else value
    if type(current) is not datetime or current.tzinfo is None:
        raise ValueError("campaign-run-time-invalid")
    try:
        if current.utcoffset() != timezone.utc.utcoffset(current):
            raise ValueError("campaign-run-time-invalid")
    except (OverflowError, ValueError) as exc:
        raise ValueError("campaign-run-time-invalid") from exc
    return current


def _reconciliation_required() -> None:
    raise CampaignRunError(
        "campaign-run-reconciliation-required", retry_safe=False,
    )
