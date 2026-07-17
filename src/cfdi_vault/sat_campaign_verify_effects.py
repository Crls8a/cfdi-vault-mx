"""Execute bounded due-only Metadata VERIFY effects for a private SAT campaign."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from cfdi_vault.ports import SatVerificationPort
from cfdi_vault.sat_campaign_grant import load_campaign_grant
from cfdi_vault.sat_campaign_manifest import CampaignWorkState
from cfdi_vault.sat_campaign_manifest_store import load_campaign_manifest
from cfdi_vault.sat_campaign_recovery_projection import project_persisted_campaign_recovery
from cfdi_vault.sat_metadata_recovery_runner import MetadataRecoveryAdvanceOutcome, verify_metadata_recovery_once
from cfdi_vault.sat_metadata_recovery_state import MetadataRecoveryStateError, load_metadata_recovery_state
from cfdi_vault.setup_core import LocalProfile


class CampaignVerifyEffectsError(ValueError):
    """Fail closed using one fixed reason and safe persistence semantics."""
    def __init__(self, reason: str, *, retry_safe: bool = False, uncertain: bool = False) -> None:
        self.reason, self.retry_safe, self.uncertain = reason, retry_safe, uncertain
        super().__init__(reason)


class CampaignVerifyEffectAction(StrEnum):
    """Exact sanitized actions emitted for campaign VERIFY work."""
    SUBMISSION_PENDING = "submission_pending"
    WAITING = "waiting"
    VERIFY_PENDING = "verify_pending"
    PACKAGES_READY = "packages_ready"
    NO_DATA = "no_data"
    FAILED = "failed"
    SPLIT = "split"
    THRESHOLD_BLOCKED = "threshold_blocked"
    ADAPTER_FAILED = "adapter_failed"


@dataclass(frozen=True)
class CampaignVerifyEffectEvent:
    """One opaque work event with no private recovery or SAT data."""
    work_ref: str
    action: CampaignVerifyEffectAction


@dataclass(frozen=True)
class CampaignVerifyEffectsResult:
    """Sanitized result for no more than two sequential VERIFY attempts."""
    verify_attempts: int
    events: tuple[CampaignVerifyEffectEvent, ...]


_TERMINAL = {CampaignWorkState.NO_DATA: CampaignVerifyEffectAction.NO_DATA, CampaignWorkState.FAILED: CampaignVerifyEffectAction.FAILED, CampaignWorkState.SPLIT: CampaignVerifyEffectAction.SPLIT, CampaignWorkState.THRESHOLD_BLOCKED: CampaignVerifyEffectAction.THRESHOLD_BLOCKED}
_VALID_OUTCOMES = frozenset({
    ("verify_scheduled", 0, False, None, False), ("verify_scheduled", 1, True, None, False),
    ("verify_scheduled", 1, True, "verify_retryable", False), ("verify_failed", 1, False, "verify_failed", False),
    ("packages_ready", 0, False, None, False), ("packages_ready", 1, True, None, True),
    ("no_data", 1, True, None, True), ("pending_after_budget", 0, False, None, False),
    ("verify_failed", 0, False, "verify_uncertain", False), ("verify_failed", 1, True, "sat_too_many_results", False),
    ("verify_failed", 1, True, "verify_failed", False)})


def execute_metadata_verify_effects_once(
    *, storage_root: str | Path, repo_root: str | Path, campaign_ref: str,
    grant_ref: str, profile: LocalProfile,
    verifier_factory: Callable[[], SatVerificationPort], now: datetime,
) -> CampaignVerifyEffectsResult:
    """Project and run due-only VERIFY for the current two outstanding slots."""
    manifest = _protect("campaign-verify-manifest-load-failed", lambda: load_campaign_manifest(storage_root, campaign_ref, repo_root=repo_root))
    grant = _protect("campaign-verify-grant-load-failed", lambda: load_campaign_grant(storage_root, grant_ref, repo_root, now=now))
    if (type(profile) is not LocalProfile or manifest.profile_id != profile.profile_id
            or grant.campaign_ref != campaign_ref or grant.profile_id != profile.profile_id
            or type(grant.tested_commit) is not str):
        raise CampaignVerifyEffectsError("campaign-verify-lineage-invalid")
    selected = tuple(item for item in manifest.items if item.state is CampaignWorkState.OUTSTANDING)[:2]
    events: list[CampaignVerifyEffectEvent] = []
    attempts = 0
    for original in selected:
        if original.recovery_ref is None or _missing_recovery(
            storage_root, repo_root, original.recovery_ref,
        ):
            events.append(CampaignVerifyEffectEvent(
                original.work_ref, CampaignVerifyEffectAction.SUBMISSION_PENDING))
            continue
        projected = _project(storage_root, repo_root, campaign_ref, grant_ref, profile, original, now)
        current = _work(projected, original.work_ref)
        if current.state in _TERMINAL:
            events.append(CampaignVerifyEffectEvent(current.work_ref, _TERMINAL[current.state]))
            continue
        if current.state is not CampaignWorkState.OUTSTANDING:
            raise CampaignVerifyEffectsError("campaign-verify-projection-conflict")
        try:
            outcome = verify_metadata_recovery_once(
                storage_root=storage_root, recovery_ref=original.recovery_ref,
                verifier_factory=verifier_factory, now=now, tested_commit=grant.tested_commit,
                entry_point="sat-campaign", repo_root=repo_root,
            )
        except Exception:
            raise CampaignVerifyEffectsError("campaign-verify-runner-failed") from None
        _validate_outcome(outcome)
        attempts += outcome.verify_count
        projected = _project(storage_root, repo_root, campaign_ref, grant_ref, profile, original, now)
        current = _work(projected, original.work_ref)
        if outcome.verify_count == 1 and not outcome.sat_contacted:
            events.append(CampaignVerifyEffectEvent(
                current.work_ref, CampaignVerifyEffectAction.ADAPTER_FAILED))
            break
        action = _TERMINAL.get(current.state) or _live_action(current, outcome)
        events.append(CampaignVerifyEffectEvent(current.work_ref, action))
    return CampaignVerifyEffectsResult(attempts, tuple(events))


def _protect(reason, operation):  # type: ignore[no-untyped-def]
    try:
        return operation()
    except Exception as error:
        raise CampaignVerifyEffectsError(
            reason, retry_safe=getattr(error, "retry_safe", False) is True,
            uncertain=getattr(error, "uncertain", False) is True) from None


def _missing_recovery(root: str | Path, repo: str | Path, ref: str) -> bool:
    try:
        load_metadata_recovery_state(root, ref, repo_root=repo)
        return False
    except MetadataRecoveryStateError as error:
        if error.reason == "recovery-state-not-found":
            return True
    except Exception:
        pass
    raise CampaignVerifyEffectsError("campaign-verify-recovery-state-invalid") from None


def _project(root, repo, campaign, grant, profile, work, now):  # type: ignore[no-untyped-def]
    return _protect("campaign-verify-projection-failed", lambda:
        project_persisted_campaign_recovery(
            storage_root=root, repo_root=repo, campaign_ref=campaign, grant_ref=grant,
            profile=profile, work_ref=work.work_ref, now=now))


def _work(manifest, ref):  # type: ignore[no-untyped-def]
    matches = tuple(item for item in manifest.items if item.work_ref == ref)
    if len(matches) != 1:
        raise CampaignVerifyEffectsError("campaign-verify-projection-conflict")
    return matches[0]


def _validate_outcome(outcome: object) -> None:
    counters = (() if type(outcome) is not MetadataRecoveryAdvanceOutcome else (
        outcome.verify_contacts_not_before_due, outcome.verify_contacts_before_due, outcome.verify_contacts_due_unknown))
    if (type(outcome) is not MetadataRecoveryAdvanceOutcome
            or type(outcome.recovery) is not dict
            or type(outcome.recovery.get("status")) is not str
            or type(outcome.sat_contacted) is not bool
            or type(outcome.verify_count) is not int or type(outcome.terminal_status_received) is not bool
            or type(outcome.download_attempts) is not int or outcome.download_attempts != 0
            or outcome.requires_live is not False
            or any(type(value) is not int or value < 0 for value in counters)
            or sum(counters) != int(outcome.sat_contacted)
            or (outcome.recovery["status"], outcome.verify_count, outcome.sat_contacted,
                outcome.error_kind, outcome.terminal_status_received) not in _VALID_OUTCOMES):
        raise CampaignVerifyEffectsError("campaign-verify-outcome-invalid")


def _live_action(work, outcome):  # type: ignore[no-untyped-def]
    status = outcome.recovery["status"]
    if work.state is not CampaignWorkState.OUTSTANDING:
        raise CampaignVerifyEffectsError("campaign-verify-projection-conflict")
    if status == "verify_scheduled":
        return CampaignVerifyEffectAction.WAITING if outcome.verify_count == 0 else CampaignVerifyEffectAction.VERIFY_PENDING
    if status == "packages_ready":
        return CampaignVerifyEffectAction.PACKAGES_READY
    raise CampaignVerifyEffectsError("campaign-verify-outcome-invalid")
