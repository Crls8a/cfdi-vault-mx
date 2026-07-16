"""Execute bounded Metadata submission effects for a verified SAT campaign."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from cfdi_vault.domain import DownloadQuery
from cfdi_vault.ports import SatRequestPort
from cfdi_vault.sat_campaign_grant import load_campaign_grant
from cfdi_vault.sat_campaign_runner import (
    CampaignSubmissionAction,
    campaign_metadata_recovery_ref,
    prepare_reserved_metadata_submissions_once,
)
from cfdi_vault.sat_metadata_submission import (
    MetadataSubmissionError,
    SubmissionStatus,
    submit_metadata_recovery_once,
)


class CampaignSubmissionEffectsError(ValueError):
    """Reject an invalid internal preparation result with a fixed reason."""


class CampaignSubmissionEffectAction(StrEnum):
    """Sanitized events emitted by one bounded effects execution."""

    RECOVERY_LINKED = "recovery_linked"
    SUBMISSION_DEFERRED = "submission_deferred"
    CLAIMED_REPLAY = "claimed_replay"
    ORPHAN_UNCERTAIN = "orphan_uncertain"
    SUBMISSION_ACCEPTED = "submission_accepted"
    SUBMISSION_FAILED = "submission_failed"
    SUBMISSION_UNCERTAIN = "submission_uncertain"
    ADAPTER_FAILED = "adapter_failed"
    SUBMISSION_ERROR = "submission_error"


@dataclass(frozen=True)
class CampaignSubmissionEffectEvent:
    """One opaque work event without query, SAT, credential, or path data."""

    work_ref: str
    action: CampaignSubmissionEffectAction


@dataclass(frozen=True)
class CampaignSubmissionEffectsResult:
    """Sanitized aggregate for at most two sequential submission attempts."""

    submission_attempts: int
    events: tuple[CampaignSubmissionEffectEvent, ...]


_PREPARATION_ACTIONS = {
    CampaignSubmissionAction.RECOVERY_LINKED:
        CampaignSubmissionEffectAction.RECOVERY_LINKED,
    CampaignSubmissionAction.SUBMISSION_DEFERRED:
        CampaignSubmissionEffectAction.SUBMISSION_DEFERRED,
    CampaignSubmissionAction.CLAIMED_REPLAY:
        CampaignSubmissionEffectAction.CLAIMED_REPLAY,
    CampaignSubmissionAction.FAILED_REPLAY:
        CampaignSubmissionEffectAction.SUBMISSION_FAILED,
    CampaignSubmissionAction.ORPHAN_UNCERTAIN:
        CampaignSubmissionEffectAction.ORPHAN_UNCERTAIN,
}
_SUBMISSION_ACTIONS = {
    SubmissionStatus.ACCEPTED: CampaignSubmissionEffectAction.SUBMISSION_ACCEPTED,
    SubmissionStatus.SUBMIT_FAILED: CampaignSubmissionEffectAction.SUBMISSION_FAILED,
    SubmissionStatus.SUBMIT_UNCERTAIN: CampaignSubmissionEffectAction.SUBMISSION_UNCERTAIN,
}


def execute_metadata_submission_effects_once(
    *,
    storage_root: str | Path,
    repo_root: str | Path,
    campaign_ref: str,
    grant_ref: str,
    profile_id: str,
    queries_by_work: Mapping[str, DownloadQuery],
    adapter_factory: Callable[[], SatRequestPort],
    now: datetime,
    invocation_ref: str | None = None,
) -> CampaignSubmissionEffectsResult:
    """Submit no more than two newly permitted Metadata requests sequentially."""
    events: list[CampaignSubmissionEffectEvent] = []
    attempts = 0
    current_invocation = invocation_ref
    verified_commit: str | None = None
    for _ in range(2):
        prepared = prepare_reserved_metadata_submissions_once(
            storage_root=storage_root, repo_root=repo_root,
            campaign_ref=campaign_ref, grant_ref=grant_ref,
            profile_id=profile_id, queries_by_work=queries_by_work,
            invocation_ref=current_invocation, max_new_submissions=1, now=now,
        )
        current_invocation = prepared.invocation_ref
        allowed = tuple(
            item for item in prepared.actions
            if item.action is CampaignSubmissionAction.SUBMISSION_ALLOWED
        )
        if len(allowed) > 1:
            raise CampaignSubmissionEffectsError("campaign-preparation-invalid")
        for item in prepared.actions:
            action = _PREPARATION_ACTIONS.get(item.action)
            if action is not None:
                events.append(CampaignSubmissionEffectEvent(item.work_ref, action))
        if not allowed:
            break
        work_ref = allowed[0].work_ref
        query = queries_by_work[work_ref]
        if verified_commit is None:
            verified_commit = load_campaign_grant(
                storage_root, grant_ref, repo_root, now=now,
            ).tested_commit
        try:
            requester = adapter_factory()
        except Exception:
            events.append(CampaignSubmissionEffectEvent(
                work_ref, CampaignSubmissionEffectAction.ADAPTER_FAILED,
            ))
            break
        attempts += 1
        try:
            claim = submit_metadata_recovery_once(
                requester=requester, query=query, now=now,
                storage_root=storage_root, profile_id=profile_id,
                criteria_hash=query.criteria_hash(), authorization_ref=grant_ref,
                tested_commit=verified_commit, entry_point="sat-campaign",
                expected_recovery_ref=campaign_metadata_recovery_ref(
                    profile_id, query.criteria_hash(),
                ),
                repo_root=repo_root,
            )
        except MetadataSubmissionError:
            events.append(CampaignSubmissionEffectEvent(
                work_ref, CampaignSubmissionEffectAction.SUBMISSION_ERROR,
            ))
            break
        action = _SUBMISSION_ACTIONS.get(claim.status)
        if action is None:
            raise CampaignSubmissionEffectsError("campaign-submission-result-invalid")
        events.append(CampaignSubmissionEffectEvent(work_ref, action))
        if claim.status is not SubmissionStatus.ACCEPTED:
            break
    return CampaignSubmissionEffectsResult(attempts, tuple(events))
