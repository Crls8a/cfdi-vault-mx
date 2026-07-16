"""Reserve fixed Metadata campaign capacity without granting SAT contact."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, time, timezone
from enum import StrEnum
from pathlib import Path

from cfdi_vault.domain import DownloadQuery, RequestType
from cfdi_vault.sat_campaign_grant import (
    CampaignGrant,
    CampaignGrantError,
    CampaignSubmissionClaim,
    claim_campaign_grant_invocation,
    claim_campaign_grant_submission,
    load_campaign_grant,
    new_campaign_invocation_ref,
)
from cfdi_vault.sat_campaign_manifest import (
    CampaignWorkItem,
    CampaignWorkState,
    SatCampaignManifest,
)
from cfdi_vault.sat_campaign_manifest_store import (
    CampaignManifestStoreError,
    bind_campaign_manifest_recovery,
    load_campaign_manifest,
    reserve_campaign_manifest_capacity,
)
from cfdi_vault.sat_metadata_recovery_state import (
    MetadataRecoveryStateError,
    campaign_metadata_recovery_ref,
    load_metadata_recovery_state,
)
from cfdi_vault.sat_metadata_submission import (
    MetadataSubmissionError,
    SubmissionStatus,
    load_metadata_submission_projection,
)


class CampaignRunnerError(ValueError):
    """Reject invalid runner lineage using a fixed sanitized reason code."""

    def __init__(
        self, reason: str, *, committed: bool = False, uncertain: bool = False,
    ) -> None:
        self.reason, self.committed, self.uncertain = reason, committed, uncertain
        super().__init__(reason)

    @property
    def retry_safe(self) -> bool:
        """Return whether a retry needs no persisted-state reconciliation."""
        return not self.committed and not self.uncertain


class CampaignCapacityAction(StrEnum):
    """Internal reservation outcome that explicitly grants no SAT permission."""

    RESERVED_WITHOUT_CONTACT = "reserved_without_contact"


@dataclass(frozen=True)
class CampaignCapacityWork:
    """One opaque internal work reservation with no contact material."""

    action: CampaignCapacityAction
    work_ref: str


@dataclass(frozen=True)
class CampaignCapacityResult:
    """Aggregate outstanding capacity after one claimed invocation."""

    invocation_ref: str
    outstanding_work_refs: tuple[str, ...]
    actions: tuple[CampaignCapacityWork, ...]


class CampaignSubmissionAction(StrEnum):
    """Sanitized outcomes that never expose query or recovery material."""

    RECOVERY_LINKED = "recovery_linked"
    SUBMISSION_ALLOWED = "submission_allowed"
    SUBMISSION_DEFERRED = "submission_deferred"
    CLAIMED_REPLAY = "claimed_replay"
    FAILED_REPLAY = "failed_replay"
    ORPHAN_UNCERTAIN = "orphan_uncertain"


@dataclass(frozen=True)
class CampaignSubmissionWork:
    """One opaque preparation result for already-outstanding work."""

    action: CampaignSubmissionAction
    work_ref: str


@dataclass(frozen=True)
class CampaignSubmissionResult:
    """Aggregate bind and claim results; owns no SAT side effect."""

    invocation_ref: str
    actions: tuple[CampaignSubmissionWork, ...]


def reserve_metadata_campaign_capacity_once(
    *,
    storage_root: str | Path,
    repo_root: str | Path,
    campaign_ref: str,
    grant_ref: str,
    profile_id: str,
    invocation_ref: str | None = None,
    now: datetime | None = None,
) -> CampaignCapacityResult:
    """Claim one invocation and reserve capacity without permitting SAT contact."""
    manifest = load_campaign_manifest(storage_root, campaign_ref, repo_root=repo_root)
    grant = load_campaign_grant(storage_root, grant_ref, repo_root, now=now)
    _validate_authority(manifest, grant, profile_id)
    claimed_ref = new_campaign_invocation_ref() if invocation_ref is None else invocation_ref
    claim = claim_campaign_grant_invocation(
        storage_root, grant_ref, claimed_ref, profile_id, repo_root, now=now,
    )
    try:
        reservation = reserve_campaign_manifest_capacity(
            storage_root, campaign_ref, grant.max_outstanding, repo_root=repo_root,
        )
    except CampaignManifestStoreError as error:
        if claim.created:
            raise CampaignRunnerError(
                "campaign-invocation-claimed-capacity-failed",
                committed=True,
                uncertain=error.uncertain,
            ) from error
        raise
    outstanding = tuple(
        item.work_ref for item in reservation.manifest.items
        if item.state is CampaignWorkState.OUTSTANDING
    )
    actions = tuple(
        CampaignCapacityWork(CampaignCapacityAction.RESERVED_WITHOUT_CONTACT, work_ref)
        for work_ref in reservation.new_work_refs
    )
    return CampaignCapacityResult(claimed_ref, outstanding, actions)


def prepare_reserved_metadata_submissions_once(
    *,
    storage_root: str | Path,
    repo_root: str | Path,
    campaign_ref: str,
    grant_ref: str,
    profile_id: str,
    queries_by_work: Mapping[str, DownloadQuery],
    invocation_ref: str | None = None,
    max_new_submissions: int = 2,
    now: datetime | None = None,
) -> CampaignSubmissionResult:
    """Bind and claim existing Metadata work without contacting SAT."""
    if (
        type(max_new_submissions) is not int
        or not 1 <= max_new_submissions <= 2
    ):
        raise CampaignRunnerError("campaign-new-submission-limit-invalid")
    manifest = load_campaign_manifest(storage_root, campaign_ref, repo_root=repo_root)
    grant = load_campaign_grant(storage_root, grant_ref, repo_root, now=now)
    _validate_authority(manifest, grant, profile_id)
    outstanding = tuple(
        item for item in manifest.items if item.state is CampaignWorkState.OUTSTANDING
    )
    queries = _validated_queries(outstanding, queries_by_work, profile_id)
    claimed_ref = new_campaign_invocation_ref() if invocation_ref is None else invocation_ref
    claim_campaign_grant_invocation(
        storage_root, grant_ref, claimed_ref, profile_id, repo_root, now=now,
    )
    grant = load_campaign_grant(storage_root, grant_ref, repo_root, now=now)
    actions: list[CampaignSubmissionWork] = []
    new_submission_count = 0
    new_submissions_blocked = False
    for work in outstanding:
        query = queries[work.work_ref]
        recovery_ref = campaign_metadata_recovery_ref(profile_id, query.criteria_hash())
        existing = _submission_for(grant, work, recovery_ref)
        if existing is not None:
            action = _existing_claim_action(
                existing, storage_root, repo_root, grant_ref, query,
            )
            actions.append(CampaignSubmissionWork(action, work.work_ref))
            if action is CampaignSubmissionAction.ORPHAN_UNCERTAIN:
                new_submissions_blocked = True
            continue
        if work.recovery_ref is None:
            try:
                manifest = bind_campaign_manifest_recovery(
                    storage_root, campaign_ref, work.work_ref, recovery_ref,
                    repo_root=repo_root,
                )
            except CampaignManifestStoreError as error:
                raise CampaignRunnerError(
                    "campaign-recovery-bind-failed", committed=True,
                    uncertain=error.uncertain,
                ) from error
            actions.append(CampaignSubmissionWork(
                CampaignSubmissionAction.RECOVERY_LINKED, work.work_ref,
            ))
        elif work.recovery_ref != recovery_ref:
            raise CampaignRunnerError("campaign-query-lineage-invalid", committed=True)
        if new_submissions_blocked or new_submission_count >= max_new_submissions:
            actions.append(CampaignSubmissionWork(
                CampaignSubmissionAction.SUBMISSION_DEFERRED, work.work_ref,
            ))
            continue
        try:
            claim = claim_campaign_grant_submission(
                storage_root, grant_ref, claimed_ref, manifest, work.work_ref,
                recovery_ref, profile_id, repo_root, now=now,
            )
        except CampaignGrantError as error:
            if error.reason == "campaign-grant-submission-conflict":
                grant = load_campaign_grant(storage_root, grant_ref, repo_root, now=now)
                reconciled = _submission_for(grant, work, recovery_ref)
                if reconciled is not None:
                    action = _existing_claim_action(
                        reconciled, storage_root, repo_root, grant_ref, query,
                    )
                    actions.append(CampaignSubmissionWork(action, work.work_ref))
                    if action is CampaignSubmissionAction.ORPHAN_UNCERTAIN:
                        new_submissions_blocked = True
                    continue
            raise CampaignRunnerError(
                "campaign-submission-claim-failed", committed=True,
                uncertain=error.uncertain,
            ) from error
        if claim.created:
            action = CampaignSubmissionAction.SUBMISSION_ALLOWED
            new_submission_count += 1
        else:
            grant = load_campaign_grant(storage_root, grant_ref, repo_root, now=now)
            reconciled = _submission_for(grant, work, recovery_ref)
            if reconciled is None:
                raise CampaignRunnerError("campaign-submission-state-invalid", committed=True)
            action = _existing_claim_action(
                reconciled, storage_root, repo_root, grant_ref, query,
            )
            if action is CampaignSubmissionAction.ORPHAN_UNCERTAIN:
                new_submissions_blocked = True
        actions.append(CampaignSubmissionWork(action, work.work_ref))
        grant = load_campaign_grant(storage_root, grant_ref, repo_root, now=now)
    return CampaignSubmissionResult(claimed_ref, tuple(actions))


def _validated_queries(
    outstanding: tuple[CampaignWorkItem, ...],
    supplied: Mapping[str, DownloadQuery],
    profile_id: str,
) -> dict[str, DownloadQuery]:
    if not isinstance(supplied, Mapping) or set(supplied) != {
        item.work_ref for item in outstanding
    }:
        raise CampaignRunnerError("campaign-query-lineage-invalid")
    result: dict[str, DownloadQuery] = {}
    for item in outstanding:
        query = supplied[item.work_ref]
        period = query.period if type(query) is DownloadQuery else None
        extras = (
            query.issuer_rfc, query.receiver_rfcs, query.uuid, query.document_status,
            query.document_type, query.complement, query.rfc_on_behalf,
            query.recovery_variant_reason,
        ) if type(query) is DownloadQuery else (True,)
        if (
            period is None or query.validate() or query.tenant_id != profile_id
            or query.direction is not item.direction
            or query.request_type is not RequestType.METADATA
            or period.start != datetime.combine(item.start, time.min, tzinfo=timezone.utc)
            or period.end != datetime.combine(item.end, time.max, tzinfo=timezone.utc)
            or any(extras)
        ):
            raise CampaignRunnerError("campaign-query-lineage-invalid")
        result[item.work_ref] = query
    return result


def _submission_for(
    grant: CampaignGrant, work: CampaignWorkItem, recovery_ref: str,
) -> CampaignSubmissionClaim | None:
    matches = tuple(
        claim for claim in grant.submission_claims
        if claim.work_ref == work.work_ref or claim.recovery_ref == recovery_ref
    )
    if len(matches) > 1 or matches and (
        matches[0].work_ref != work.work_ref or matches[0].recovery_ref != recovery_ref
    ):
        raise CampaignRunnerError("campaign-submission-lineage-invalid", committed=True)
    return matches[0] if matches else None


def _existing_claim_action(
    claim: CampaignSubmissionClaim,
    storage_root: str | Path,
    repo_root: str | Path,
    grant_ref: str,
    query: DownloadQuery,
) -> CampaignSubmissionAction:
    try:
        record = load_metadata_recovery_state(
            storage_root, claim.recovery_ref, repo_root=repo_root,
        )
    except MetadataRecoveryStateError as error:
        if error.reason == "recovery-state-not-found":
            try:
                projection = load_metadata_submission_projection(
                    storage_root, query=query, profile_id=claim.profile_id,
                    criteria_hash=query.criteria_hash(), authorization_ref=grant_ref,
                    recovery_ref=claim.recovery_ref, repo_root=repo_root,
                )
            except MetadataSubmissionError as submission_error:
                raise CampaignRunnerError(
                    "campaign-submission-state-invalid", committed=True,
                ) from submission_error
            if (projection is not None
                    and projection.status is SubmissionStatus.SUBMIT_FAILED):
                return CampaignSubmissionAction.FAILED_REPLAY
            return CampaignSubmissionAction.ORPHAN_UNCERTAIN
        raise CampaignRunnerError(
            "campaign-recovery-state-invalid", committed=True,
        ) from error
    period = query.period
    assert period is not None
    exact = (
        record.recovery.recovery_ref == claim.recovery_ref
        and record.profile_id == claim.profile_id
        and record.criteria_hash == query.criteria_hash()
        and record.direction == query.direction.value
        and record.kind == query.request_type.value
        and record.fecha_inicial == period.start.date().isoformat()
        and record.fecha_final == period.end.date().isoformat()
        and record.authorization_ref == grant_ref
    )
    if not exact:
        raise CampaignRunnerError("campaign-recovery-lineage-invalid", committed=True)
    return CampaignSubmissionAction.CLAIMED_REPLAY


def _validate_authority(
    manifest: SatCampaignManifest,
    grant: CampaignGrant,
    profile_id: str,
) -> None:
    if (
        manifest.campaign_ref != grant.campaign_ref
        or manifest.profile_id != profile_id
        or grant.profile_id != profile_id
        or grant.phase != "metadata-proof"
        or grant.max_outstanding != manifest.max_outstanding
    ):
        raise CampaignRunnerError("campaign-authority-lineage-invalid")
