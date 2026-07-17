"""Project persisted Metadata submission outcomes into private campaign state."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from cfdi_vault.domain import DownloadQuery
from cfdi_vault.sat_campaign_grant import (
    CampaignLocalReconciliationEvidence,
    campaign_grant_redacted_summary,
    campaign_manifest_digest,
    load_campaign_local_reconciliation_evidence,
)
from cfdi_vault.sat_campaign_manifest import SatCampaignManifest
from cfdi_vault.sat_campaign_manifest_store import (
    CampaignManifestStoreError,
    load_campaign_manifest,
    project_campaign_manifest_submission_failure,
)
from cfdi_vault.sat_campaign_query import build_metadata_query_for_work
from cfdi_vault.sat_metadata_recovery_state import (
    MetadataRecoveryStateError,
    campaign_metadata_recovery_ref,
    load_metadata_recovery_state,
)
from cfdi_vault.sat_metadata_submission import (
    MetadataSubmissionProjection,
    SubmissionFailureCategory,
    SubmissionStatus,
    load_metadata_submission_projection,
)
from cfdi_vault.setup_core import LocalProfile


class CampaignSubmissionProjectionError(ValueError):
    """Reject unsafe persisted projection using one fixed redacted reason."""
    def __init__(
        self, reason: str, *, committed: bool = False, uncertain: bool = False,
    ) -> None:
        self.reason, self.committed, self.uncertain = reason, committed, uncertain
        super().__init__(reason)


def project_persisted_campaign_submission(
    *, storage_root: str | Path, repo_root: str | Path, campaign_ref: str,
    grant_ref: str, profile: LocalProfile, work_ref: str, now: datetime,
) -> SatCampaignManifest:
    """Mutate only an exact persisted failed submission; all other outcomes are read-only."""
    try:
        manifest = load_campaign_manifest(storage_root, campaign_ref, repo_root=repo_root)
        query = build_metadata_query_for_work(manifest, profile, work_ref)
        criteria_hash = query.criteria_hash()
        recovery_ref = campaign_metadata_recovery_ref(profile.profile_id, criteria_hash)
    except Exception:
        _deny("campaign-projection-query-invalid")
    try:
        evidence = load_campaign_local_reconciliation_evidence(
            storage_root, grant_ref, repo_root, now=now)
        if (type(evidence) is not CampaignLocalReconciliationEvidence
                or evidence.authorizes_sat_contact is not False):
            raise TypeError
        grant = evidence.grant
        campaign_grant_redacted_summary(grant)
        if (grant.campaign_ref != manifest.campaign_ref
                or grant.profile_id != profile.profile_id
                or grant.manifest_digest != campaign_manifest_digest(manifest)):
            raise ValueError
        related = tuple(claim for claim in grant.submission_claims
                        if claim.work_ref == work_ref or claim.recovery_ref == recovery_ref)
        if (len(related) != 1 or related[0].work_ref != work_ref
                or related[0].recovery_ref != recovery_ref
                or related[0].grant_ref != grant_ref):
            raise ValueError
    except Exception:
        _deny("campaign-projection-lineage-invalid")
    try:
        projection = load_metadata_submission_projection(
            storage_root, query=query, profile_id=profile.profile_id,
            criteria_hash=criteria_hash, authorization_ref=grant_ref,
            recovery_ref=recovery_ref, repo_root=repo_root)
    except Exception:
        _deny("campaign-projection-submission-invalid")
    if projection is None:
        return manifest
    _validate_projection(projection)
    if projection.status is SubmissionStatus.ACCEPTED:
        _validate_accepted_recovery(
            storage_root, repo_root, recovery_ref, profile, query, criteria_hash, grant_ref)
        return manifest
    if projection.status is not SubmissionStatus.SUBMIT_FAILED:
        return manifest
    assert projection.failure_category is not None
    try:
        return project_campaign_manifest_submission_failure(
            storage_root, campaign_ref, work_ref, recovery_ref,
            projection.failure_category.value, repo_root=repo_root)
    except CampaignManifestStoreError as error:
        raise CampaignSubmissionProjectionError(
            "campaign-projection-write-failed",
            committed=error.committed, uncertain=error.uncertain) from None
    except Exception:
        _deny("campaign-projection-write-failed")


def _validate_projection(projection: object) -> None:
    if type(projection) is not MetadataSubmissionProjection:
        _deny("campaign-projection-submission-invalid")
    status, category = projection.status, projection.failure_category
    valid = ((status in {SubmissionStatus.CLAIMED, SubmissionStatus.ACCEPTED} and category is None)
             or (status is SubmissionStatus.SUBMIT_UNCERTAIN
                 and category is SubmissionFailureCategory.SUBMIT_UNCERTAIN)
             or (status is SubmissionStatus.SUBMIT_FAILED
                 and type(category) is SubmissionFailureCategory
                 and category is not SubmissionFailureCategory.SUBMIT_UNCERTAIN))
    if not valid:
        _deny("campaign-projection-submission-invalid")


def _validate_accepted_recovery(
    storage: str | Path, repo: str | Path, recovery_ref: str,
    profile: LocalProfile, query: DownloadQuery, criteria_hash: str, grant_ref: str,
) -> None:
    try:
        record = load_metadata_recovery_state(storage, recovery_ref, repo_root=repo)
    except MetadataRecoveryStateError as error:
        if error.reason == "recovery-state-not-found":
            return
        _deny("campaign-projection-recovery-invalid")
    period = query.period
    exact = (record.recovery.recovery_ref == recovery_ref
             and record.profile_id == profile.profile_id
             and record.criteria_hash == criteria_hash
             and record.direction == query.direction.value
             and record.kind == query.request_type.value and period is not None
             and record.fecha_inicial == period.start.date().isoformat()
             and record.fecha_final == period.end.date().isoformat()
             and record.authorization_ref == grant_ref)
    if not exact:
        _deny("campaign-projection-recovery-invalid")


def _deny(reason: str) -> None:
    raise CampaignSubmissionProjectionError(reason)
