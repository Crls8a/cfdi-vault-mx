"""Project persisted VERIFY terminal state into the private SAT campaign manifest."""
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
from cfdi_vault.sat_campaign_manifest import CampaignWorkItem, CampaignWorkState, SatCampaignManifest
from cfdi_vault.sat_campaign_manifest_store import (
    CampaignManifestStoreError,
    load_campaign_manifest,
    project_campaign_manifest_submission_failure,
    record_campaign_manifest_result,
)
from cfdi_vault.sat_campaign_query import build_metadata_query_for_work
from cfdi_vault.sat_metadata_recovery import MetadataRecovery, RecoveryStatus
from cfdi_vault.sat_metadata_recovery_state import (
    MetadataObservationProvenance,
    MetadataRecoveryStateRecord,
    MetadataVerifyErrorKind,
    campaign_metadata_recovery_ref,
    load_metadata_recovery_state,
)
from cfdi_vault.setup_core import LocalProfile


class CampaignRecoveryProjectionError(ValueError):
    """Reject unsafe local recovery projection using fixed redacted reasons."""

    def __init__(
        self, reason: str, *, committed: bool = False, uncertain: bool = False,
    ) -> None:
        self.reason, self.committed, self.uncertain = reason, committed, uncertain
        super().__init__(reason)

    @property
    def retry_safe(self) -> bool:
        """Return whether retry needs no prior persisted-state reconciliation."""
        return not self.committed and not self.uncertain


def project_persisted_campaign_recovery(
    *, storage_root: str | Path, repo_root: str | Path, campaign_ref: str,
    grant_ref: str, profile: LocalProfile, work_ref: str, now: datetime,
) -> SatCampaignManifest:
    """Project one exact local recovery without SAT contact or package processing."""
    try:
        manifest = load_campaign_manifest(storage_root, campaign_ref, repo_root=repo_root)
        query = build_metadata_query_for_work(manifest, profile, work_ref)
        if type(query) is not DownloadQuery or query.period is None:
            raise TypeError
        criteria_hash = query.criteria_hash()
        recovery_ref = campaign_metadata_recovery_ref(profile.profile_id, criteria_hash)
        work = _work(manifest, work_ref)
    except Exception:
        _deny("campaign-recovery-projection-query-invalid")
    try:
        evidence = load_campaign_local_reconciliation_evidence(
            storage_root, grant_ref, repo_root, now=now)
        if (type(evidence) is not CampaignLocalReconciliationEvidence
                or evidence.authorizes_sat_contact is not False):
            raise TypeError
        grant = evidence.grant
        campaign_grant_redacted_summary(grant)
        if (grant.grant_ref != grant_ref or grant.campaign_ref != manifest.campaign_ref
                or grant.profile_id != profile.profile_id
                or grant.manifest_digest != campaign_manifest_digest(manifest)):
            raise ValueError
        related = tuple(claim for claim in grant.submission_claims
                        if claim.work_ref == work_ref or claim.recovery_ref == recovery_ref)
        if (len(related) != 1 or related[0].grant_ref != grant_ref
                or related[0].work_ref != work_ref or related[0].recovery_ref != recovery_ref
                or related[0].profile_id != profile.profile_id
                or related[0].tested_commit != grant.tested_commit):
            raise ValueError
        claim = related[0]
    except Exception:
        _deny("campaign-recovery-projection-lineage-invalid")
    try:
        record = load_metadata_recovery_state(storage_root, recovery_ref, repo_root=repo_root)
        _validate_recovery(record, query, profile, criteria_hash, recovery_ref, grant_ref,
                           grant.tested_commit)
        if record.recovery.created_at < claim.claimed_at:
            raise ValueError
    except CampaignRecoveryProjectionError:
        raise
    except Exception:
        _deny("campaign-recovery-projection-recovery-invalid")
    status = _validate_state(record)
    if status in {RecoveryStatus.VERIFY_SCHEDULED, RecoveryStatus.PACKAGES_READY}:
        _require_manifest_state(work, recovery_ref, CampaignWorkState.OUTSTANDING)
        return manifest
    if status is RecoveryStatus.NO_DATA:
        if _matches(work, recovery_ref, CampaignWorkState.NO_DATA):
            return manifest
        _require_manifest_state(work, recovery_ref, CampaignWorkState.OUTSTANDING)
        return _write(lambda: record_campaign_manifest_result(
            storage_root, campaign_ref, work_ref, CampaignWorkState.NO_DATA,
            recovery_ref, repo_root=repo_root))
    kind = record.last_verify_error_kind
    category = status.value
    if status is RecoveryStatus.VERIFY_FAILED:
        if type(kind) is not MetadataVerifyErrorKind:
            _deny("campaign-recovery-projection-state-invalid")
        category = kind.value
    return _write(lambda: project_campaign_manifest_submission_failure(
        storage_root, campaign_ref, work_ref, recovery_ref, category, repo_root=repo_root))


def _validate_recovery(
    record: object, query: DownloadQuery, profile: LocalProfile, criteria_hash: str,
    recovery_ref: str, grant_ref: str, tested_commit: str,
) -> None:
    if type(record) is not MetadataRecoveryStateRecord or type(record.recovery) is not MetadataRecovery:
        _deny("campaign-recovery-projection-recovery-invalid")
    period, provenance = query.period, record.observation_provenance
    exact = (record.recovery.recovery_ref == recovery_ref
             and record.profile_id == profile.profile_id
             and record.criteria_hash == criteria_hash
             and record.direction == query.direction.value
             and record.kind == query.request_type.value and period is not None
             and record.fecha_inicial == period.start.date().isoformat()
             and record.fecha_final == period.end.date().isoformat()
             and record.authorization_ref == grant_ref
             and type(provenance) is MetadataObservationProvenance
             and provenance.entry_point == "sat-campaign"
             and provenance.tested_commit == tested_commit)
    if not exact:
        _deny("campaign-recovery-projection-recovery-invalid")


def _validate_state(record: MetadataRecoveryStateRecord) -> RecoveryStatus:
    status, kind = record.recovery.status, record.last_verify_error_kind
    if type(status) is not RecoveryStatus or (kind is not None and type(kind) is not MetadataVerifyErrorKind):
        _deny("campaign-recovery-projection-state-invalid")
    allowed = {
        RecoveryStatus.VERIFY_SCHEDULED: {None, MetadataVerifyErrorKind.VERIFY_RETRYABLE,
                                          MetadataVerifyErrorKind.VERIFY_UNCERTAIN},
        RecoveryStatus.PACKAGES_READY: {None},
        RecoveryStatus.NO_DATA: {None},
        RecoveryStatus.PENDING_AFTER_BUDGET: {None, MetadataVerifyErrorKind.VERIFY_RETRYABLE,
                                              MetadataVerifyErrorKind.VERIFY_UNCERTAIN},
        RecoveryStatus.VERIFY_FAILED: {MetadataVerifyErrorKind.SAT_TOO_MANY_RESULTS,
                                       MetadataVerifyErrorKind.VERIFY_FAILED,
                                       MetadataVerifyErrorKind.VERIFY_UNCERTAIN},
    }
    if status not in allowed or kind not in allowed[status]:
        _deny("campaign-recovery-projection-state-invalid")
    return status


def _work(manifest: SatCampaignManifest, work_ref: str) -> CampaignWorkItem:
    matches = tuple(item for item in manifest.items if item.work_ref == work_ref)
    if len(matches) != 1:
        raise ValueError
    return matches[0]


def _matches(work: CampaignWorkItem, recovery_ref: str, state: CampaignWorkState) -> bool:
    return work.state is state and work.recovery_ref == recovery_ref and work.evidence is None


def _require_manifest_state(
    work: CampaignWorkItem, recovery_ref: str, expected: CampaignWorkState,
) -> None:
    if not _matches(work, recovery_ref, expected):
        _deny("campaign-recovery-projection-manifest-conflict")


def _write(operation):  # type: ignore[no-untyped-def]
    try:
        return operation()
    except CampaignManifestStoreError as error:
        raise CampaignRecoveryProjectionError(
            "campaign-recovery-projection-write-failed",
            committed=error.committed, uncertain=error.uncertain) from None
    except Exception:
        _deny("campaign-recovery-projection-write-failed")


def _deny(reason: str) -> None:
    raise CampaignRecoveryProjectionError(reason) from None
