"""Sanitized aggregate status projection for one productive SAT campaign."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cfdi_vault.sat_campaign_manifest import (
    CampaignWorkItem,
    CampaignWorkState,
    SatCampaignManifest,
    campaign_redacted_summary,
)
from cfdi_vault.sat_campaign_manifest_store import load_campaign_manifest
from cfdi_vault.sat_campaign_query import build_metadata_query_for_work
from cfdi_vault.sat_metadata_recovery_state import (
    MetadataRecoveryStateRecord,
    campaign_metadata_recovery_ref,
    list_metadata_recovery_states,
)
from cfdi_vault.setup_core import LocalProfile


class CampaignStatusError(ValueError):
    """Reject invalid status lineage without retaining private details."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class CampaignStatusResult:
    """Ref-free manifest and Metadata recovery aggregates."""

    base_count: int
    split_count: int
    leaf_count: int
    total_count: int
    outstanding_count: int
    terminal_count: int
    planned_count: int
    completed_count: int
    no_data_count: int
    failed_count: int
    threshold_blocked_count: int
    verify_attempts: int
    next_check_at: str
    package_count: int
    zip_valid_count: int
    txt_count: int


def load_campaign_status(
    storage_root: str | Path,
    campaign_ref: str,
    profile: LocalProfile,
) -> CampaignStatusResult:
    """Load private local state and return only validated campaign aggregates."""

    manifest = load_campaign_manifest(storage_root, campaign_ref)
    try:
        records = list_metadata_recovery_states(storage_root)
    except Exception as error:
        raise CampaignStatusError("campaign-status-recovery-invalid") from error
    return project_campaign_status(manifest, records, profile)


def project_campaign_status(
    manifest: SatCampaignManifest,
    records: tuple[MetadataRecoveryStateRecord, ...],
    profile: LocalProfile,
) -> CampaignStatusResult:
    """Project only recovery records bound to exact campaign work lineage."""

    if type(profile) is not LocalProfile or manifest.profile_id != profile.profile_id:
        raise CampaignStatusError("campaign-profile-mismatch")
    try:
        summary = campaign_redacted_summary(manifest)
        counts = summary["stateCounts"]
        if type(counts) is not dict:
            raise ValueError
        indexed = {record.recovery.recovery_ref: record for record in records}
        bound = tuple(item for item in manifest.items if item.recovery_ref is not None)
        selected = tuple(_require_exact_record(manifest, profile, item, indexed) for item in bound)
        due = tuple(
            record.recovery.to_redacted_document()["nextCheckAt"] for record in selected
            if record.recovery.next_check_at is not None
        )
        return CampaignStatusResult(
            int(summary["baseCount"]), int(summary["splitCount"]),
            int(summary["leafCount"]), int(summary["totalCount"]),
            int(summary["outstandingCount"]), int(summary["terminalCount"]),
            int(counts[CampaignWorkState.PLANNED.value]),
            int(counts[CampaignWorkState.COMPLETED.value]),
            int(counts[CampaignWorkState.NO_DATA.value]),
            int(counts[CampaignWorkState.FAILED.value]),
            int(counts[CampaignWorkState.THRESHOLD_BLOCKED.value]),
            sum(record.recovery.verify_attempts for record in selected),
            min(due, default=""),
            sum(len(record.recovery.packages) for record in selected),
            sum(
                package.zip_valid is True
                for record in selected for package in record.recovery.packages
            ),
            sum(record.recovery.txt_count for record in selected),
        )
    except CampaignStatusError:
        raise
    except Exception as error:
        raise CampaignStatusError("campaign-status-recovery-invalid") from error


def _require_exact_record(
    manifest: SatCampaignManifest,
    profile: LocalProfile,
    item: CampaignWorkItem,
    indexed: dict[str, MetadataRecoveryStateRecord],
) -> MetadataRecoveryStateRecord:
    work_ref = item.work_ref
    recovery_ref = item.recovery_ref
    record = indexed.get(recovery_ref)
    query = build_metadata_query_for_work(manifest, profile, work_ref)
    period = query.period
    provenance = record.observation_provenance if record is not None else None
    exact = (
        record is not None
        and period is not None
        and record.recovery.recovery_ref == recovery_ref
        and record.profile_id == profile.profile_id
        and record.direction == query.direction.value
        and record.kind == query.request_type.value
        and record.fecha_inicial == period.start.date().isoformat()
        and record.fecha_final == period.end.date().isoformat()
        and record.criteria_hash == query.criteria_hash()
        and recovery_ref == campaign_metadata_recovery_ref(profile.profile_id, record.criteria_hash)
        and provenance is not None
        and provenance.entry_point == "sat-campaign"
    )
    if not exact:
        raise CampaignStatusError("campaign-status-recovery-invalid")
    return record
