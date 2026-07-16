"""Reserve fixed Metadata campaign capacity without granting SAT contact."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from cfdi_vault.sat_campaign_grant import (
    CampaignGrant,
    claim_campaign_grant_invocation,
    load_campaign_grant,
    new_campaign_invocation_ref,
)
from cfdi_vault.sat_campaign_manifest import CampaignWorkState, SatCampaignManifest
from cfdi_vault.sat_campaign_manifest_store import (
    CampaignManifestStoreError,
    load_campaign_manifest,
    reserve_campaign_manifest_capacity,
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
