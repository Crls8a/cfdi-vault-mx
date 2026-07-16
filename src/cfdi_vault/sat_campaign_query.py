"""Pure internal Metadata query derivation; owns no I/O, credentials, CLI, or SAT contact."""

from __future__ import annotations

from datetime import datetime, time, timezone

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_campaign_manifest import (
    CampaignWorkState,
    SatCampaignManifest,
    campaign_redacted_summary,
)
from cfdi_vault.setup_core import LocalProfile, SetupError, validate_rfc


class CampaignQueryError(ValueError):
    """Reject query derivation with a fixed reason and no private values."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def build_outstanding_metadata_queries(
    manifest: SatCampaignManifest,
    profile: LocalProfile,
) -> dict[str, DownloadQuery]:
    """Derive canonical Metadata queries for outstanding work in manifest order."""

    campaign_redacted_summary(manifest)  # Revalidate reconstructed or mutated private state.
    _validate_profile_binding(manifest, profile)
    queries: dict[str, DownloadQuery] = {}
    for item in manifest.items:
        if item.state is not CampaignWorkState.OUTSTANDING:
            continue
        if item.direction not in {DownloadDirection.RECEIVED, DownloadDirection.ISSUED}:
            raise CampaignQueryError("work-direction-unsupported")
        query = DownloadQuery(
            tenant_id=manifest.profile_id,
            requester_rfc=profile.rfc,
            direction=item.direction,
            request_type=RequestType.METADATA,
            period=DateTimePeriod(
                datetime.combine(item.start, time.min, tzinfo=timezone.utc),
                datetime.combine(item.end, time.max, tzinfo=timezone.utc),
            ),
        )
        if query.validate():
            raise CampaignQueryError("metadata-query-invalid")
        queries[item.work_ref] = query
    return queries


def _validate_profile_binding(manifest: SatCampaignManifest, profile: LocalProfile) -> None:
    if type(profile) is not LocalProfile or type(profile.profile_id) is not str:
        raise CampaignQueryError("profile-invalid")
    if profile.profile_id != manifest.profile_id:
        raise CampaignQueryError("profile-manifest-mismatch")
    if type(profile.rfc) is not str:
        raise CampaignQueryError("profile-rfc-invalid")
    try:
        canonical_rfc = validate_rfc(profile.rfc)
    except SetupError:
        raise CampaignQueryError("profile-rfc-invalid") from None
    if canonical_rfc != profile.rfc:
        raise CampaignQueryError("profile-rfc-invalid")
