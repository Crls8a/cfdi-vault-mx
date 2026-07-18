"""Sanitized aggregate status projection for SAT campaign persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cfdi_vault.recovery_db import (
    SatArtifactRecord,
    SatCampaignRecord,
    SatCampaignWindowRecord,
    SatClaimRecord,
    SatPackageRecord,
    SatRequestRecord,
    SatVerifyAttemptRecord,
)


class SatCampaignStatusMixin:
    """Expose only campaign aggregates and opaque campaign references."""

    def get_campaign_status(self, campaign_ref: str, *, profile_ref: str | None = None) -> dict[str, object] | None:
        with self._session_factory() as session:
            now = datetime.now(timezone.utc)
            campaign = session.scalar(select(SatCampaignRecord).where(SatCampaignRecord.campaign_ref == campaign_ref))
            if campaign is None:
                return None
            if profile_ref is not None and campaign.profile_ref != profile_ref:
                raise ValueError("campaign profile mismatch")
            windows = self._counts(session, SatCampaignWindowRecord.status, SatCampaignWindowRecord.campaign_id == campaign.id)
            base_count = int(session.scalar(select(func.count()).select_from(SatCampaignWindowRecord).where(
                SatCampaignWindowRecord.campaign_id == campaign.id, SatCampaignWindowRecord.split_depth == 0,
            )) or 0)
            split_count = int(session.scalar(select(func.count()).select_from(SatCampaignWindowRecord).where(
                SatCampaignWindowRecord.campaign_id == campaign.id, SatCampaignWindowRecord.split_depth == 1,
            )) or 0)
            requests = self._counts(session, SatRequestRecord.status, SatRequestRecord.campaign_id == campaign.id)
            packages = self._counts(session, SatPackageRecord.download_state, SatPackageRecord.campaign_id == campaign.id)
            artifacts = self._counts(session, SatArtifactRecord.kind, SatArtifactRecord.campaign_id == campaign.id)
            next_check = session.scalar(select(func.min(SatRequestRecord.next_check_at)).where(
                SatRequestRecord.campaign_id == campaign.id,
                SatRequestRecord.status.in_(("submitted", "waiting_verify")),
                SatRequestRecord.next_check_at.is_not(None),
            ))
            open_count = session.scalar(select(func.count()).select_from(SatClaimRecord).where(
                SatClaimRecord.campaign_id == campaign.id, SatClaimRecord.active.is_(True),
                SatClaimRecord.lease_until > now)) or 0
            attempts = session.scalar(select(func.count()).select_from(SatVerifyAttemptRecord).where(
                SatVerifyAttemptRecord.campaign_id == campaign.id)) or 0
            latest_attempt = session.scalar(select(SatVerifyAttemptRecord.result).where(
                SatVerifyAttemptRecord.campaign_id == campaign.id,
            ).order_by(SatVerifyAttemptRecord.created_at.desc(), SatVerifyAttemptRecord.id.desc()).limit(1))
            deadlines = session.scalars(select(SatRequestRecord.service_window_expires_at).where(
                SatRequestRecord.campaign_id == campaign.id,
                SatRequestRecord.service_window_expires_at.is_not(None),
            )).all()
            service_window_state = (
                "active" if any(value > now for value in deadlines)
                else "exceeded" if deadlines else "legacy"
            )
            return {"campaign_ref": campaign.campaign_ref, "phase": campaign.phase, "status": campaign.status,
                    "base_count": base_count, "split_count": split_count,
                    "leaf_count": base_count + split_count, "total_count": base_count + split_count,
                    "windows": windows, "requests": requests, "packages": packages,
                    "artifacts": artifacts, "open_operations": int(open_count),
                    "verify_attempts": int(attempts),
                    "next_check_at": next_check.isoformat() if next_check else None,
                    "last_verify_result": latest_attempt,
                    "service_window_state": service_window_state}

    @staticmethod
    def _counts(session: Session, column: Any, predicate: Any) -> dict[str, int]:
        rows = session.execute(select(column, func.count()).where(predicate).group_by(column)).all()
        return {str(value): int(count) for value, count in rows}
