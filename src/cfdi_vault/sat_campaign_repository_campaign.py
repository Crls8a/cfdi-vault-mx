"""Campaign, window and grant persistence operations."""

from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import and_, exists, or_, select
from sqlalchemy.orm import aliased

from cfdi_vault.recovery_db import (
    SatArtifactRecord,
    SatCampaignRecord,
    SatCampaignWindowRecord,
    SatGrantRecord,
    SatMetadataImportRecord,
)


class SatCampaignRepositoryCampaignMixin:
    """Create immutable campaign planning records with idempotent writes."""

    _GRANT_PHASES = frozenset({"metadata-proof", "cfdi-proof", "continue"})

    def create_campaign(self, *, campaign_ref: str, tenant_id: str, profile_ref: str,
                        manifest_sha256: str, commit_ref: str, phase: str, status: str,
                        budget: int, now: datetime | None = None) -> SatCampaignRecord:
        now = now or datetime.now(timezone.utc)
        with self._session_factory() as session:
            existing = session.scalar(select(SatCampaignRecord).where(
                SatCampaignRecord.campaign_ref == campaign_ref))
            if existing:
                if (existing.tenant_id, existing.profile_ref, existing.manifest_sha256, existing.commit_ref,
                    existing.phase, existing.status, existing.budget) != (
                    tenant_id, profile_ref, manifest_sha256, commit_ref, phase, status, budget
                ):
                    raise ValueError("campaign identity conflict")
                return existing
            record = SatCampaignRecord(campaign_ref=campaign_ref, tenant_id=tenant_id, profile_ref=profile_ref,
                manifest_sha256=manifest_sha256, commit_ref=commit_ref, phase=phase, status=status,
                max_open_operations=2, budget=budget, created_at=now, updated_at=now)
            session.add(record)
            session.commit()
            return record

    def reserve_window(self, *, campaign_ref: str, work_ref: str, direction: str,
                       start_date: date, end_date: date, parent_work_ref: str | None = None,
                       status: str = "reserved", now: datetime | None = None) -> SatCampaignWindowRecord:
        now = now or datetime.now(timezone.utc)
        days = (end_date - start_date).days + 1
        if days not in (7, 14):
            raise ValueError("window must cover 7 or 14 days")
        with self._session_factory() as session:
            campaign = self._campaign(session, campaign_ref)
            existing = session.scalar(select(SatCampaignWindowRecord).where(
                SatCampaignWindowRecord.work_ref == work_ref))
            if existing:
                parent_id = None
                if parent_work_ref:
                    parent_record = session.scalar(select(SatCampaignWindowRecord).where(
                        SatCampaignWindowRecord.work_ref == parent_work_ref,
                        SatCampaignWindowRecord.campaign_id == campaign.id,
                    ))
                    parent_id = parent_record.id if parent_record else None
                if (existing.campaign_id, existing.direction, existing.start_date, existing.end_date,
                    existing.parent_window_id, existing.status) != (
                    campaign.id, direction, start_date, end_date, parent_id, status
                ):
                    raise ValueError("window identity conflict")
                return existing
            parent = None
            depth = 0
            if parent_work_ref:
                parent = session.scalar(select(SatCampaignWindowRecord).where(
                    SatCampaignWindowRecord.work_ref == parent_work_ref,
                    SatCampaignWindowRecord.campaign_id == campaign.id,
                ))
                if (parent is None or parent.split_depth != 0 or days != 7 or
                        direction != parent.direction or
                        start_date < parent.start_date or end_date > parent.end_date):
                    raise ValueError("window split must be a same-campaign 14-to-7-day child")
                depth = 1
            elif days != 14:
                raise ValueError("unsplit window must cover 14 days")
            record = SatCampaignWindowRecord(campaign_id=campaign.id, work_ref=work_ref,
                parent_window_id=parent.id if parent else None, direction=direction,
                start_date=start_date, end_date=end_date, split_depth=depth, status=status,
                created_at=now, updated_at=now)
            session.add(record)
            session.commit()
            return record

    def create_grant(self, *, campaign_ref: str, grant_ref: str, phase: str, reason: str,
                     budget: int, expires_at: datetime, now: datetime | None = None) -> SatGrantRecord:
        now = now or datetime.now(timezone.utc)
        with self._session_factory() as session:
            campaign = self._campaign(session, campaign_ref)
            existing = session.scalar(select(SatGrantRecord).where(SatGrantRecord.grant_ref == grant_ref))
            if existing:
                if (existing.campaign_id, existing.phase, existing.reason, existing.budget,
                    existing.expires_at) != (campaign.id, phase, reason, budget, expires_at):
                    raise ValueError("grant identity conflict")
                return existing
            record = SatGrantRecord(campaign_id=campaign.id, grant_ref=grant_ref, phase=phase,
                manifest_sha256=campaign.manifest_sha256, commit_ref=campaign.commit_ref,
                profile_ref=campaign.profile_ref, reason=reason, budget=budget,
                expires_at=expires_at, created_at=now)
            session.add(record)
            session.commit()
            return record

    def has_eligible_metadata_import(self, campaign_ref: str) -> bool:
        """Return whether a campaign has trustworthy eligible metadata evidence.

        A metadata import is eligible for the CFDI lane only after the worker
        has persisted structural evidence for a supported SAT TXT and counted
        at least one eligible record.  The external artifact must be a
        metadata package/TXT that passed validation; fiscal rows remain outside
        this aggregate query.
        """

        with self._session_factory() as session:
            campaign = self._campaign(session, campaign_ref)
            latest_import = aliased(SatMetadataImportRecord)
            evidence = session.scalar(
                select(SatMetadataImportRecord.id)
                .join(
                    SatArtifactRecord,
                    SatArtifactRecord.id == SatMetadataImportRecord.artifact_id,
                )
                .where(
                    SatMetadataImportRecord.campaign_id == campaign.id,
                    SatMetadataImportRecord.encoding == "utf-8-sig",
                    SatMetadataImportRecord.delimiter == "~",
                    SatMetadataImportRecord.header_compatible.is_(True),
                    SatMetadataImportRecord.record_count > 0,
                    SatMetadataImportRecord.eligible_count > 0,
                    SatArtifactRecord.campaign_id == campaign.id,
                    SatArtifactRecord.window_id == SatMetadataImportRecord.window_id,
                    SatArtifactRecord.kind.in_(("metadata_zip", "metadata_txt")),
                    SatArtifactRecord.validation_status.in_(("valid", "processed")),
                    ~exists(select(latest_import.id).where(
                        latest_import.campaign_id == SatMetadataImportRecord.campaign_id,
                        latest_import.window_id == SatMetadataImportRecord.window_id,
                        or_(
                            latest_import.created_at > SatMetadataImportRecord.created_at,
                            and_(
                                latest_import.created_at == SatMetadataImportRecord.created_at,
                                latest_import.id > SatMetadataImportRecord.id,
                            ),
                        ),
                    )),
                )
                .limit(1)
            )
            return evidence is not None

    def validate_grant(self, *, campaign_ref: str, grant_ref: str, profile_ref: str,
                       commit_ref: str, phase: str | None = None,
                       now: datetime | None = None) -> SatGrantRecord:
        """Validate grant provenance, phase and expiry before external effects.

        ``phase`` remains an optional exact-match guard for callers that already
        know the lane they are executing.  When omitted, the phase is read from
        the durable grant identified by ``grant_ref`` and returned with the
        validated record.  This is required when a campaign has not yet
        advanced its aggregate phase even though a later, evidence-gated grant
        has been issued.
        """

        stamp = now or datetime.now(timezone.utc)
        with self._session_factory() as session:
            campaign = self._campaign(session, campaign_ref)
            if campaign.profile_ref != profile_ref or campaign.commit_ref != commit_ref:
                raise ValueError("campaign grant identity mismatch")
            grant = session.scalar(select(SatGrantRecord).where(
                SatGrantRecord.campaign_id == campaign.id, SatGrantRecord.grant_ref == grant_ref,
            ))
            if grant is None or grant.phase not in self._GRANT_PHASES or grant.expires_at <= stamp:
                raise ValueError("campaign grant invalid or expired")
            if phase is not None and grant.phase != phase:
                raise ValueError("campaign grant phase mismatch")
            return grant
