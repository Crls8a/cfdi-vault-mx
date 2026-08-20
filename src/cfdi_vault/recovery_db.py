"""PostgreSQL recovery and accounting schema."""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cfdi_vault.db import Base, ensure_tables_exist


class Tenant(Base):
    """Logical owner of SAT credentials and CFDI data."""

    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    rfc: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CredentialProfile(Base):
    """Credential custody configuration without storing raw secrets by default."""

    __tablename__ = "credential_profiles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id"), index=True, nullable=False)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    certificate_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    certificate_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    key_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    signer_endpoint: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DownloadJob(Base):
    """User or scheduler intent represented as a durable job."""

    __tablename__ = "download_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id"), index=True, nullable=False)
    rfc: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    direction: Mapped[str] = mapped_column(String(32), nullable=False)
    request_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    criteria_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "criteria_hash", name="uq_download_jobs_tenant_hash"),
        Index(
            "ix_download_jobs_tenant_status_updated",
            "tenant_id",
            "status",
            "updated_at",
        ),
    )


class SatCampaignRecord(Base):
    """Durable SAT campaign identity and execution budget."""

    __tablename__ = "sat_campaigns"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_ref: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(64), ForeignKey("tenants.id"), nullable=False)
    profile_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    commit_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    max_open_operations: Mapped[int] = mapped_column(SmallInteger, default=2, nullable=False)
    budget: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_sat_campaigns_tenant_id"),
        UniqueConstraint("id", "profile_ref", "manifest_sha256", "commit_ref", name="uq_sat_campaigns_identity"),
    )


class SatCampaignWindowRecord(Base):
    """A bounded SAT campaign window, including one permitted split."""

    __tablename__ = "sat_campaign_windows"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_id: Mapped[int] = mapped_column(Integer, ForeignKey("sat_campaigns.id"), nullable=False)
    work_ref: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    parent_window_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("sat_campaign_windows.id"), nullable=True
    )
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    start_date: Mapped[date] = mapped_column(Date, nullable=False)
    end_date: Mapped[date] = mapped_column(Date, nullable=False)
    split_depth: Mapped[int] = mapped_column(SmallInteger, default=0, nullable=False)
    recovery_ref: Mapped[str | None] = mapped_column(String(96), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("campaign_id", "direction", "start_date", "end_date", name="uq_sat_campaign_windows_period"),
        UniqueConstraint("campaign_id", "id", name="uq_sat_campaign_windows_campaign_id"),
        ForeignKeyConstraint(
            ["campaign_id", "parent_window_id"],
            ["sat_campaign_windows.campaign_id", "sat_campaign_windows.id"],
            name="fk_sat_campaign_windows_parent_campaign",
        ),
        CheckConstraint("split_depth = 0 OR parent_window_id IS NOT NULL",
                        name="ck_sat_campaign_windows_split_parent"),
        Index("ix_sat_campaign_windows_campaign_status_date", "campaign_id", "status", "start_date"),
    )


class SatGrantRecord(Base):
    """One exact authorization grant bound to a campaign revision."""

    __tablename__ = "sat_grants"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_id: Mapped[int] = mapped_column(Integer, ForeignKey("sat_campaigns.id"), nullable=False)
    grant_ref: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    commit_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    profile_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    budget: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("campaign_id", "grant_ref", name="uq_sat_grants_campaign_ref"),
        ForeignKeyConstraint(
            ["campaign_id", "profile_ref", "manifest_sha256", "commit_ref"],
            ["sat_campaigns.id", "sat_campaigns.profile_ref", "sat_campaigns.manifest_sha256", "sat_campaigns.commit_ref"],
            name="fk_sat_grants_campaign_identity",
        ),
        Index("ix_sat_grants_campaign_expires", "campaign_id", "expires_at"),
    )


class SatRequestRecord(Base):
    """Lifecycle of a SAT request."""

    __tablename__ = "sat_requests"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    job_id: Mapped[str | None] = mapped_column(String(64), ForeignKey("download_jobs.id"), nullable=True)
    id_solicitud: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    criteria_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    direction: Mapped[str] = mapped_column(String(32), nullable=False)
    request_type: Mapped[str] = mapped_column(String(32), nullable=False)
    sat_state: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    sat_code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    sat_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_storage_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    raw_response: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)
    campaign_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("sat_campaigns.id"), nullable=True)
    window_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("sat_campaign_windows.id"), nullable=True)
    work_ref: Mapped[str | None] = mapped_column(String(96), nullable=True)
    recovery_ref: Mapped[str | None] = mapped_column(String(96), nullable=True)
    grant_ref: Mapped[str | None] = mapped_column(String(96), nullable=True)
    next_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    service_window_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verify_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(64), default="submitted", nullable=False)
    response_summary: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "campaign_id"],
            ["sat_campaigns.tenant_id", "sat_campaigns.id"],
            name="fk_sat_requests_campaign_tenant",
        ),
        UniqueConstraint("campaign_id", "work_ref", "request_type", name="uq_sat_requests_campaign_work_type"),
        UniqueConstraint("campaign_id", "id", name="uq_sat_requests_campaign_id"),
        ForeignKeyConstraint(
            ["campaign_id", "window_id"],
            ["sat_campaign_windows.campaign_id", "sat_campaign_windows.id"],
            name="fk_sat_requests_campaign_window",
        ),
        ForeignKeyConstraint(
            ["campaign_id", "grant_ref"],
            ["sat_grants.campaign_id", "sat_grants.grant_ref"],
            name="fk_sat_requests_campaign_grant",
        ),
        Index("ix_sat_requests_campaign_status", "campaign_id", "status"),
        Index("ix_sat_requests_due_verify", "status", "next_check_at", postgresql_where=text("next_check_at IS NOT NULL")),
        Index(
            "ix_sat_requests_service_window",
            "status",
            "service_window_expires_at",
            postgresql_where=text("service_window_expires_at IS NOT NULL"),
        ),
    )


class SatPackageRecord(Base):
    """Lifecycle of a SAT package returned from verification."""

    __tablename__ = "sat_packages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    id_paquete: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    id_solicitud: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sha256_zip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    storage_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    downloaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    campaign_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("sat_campaigns.id"), nullable=True)
    window_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("sat_campaign_windows.id"), nullable=True)
    artifact_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("sat_artifacts.id"), nullable=True)
    claim_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("sat_claims.id"), nullable=True)
    ordinal: Mapped[int | None] = mapped_column(Integer, nullable=True)
    download_state: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    validation_status: Mapped[str] = mapped_column(String(32), default="unvalidated", nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "campaign_id"],
            ["sat_campaigns.tenant_id", "sat_campaigns.id"],
            name="fk_sat_packages_campaign_tenant",
        ),
        ForeignKeyConstraint(
            ["campaign_id", "window_id"],
            ["sat_campaign_windows.campaign_id", "sat_campaign_windows.id"],
            name="fk_sat_packages_campaign_window",
        ),
        ForeignKeyConstraint(
            ["campaign_id", "artifact_id"],
            ["sat_artifacts.campaign_id", "sat_artifacts.id"],
            name="fk_sat_packages_campaign_artifact",
        ),
        ForeignKeyConstraint(
            ["campaign_id", "claim_id"],
            ["sat_claims.campaign_id", "sat_claims.id"],
            name="fk_sat_packages_campaign_claim",
        ),
        Index("ix_sat_packages_campaign_state", "campaign_id", "download_state"),
        Index("ix_sat_packages_request_status", "id_solicitud", "status"),
    )


class SatArtifactRecord(Base):
    """External ZIP/TXT/XML artifact metadata; payload bytes stay out of PostgreSQL."""

    __tablename__ = "sat_artifacts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_id: Mapped[int] = mapped_column(Integer, ForeignKey("sat_campaigns.id"), nullable=False)
    window_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("sat_campaign_windows.id"), nullable=True)
    artifact_scope: Mapped[str] = mapped_column(String(16), default="window", nullable=False)
    artifact_ref: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    validation_status: Mapped[str] = mapped_column(String(32), nullable=False)
    counts: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("campaign_id", "kind", "sha256", name="uq_sat_artifacts_content"),
        UniqueConstraint("campaign_id", "id", name="uq_sat_artifacts_campaign_id"),
        ForeignKeyConstraint(
            ["campaign_id", "window_id"],
            ["sat_campaign_windows.campaign_id", "sat_campaign_windows.id"],
            name="fk_sat_artifacts_campaign_window",
        ),
        Index("ix_sat_artifacts_campaign_kind", "campaign_id", "kind"),
    )


class SatClaimRecord(Base):
    """Idempotency claim reserved before an external SAT effect."""

    __tablename__ = "sat_claims"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    claim_ref: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    grant_ref: Mapped[str | None] = mapped_column(String(96), nullable=True)
    campaign_id: Mapped[int] = mapped_column(Integer, ForeignKey("sat_campaigns.id"), nullable=False)
    window_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("sat_campaign_windows.id"), nullable=True)
    request_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("sat_requests.id"), nullable=True)
    operation_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(192), nullable=False)
    operation_slot: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    worker_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    result: Mapped[str | None] = mapped_column(String(32), nullable=True)
    result_code: Mapped[str | None] = mapped_column(String(32), nullable=True)

    __table_args__ = (
        UniqueConstraint("campaign_id", "idempotency_key", name="uq_sat_claims_idempotency"),
        UniqueConstraint("campaign_id", "id", name="uq_sat_claims_campaign_id"),
        ForeignKeyConstraint(
            ["campaign_id", "window_id"],
            ["sat_campaign_windows.campaign_id", "sat_campaign_windows.id"],
            name="fk_sat_claims_campaign_window",
        ),
        ForeignKeyConstraint(
            ["campaign_id", "request_id"],
            ["sat_requests.campaign_id", "sat_requests.id"],
            name="fk_sat_claims_campaign_request",
        ),
        ForeignKeyConstraint(
            ["campaign_id", "grant_ref"],
            ["sat_grants.campaign_id", "sat_grants.grant_ref"],
            name="fk_sat_claims_campaign_grant",
        ),
        Index("ix_sat_claims_campaign_open_slot", "campaign_id", "operation_slot", unique=True, postgresql_where=text("active")),
        Index("ix_sat_claims_lease", "lease_until", postgresql_where=text("active")),
    )


class SatVerifyAttemptRecord(Base):
    """Append-only SAT VERIFY history linked to a verify claim."""

    __tablename__ = "sat_verify_attempts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_id: Mapped[int] = mapped_column(Integer, ForeignKey("sat_campaigns.id"), nullable=False)
    request_id: Mapped[int] = mapped_column(Integer, ForeignKey("sat_requests.id"), nullable=False)
    claim_id: Mapped[int] = mapped_column(Integer, ForeignKey("sat_claims.id"), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    contacted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    result_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    next_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claim_ref: Mapped[str] = mapped_column(String(96), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("request_id", "attempt", name="uq_sat_verify_attempts_number"),
        UniqueConstraint("claim_ref", name="uq_sat_verify_attempts_claim"),
        ForeignKeyConstraint(
            ["campaign_id", "request_id"],
            ["sat_requests.campaign_id", "sat_requests.id"],
            name="fk_sat_verify_attempts_campaign_request",
        ),
        ForeignKeyConstraint(
            ["campaign_id", "claim_id"],
            ["sat_claims.campaign_id", "sat_claims.id"],
            name="fk_sat_verify_attempts_campaign_claim",
        ),
        Index("ix_sat_verify_attempts_request_created", "request_id", "created_at"),
    )


class SatMonitorRunRecord(Base):
    """Append-only sanitized aggregates for one monitor wake cycle."""

    __tablename__ = "sat_monitor_runs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    run_ref: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    wake_reason: Mapped[str] = mapped_column(String(32), nullable=False)
    due_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    contacted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    package_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    no_data_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    terminal_category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    watchdog_wake: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "finished_at >= started_at", name="ck_sat_monitor_runs_time",
        ),
        CheckConstraint(
            "wake_reason IN ('startup', 'schedule_changed', 'watchdog', 'reconnect', 'manual', 'unknown')",
            name="ck_sat_monitor_runs_reason",
        ),
        CheckConstraint(
            "due_count >= 0 AND contacted_count >= 0 AND package_count >= 0 "
            "AND no_data_count >= 0 AND error_count >= 0 AND duration_ms >= 0",
            name="ck_sat_monitor_runs_counts",
        ),
        CheckConstraint(
            "terminal_category IS NULL OR terminal_category ~ '^[a-z][a-z0-9._-]{0,31}$'",
            name="ck_sat_monitor_runs_terminal",
        ),
        Index("ix_sat_monitor_runs_started_at", "started_at", "id"),
    )


class SatCampaignRunRecord(Base):
    """Durable request for one bounded campaign run (ADR 0005).

    The row is the work item; the ``sat.campaign.run`` queue message is only a
    wake hint. A terminal row is never re-run automatically: an expired lease
    becomes ``abandoned`` and a new run needs a new human request.
    """

    __tablename__ = "sat_campaign_runs"

    run_ref: Mapped[str] = mapped_column(String(96), primary_key=True)
    campaign_id: Mapped[int] = mapped_column(Integer, ForeignKey("sat_campaigns.id"), nullable=False)
    grant_ref: Mapped[str] = mapped_column(String(96), nullable=False)
    profile_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    commit_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="queued", nullable=False)
    requested_via: Mapped[str] = mapped_column(String(16), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    worker_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    result_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    contacted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    submitted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    package_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'claimed', 'running', 'succeeded', 'failed', 'abandoned')",
            name="ck_sat_campaign_runs_status",
        ),
        CheckConstraint(
            "requested_via IN ('panel', 'cli')", name="ck_sat_campaign_runs_requested_via",
        ),
        CheckConstraint(
            "result_code IS NULL OR result_code ~ '^[a-z][a-z0-9._-]{0,63}$'",
            name="ck_sat_campaign_runs_result",
        ),
        CheckConstraint(
            "contacted_count >= 0 AND submitted_count >= 0 AND package_count >= 0",
            name="ck_sat_campaign_runs_counts",
        ),
        CheckConstraint(
            "(status IN ('succeeded', 'failed', 'abandoned')) = (finished_at IS NOT NULL)",
            name="ck_sat_campaign_runs_completion",
        ),
        Index(
            "uq_sat_campaign_runs_active", "campaign_id", "grant_ref", unique=True,
            postgresql_where=text("status IN ('queued', 'claimed', 'running')"),
        ),
        Index(
            "ix_sat_campaign_runs_queued", "requested_at", "run_ref",
            postgresql_where=text("status = 'queued'"),
        ),
        Index(
            "ix_sat_campaign_runs_lease", "lease_until",
            postgresql_where=text("status IN ('queued', 'claimed', 'running')"),
        ),
        Index("ix_sat_campaign_runs_campaign_requested", "campaign_id", "requested_at", "run_ref"),
    )


class SatMetadataImportRecord(Base):
    """Sanitized structural and aggregate results for one metadata TXT import."""

    __tablename__ = "sat_metadata_imports"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    campaign_id: Mapped[int] = mapped_column(Integer, ForeignKey("sat_campaigns.id"), nullable=False)
    window_id: Mapped[int] = mapped_column(Integer, ForeignKey("sat_campaign_windows.id"), nullable=False)
    artifact_id: Mapped[int] = mapped_column(Integer, ForeignKey("sat_artifacts.id"), nullable=False)
    encoding: Mapped[str] = mapped_column(String(32), nullable=False)
    delimiter: Mapped[str] = mapped_column(String(4), nullable=False)
    header_compatible: Mapped[bool] = mapped_column(Boolean, nullable=False)
    record_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    eligible_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    cancelled_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    duplicate_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    conflict_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    unknown_count: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["campaign_id", "window_id"],
            ["sat_campaign_windows.campaign_id", "sat_campaign_windows.id"],
            name="fk_sat_metadata_imports_campaign_window",
        ),
        ForeignKeyConstraint(
            ["campaign_id", "artifact_id"],
            ["sat_artifacts.campaign_id", "sat_artifacts.id"],
            name="fk_sat_metadata_imports_campaign_artifact",
        ),
        Index("ix_sat_metadata_imports_window", "window_id", "created_at"),
    )


class QueueJobEvent(Base):
    """Append-only queue/job event for audit and troubleshooting."""

    __tablename__ = "queue_job_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    queue_name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (Index("ix_queue_job_events_job_created", "job_id", "created_at"),)


class SignerAudit(Base):
    """Audit trail for every signing event."""

    __tablename__ = "signer_audit"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    certificate_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    signer_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ReconciliationEvent(Base):
    """Append-only explanation for UUID reconciliation transitions."""

    __tablename__ = "reconciliation_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    uuid: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    previous_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    new_state: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class CfdiDocument(Base):
    """Normalized accounting header for a CFDI."""

    __tablename__ = "cfdi_documents"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    uuid: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    document_type: Mapped[str | None] = mapped_column(String(8), index=True, nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    issue_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True, nullable=True)
    certified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    currency: Mapped[str | None] = mapped_column(String(8), nullable=True)
    subtotal: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    discount: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    total: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), index=True, nullable=True)
    issuer_rfc: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    issuer_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    receiver_rfc: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    receiver_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    payment_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    payment_form: Mapped[str | None] = mapped_column(String(16), nullable=True)
    download_state: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    xml_sha256: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    parser_status: Mapped[str] = mapped_column(String(32), default="complete", nullable=False)
    search_text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "uuid", name="uq_cfdi_documents_tenant_uuid"),
        Index("ix_cfdi_documents_tenant_issue_date", "tenant_id", "issue_date"),
        Index(
            "ix_cfdi_documents_tenant_parser_updated",
            "tenant_id",
            "parser_status",
            "updated_at",
        ),
    )

    concepts: Mapped[list["CfdiConcept"]] = relationship(back_populates="document")


class CfdiParty(Base):
    """Party index for issuer/receiver search."""

    __tablename__ = "cfdi_parties"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    rfc: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    document_uuid: Mapped[str] = mapped_column(String(64), index=True, nullable=False)


class CfdiConcept(Base):
    """Line item/concept extracted from CFDI XML."""

    __tablename__ = "cfdi_concepts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("cfdi_documents.id"), index=True, nullable=False)
    product_service_key: Mapped[str | None] = mapped_column(String(32), nullable=True)
    unit_key: Mapped[str | None] = mapped_column(String(32), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    quantity: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    unit_value: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    amount: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    discount: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    tax_object: Mapped[str | None] = mapped_column(String(16), nullable=True)
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)

    document: Mapped[CfdiDocument] = relationship(back_populates="concepts")


class CfdiTax(Base):
    """Tax line extracted from document or concept level."""

    __tablename__ = "cfdi_taxes"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    document_uuid: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    concept_id: Mapped[int | None] = mapped_column(ForeignKey("cfdi_concepts.id"), nullable=True)
    tax_type: Mapped[str] = mapped_column(String(16), nullable=False)
    tax: Mapped[str | None] = mapped_column(String(16), nullable=True)
    factor_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    rate_or_quota: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    base: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    amount: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)


class CfdiPayment(Base):
    """Payment complement data."""

    __tablename__ = "cfdi_payments"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    document_uuid: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    payment_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payment_form: Mapped[str | None] = mapped_column(String(16), nullable=True)
    currency: Mapped[str | None] = mapped_column(String(8), nullable=True)
    amount: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)


class CfdiPayroll(Base):
    """Payroll complement data."""

    __tablename__ = "cfdi_payroll"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    document_uuid: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    employee_curp: Mapped[str | None] = mapped_column(String(32), nullable=True)
    employee_number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payroll_type: Mapped[str | None] = mapped_column(String(16), nullable=True)
    payment_start_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payment_end_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)


class CfdiRelatedDocument(Base):
    """Related CFDI UUIDs."""

    __tablename__ = "cfdi_related_documents"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    document_uuid: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    related_uuid: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    relation_type: Mapped[str | None] = mapped_column(String(16), nullable=True)


class CfdiMetadataLedger(Base):
    """Metadata-led control plane for expected documents."""

    __tablename__ = "cfdi_metadata_ledger"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    uuid: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    direction: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    issuer_rfc: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    issuer_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    receiver_rfc: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    receiver_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    issue_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True, nullable=True)
    total: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    status: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)
    effect: Mapped[str | None] = mapped_column(String(16), nullable=True)
    reconciliation_state: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    source_package_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    source_metadata_sha256: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict, nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "uuid", "direction", name="uq_metadata_ledger_uuid_direction"),
        Index(
            "ix_cfdi_metadata_ledger_tenant_reconciliation_last_seen",
            "tenant_id",
            "reconciliation_state",
            "last_seen_at",
        ),
    )


class XmlEvidence(Base):
    """Stored XML evidence and file fingerprints."""

    __tablename__ = "xml_evidence"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    uuid: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    source_package_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    xml_sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    parser_version: Mapped[str] = mapped_column(String(32), nullable=False)
    parser_status: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "uuid", "xml_sha256", name="uq_xml_evidence_hash"),
        Index("ix_xml_evidence_tenant_storage_key", "tenant_id", "storage_key"),
        Index("ix_xml_evidence_tenant_sha256", "tenant_id", "xml_sha256"),
        Index(
            "ix_xml_evidence_tenant_parser_created",
            "tenant_id",
            "parser_status",
            "created_at",
        ),
    )


def init_recovery_schema(engine: Engine) -> None:
    """Validate that Flyway has created all recovery tables."""

    ensure_tables_exist(engine, Base.metadata.tables)
