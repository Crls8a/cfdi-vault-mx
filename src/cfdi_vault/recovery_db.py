"""PostgreSQL-ready recovery and accounting schema.

The models use SQLAlchemy portable types so the same schema can be exercised
with SQLite in tests while remaining compatible with PostgreSQL JSONB-oriented
deployments.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, Numeric, String, Text, UniqueConstraint
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cfdi_vault.db import Base


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
    payload: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (UniqueConstraint("tenant_id", "criteria_hash", name="uq_download_jobs_tenant_hash"),)


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
    raw_response: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)


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
    last_error: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


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
    payload: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


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
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("tenant_id", "uuid", name="uq_cfdi_documents_tenant_uuid"),
        Index("ix_cfdi_documents_tenant_issue_date", "tenant_id", "issue_date"),
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
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)

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
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)


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
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)


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
    raw_payload: Mapped[dict[str, object]] = mapped_column(JSON, default=dict, nullable=False)

    __table_args__ = (UniqueConstraint("tenant_id", "uuid", "direction", name="uq_metadata_ledger_uuid_direction"),)


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

    __table_args__ = (UniqueConstraint("tenant_id", "uuid", "xml_sha256", name="uq_xml_evidence_hash"),)


def init_recovery_schema(engine: Engine) -> None:
    """Create all recovery tables."""

    Base.metadata.create_all(engine)
