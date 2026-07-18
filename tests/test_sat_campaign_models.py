from __future__ import annotations

from sqlalchemy import inspect

from cfdi_vault.db import Base
from cfdi_vault.recovery_db import (
    SatArtifactRecord,
    SatCampaignRecord,
    SatCampaignWindowRecord,
    SatClaimRecord,
    SatGrantRecord,
    SatMetadataImportRecord,
    SatPackageRecord,
    SatRequestRecord,
    SatVerifyAttemptRecord,
)


def test_campaign_models_register_every_v3_table() -> None:
    assert {
        "sat_campaigns",
        "sat_campaign_windows",
        "sat_grants",
        "sat_claims",
        "sat_verify_attempts",
        "sat_artifacts",
        "sat_metadata_imports",
    }.issubset(Base.metadata.tables)


def test_request_and_package_models_include_v3_columns_without_replacing_legacy_payload() -> None:
    request_columns = set(inspect(SatRequestRecord).columns.keys())
    package_columns = set(inspect(SatPackageRecord).columns.keys())

    assert {
        "campaign_id",
        "window_id",
        "work_ref",
        "recovery_ref",
        "next_check_at",
        "service_window_expires_at",
        "verify_attempts",
        "status",
        "response_summary",
        "raw_response",
    }.issubset(request_columns)
    assert {
        "campaign_id",
        "window_id",
        "artifact_id",
        "claim_id",
        "ordinal",
        "download_state",
        "validation_status",
    }.issubset(package_columns)


def test_v3_models_expose_migration_index_names() -> None:
    expected = {
        "ix_sat_campaign_windows_campaign_status_date",
        "ix_sat_grants_campaign_expires",
        "ix_sat_claims_campaign_open_slot",
        "ix_sat_claims_lease",
        "ix_sat_verify_attempts_request_created",
        "ix_sat_artifacts_campaign_kind",
        "ix_sat_metadata_imports_window",
        "ix_sat_packages_campaign_state",
        "ix_sat_packages_request_status",
        "ix_sat_requests_campaign_status",
        "ix_sat_requests_due_verify",
        "ix_sat_requests_service_window",
    }
    actual = {
        index.name
        for table in Base.metadata.tables.values()
        for index in table.indexes
        if index.name in expected
    }
    assert actual == expected


def test_v3_model_classes_map_to_expected_tables() -> None:
    assert SatCampaignRecord.__tablename__ == "sat_campaigns"
    assert SatCampaignWindowRecord.__tablename__ == "sat_campaign_windows"
    assert SatGrantRecord.__tablename__ == "sat_grants"
    assert SatClaimRecord.__tablename__ == "sat_claims"
    assert SatVerifyAttemptRecord.__tablename__ == "sat_verify_attempts"
    assert SatArtifactRecord.__tablename__ == "sat_artifacts"
    assert SatMetadataImportRecord.__tablename__ == "sat_metadata_imports"


def test_request_and_package_models_bind_tenant_to_campaign() -> None:
    request_constraints = {constraint.name for constraint in SatRequestRecord.__table__.constraints}
    package_constraints = {constraint.name for constraint in SatPackageRecord.__table__.constraints}

    assert "fk_sat_requests_campaign_tenant" in request_constraints
    assert "fk_sat_packages_campaign_tenant" in package_constraints
