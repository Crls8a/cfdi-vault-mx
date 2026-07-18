from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

import cfdi_vault.recovery_db  # noqa: F401
from cfdi_vault.db import Base, create_engine_from_url, init_db
from cfdi_vault.recovery_db import init_recovery_schema


def test_postgres_fixture_runner_discovers_all_migrations_in_version_order(
    tmp_path: Path,
    migration_paths: Callable[[Path], tuple[Path, ...]],
) -> None:
    for filename in (
        "V10__later.sql",
        "V2__evidence_indexes.sql",
        "V1__baseline.sql",
        "README.md",
    ):
        (tmp_path / filename).write_text("-- synthetic migration", encoding="utf-8")

    assert [path.name for path in migration_paths(tmp_path)] == [
        "V1__baseline.sql",
        "V2__evidence_indexes.sql",
        "V10__later.sql",
    ]


def test_flyway_migrations_declare_all_orm_tables_and_indexes(
    migration_paths: Callable[[Path], tuple[Path, ...]],
) -> None:
    migrations = migration_paths(Path("db/migration"))
    all_migrations = "\n".join(path.read_text(encoding="utf-8") for path in migrations)

    for table_name in Base.metadata.tables:
        assert re.search(rf"\bCREATE TABLE {re.escape(table_name)}\b", all_migrations), table_name

    for table in Base.metadata.tables.values():
        for index in table.indexes:
            assert re.search(rf"\bINDEX {re.escape(index.name or '')}\b", all_migrations), index.name


def test_initial_flyway_migration_uses_postgresql_jsonb_payloads() -> None:
    migration = Path("db/migration/V1__initial_postgresql_schema.sql").read_text(encoding="utf-8")

    assert "raw_payload JSONB NOT NULL" in migration
    assert "payload JSONB NOT NULL" in migration
    assert "raw_response JSONB NOT NULL" in migration


def test_evidence_index_migration_is_additive_and_query_driven() -> None:
    migration = Path("db/migration/V2__evidence_query_indexes.sql").read_text(
        encoding="utf-8"
    )
    executable_sql = "\n".join(
        line for line in migration.splitlines() if not line.strip().startswith("--")
    )
    expected_indexes = {
        "ix_xml_evidence_tenant_storage_key",
        "ix_xml_evidence_tenant_sha256",
        "ix_xml_evidence_tenant_parser_created",
        "ix_cfdi_documents_tenant_parser_updated",
        "ix_cfdi_metadata_ledger_tenant_reconciliation_last_seen",
        "ix_download_jobs_tenant_status_updated",
        "ix_queue_job_events_job_created",
    }

    for index_name in expected_indexes:
        assert f"CREATE INDEX {index_name}" in migration
    assert "DROP " not in executable_sql.upper()
    assert "ALTER TABLE" not in executable_sql.upper()
    assert "BYTEA" not in executable_sql.upper()


def test_sat_campaign_migration_declares_durable_state_and_safety_guards() -> None:
    migration = Path("db/migration/V3__sat_campaign_state.sql").read_text(
        encoding="utf-8"
    )

    for table_name in (
        "sat_campaigns",
        "sat_campaign_windows",
        "sat_grants",
        "sat_verify_attempts",
        "sat_claims",
        "sat_artifacts",
        "sat_metadata_imports",
    ):
        assert f"CREATE TABLE {table_name}" in migration

    assert "ALTER TABLE sat_requests" in migration
    assert "ALTER TABLE sat_packages" in migration
    assert "response_summary JSONB" in migration
    assert "raw_response" in migration
    assert "sat_verify_attempts_append_only" in migration
    assert "FOR EACH ROW" in migration
    assert "operation_slot" in migration
    assert "active BOOLEAN NOT NULL DEFAULT TRUE" in migration
    assert "WHERE active" in migration
    assert "lease_expired" in migration
    assert "UNIQUE INDEX ix_sat_claims_campaign_open_slot" in migration
    assert "next_check_at" in migration
    assert "service_window_expires_at" in migration
    assert "storage_key" in migration
    assert "FOREIGN KEY (campaign_id, parent_window_id)" in migration
    assert "FOREIGN KEY (campaign_id, window_id)" in migration
    assert "FOREIGN KEY (campaign_id, artifact_id)" in migration
    assert "FOREIGN KEY (campaign_id, profile_ref, manifest_sha256, commit_ref)" in migration
    assert "ck_sat_requests_campaign_window_pair" in migration
    assert "ck_sat_requests_work_ref_when_linked" in migration
    assert "ck_sat_packages_campaign_artifact_pair" in migration
    assert "ck_sat_packages_campaign_claim_pair" in migration
    assert "download_state IN ('pending', 'downloaded', 'download_uncertain', 'download_failed')" in migration
    assert "validation_status IN ('unvalidated', 'valid', 'invalid')" in migration
    assert "claim_operation_kind <> 'verify'" in migration
    assert "claim_request_id <> NEW.request_id" in migration
    assert "claim_active IS NOT TRUE" in migration
    assert "ck_sat_claims_request_for_non_submit" in migration
    assert "artifact_scope VARCHAR(16)" in migration
    assert "ck_sat_artifacts_scope" in migration
    assert "end_date - start_date + 1 IN (7, 14)" in migration
    assert "TRUNCATE" in migration


def test_sat_campaign_migration_does_not_store_payload_bytes_or_secrets() -> None:
    migration = Path("db/migration/V3__sat_campaign_state.sql").read_text(
        encoding="utf-8"
    ).upper()

    assert "BYTEA" not in migration
    assert "PASSWORD" not in migration
    assert "PRIVATE KEY" not in migration
    assert "SOAP" not in migration


def test_sat_campaign_migration_enforces_tenant_campaign_isolation() -> None:
    migration = Path("db/migration/V3__sat_campaign_state.sql").read_text(encoding="utf-8")
    normalized = re.sub(r"\s+", " ", migration)

    assert "CONSTRAINT uq_sat_campaigns_tenant_id UNIQUE (tenant_id, id)" in normalized
    assert (
        "FOREIGN KEY (tenant_id, campaign_id) REFERENCES sat_campaigns (tenant_id, id)"
        in normalized
    )
    assert "CREATE INDEX ix_sat_packages_request_status ON sat_packages (id_solicitud, status)" in normalized


@pytest.mark.integration
def test_sat_v3_postgres_schema_and_campaign_isolation(reset_postgres_database: str) -> None:
    engine = create_engine_from_url(reset_postgres_database)
    try:
        database_inspector = inspect(engine)
        table_names = set(database_inspector.get_table_names())
        assert {
            "sat_campaigns",
            "sat_campaign_windows",
            "sat_grants",
            "sat_verify_attempts",
            "sat_claims",
            "sat_artifacts",
            "sat_metadata_imports",
        }.issubset(table_names)
        assert {"campaign_id", "window_id", "response_summary"}.issubset(
            {column["name"] for column in database_inspector.get_columns("sat_requests")}
        )
        assert {"campaign_id", "artifact_id", "download_state"}.issubset(
            {column["name"] for column in database_inspector.get_columns("sat_packages")}
        )

        with engine.begin() as connection:
            indexes = {
                row[0]
                for row in connection.execute(
                    text(
                        "SELECT indexname FROM pg_indexes "
                        "WHERE schemaname = 'public' AND indexname LIKE 'ix_sat_%'"
                    )
                )
            }
            assert "ix_sat_claims_campaign_open_slot" in indexes
            assert "ix_sat_requests_due_verify" in indexes
            triggers = {
                row[0]
                for row in connection.execute(
                    text(
                        "SELECT tgname FROM pg_trigger "
                        "WHERE tgrelid = 'sat_verify_attempts'::regclass "
                        "AND NOT tgisinternal"
                    )
                )
            }
            assert {
                "sat_verify_attempts_append_only",
                "sat_verify_attempts_validate_claim",
            }.issubset(triggers)

            now = datetime.now(timezone.utc)
            for suffix in ("a", "b"):
                connection.execute(
                    text(
                        "INSERT INTO tenants (id, name, rfc, created_at) "
                        "VALUES (:tenant, :name, :rfc, :created_at)"
                    ),
                    {
                        "tenant": f"sat-db-{suffix}",
                        "name": "Synthetic Tenant",
                        "rfc": f"SYNTEST{suffix.upper()}",
                        "created_at": now,
                    },
                )
                connection.execute(
                    text(
                        "INSERT INTO sat_campaigns "
                        "(campaign_ref, tenant_id, profile_ref, manifest_sha256, commit_ref, "
                        "phase, status, budget, created_at, updated_at) "
                        "VALUES (:campaign_ref, :tenant, :profile, :digest, :commit, "
                        "'metadata-proof', 'planned', 1, :created_at, :created_at)"
                    ),
                    {
                        "campaign_ref": f"campaign-{suffix}",
                        "tenant": f"sat-db-{suffix}",
                        "profile": f"profile-{suffix}",
                        "digest": "a" * 64,
                        "commit": f"commit-{suffix}",
                        "created_at": now,
                    },
                )

            campaign_ids = dict(
                connection.execute(
                    text("SELECT campaign_ref, id FROM sat_campaigns ORDER BY campaign_ref")
                ).all()
            )
            window_id = connection.execute(
                text(
                    "INSERT INTO sat_campaign_windows "
                    "(campaign_id, work_ref, direction, start_date, end_date, status, created_at, updated_at) "
                    "VALUES (:campaign_id, 'work-a', 'received', '2026-01-01', '2026-01-14', "
                    "'planned', :created_at, :created_at) RETURNING id"
                ),
                {"campaign_id": campaign_ids["campaign-a"], "created_at": now},
            ).scalar_one()
            window_b_id = connection.execute(
                text(
                    "INSERT INTO sat_campaign_windows "
                    "(campaign_id, work_ref, direction, start_date, end_date, status, created_at, updated_at) "
                    "VALUES (:campaign_id, 'work-b', 'received', '2026-01-01', '2026-01-14', "
                    "'planned', :created_at, :created_at) RETURNING id"
                ),
                {"campaign_id": campaign_ids["campaign-b"], "created_at": now},
            ).scalar_one()
            artifact_a_id = connection.execute(
                text(
                    "INSERT INTO sat_artifacts "
                    "(campaign_id, window_id, artifact_ref, kind, storage_key, sha256, size_bytes, "
                    "validation_status, created_at) "
                    "VALUES (:campaign_id, :window_id, 'artifact-a', 'metadata_txt', 'opaque/a', :sha256, "
                    "1, 'valid', :created_at) RETURNING id"
                ),
                {
                    "campaign_id": campaign_ids["campaign-a"],
                    "window_id": window_id,
                    "sha256": "b" * 64,
                    "created_at": now,
                },
            ).scalar_one()
            claim_a_id = connection.execute(
                text(
                    "INSERT INTO sat_claims "
                    "(claim_ref, campaign_id, operation_kind, idempotency_key, operation_slot, "
                    "worker_ref, claimed_at, lease_until) "
                    "VALUES ('claim-a', :campaign_id, 'submit', 'idempotency-a', 1, 'worker-a', "
                    ":created_at, :created_at) RETURNING id"
                ),
                {"campaign_id": campaign_ids["campaign-a"], "created_at": now},
            ).scalar_one()

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO sat_campaign_windows "
                        "(campaign_id, work_ref, parent_window_id, direction, start_date, end_date, "
                        "split_depth, status, created_at, updated_at) "
                        "VALUES (:campaign_id, 'work-cross-campaign', :parent_id, 'received', "
                        "'2026-01-15', '2026-01-21', 1, 'planned', :created_at, :created_at)"
                    ),
                    {
                        "campaign_id": campaign_ids["campaign-b"],
                        "parent_id": window_id,
                        "created_at": datetime.now(timezone.utc),
                    },
                )

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO sat_requests "
                        "(tenant_id, id_solicitud, criteria_hash, direction, request_type, sat_state, "
                        "requested_at, raw_response, campaign_id, window_id, work_ref, status) "
                        "VALUES ('sat-db-b', 'request-cross-tenant', :criteria_hash, 'received', 'Metadata', "
                        "'pending', :created_at, '{}'::jsonb, :campaign_id, :window_id, 'work-request-cross', "
                        "'submitted')"
                    ),
                    {
                        "criteria_hash": "c" * 64,
                        "created_at": now,
                        "campaign_id": campaign_ids["campaign-a"],
                        "window_id": window_id,
                    },
                )

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO sat_packages "
                        "(tenant_id, id_paquete, id_solicitud, status, attempts, last_error, created_at, "
                        "updated_at, campaign_id, window_id, artifact_id, claim_id) "
                        "VALUES ('sat-db-b', 'package-cross-tenant', 'request-cross-tenant', 'pending', 0, "
                        "'{}'::jsonb, :created_at, :created_at, :campaign_id, :window_id, :artifact_id, :claim_id)"
                    ),
                    {
                        "created_at": now,
                        "campaign_id": campaign_ids["campaign-a"],
                        "window_id": window_id,
                        "artifact_id": artifact_a_id,
                        "claim_id": claim_a_id,
                    },
                )

        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "INSERT INTO sat_metadata_imports "
                        "(campaign_id, window_id, artifact_id, encoding, delimiter, header_compatible, created_at) "
                        "VALUES (:campaign_id, :window_id, :artifact_id, 'utf-8-sig', '~', TRUE, :created_at)"
                    ),
                    {
                        "campaign_id": campaign_ids["campaign-b"],
                        "window_id": window_b_id,
                        "artifact_id": artifact_a_id,
                        "created_at": datetime.now(timezone.utc),
                    },
                )
    finally:
        engine.dispose()


@pytest.mark.integration
def test_flyway_baseline_satisfies_runtime_schema_validation(reset_postgres_database: str) -> None:
    engine = create_engine_from_url(reset_postgres_database)
    try:
        init_db(engine)
        init_recovery_schema(engine)
    finally:
        engine.dispose()


@pytest.mark.integration
def test_runtime_schema_validation_does_not_bootstrap_empty_database(reset_postgres_database: str) -> None:
    engine = create_engine_from_url(reset_postgres_database)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
            connection.exec_driver_sql("CREATE SCHEMA public")

        with pytest.raises(RuntimeError, match="Run Flyway migrations"):
            init_db(engine)
        with pytest.raises(RuntimeError, match="Run Flyway migrations"):
            init_recovery_schema(engine)

        assert inspect(engine).get_table_names() == []
    finally:
        engine.dispose()
