from __future__ import annotations

import re
from pathlib import Path

MIGRATION = Path("db/migration/V6__ledger_jobs_outbox.sql")
PREVIOUS = tuple(Path("db/migration").glob("V[1-5]__*.sql"))


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def _normalized_sql() -> str:
    return re.sub(r"\s+", " ", _sql())


def _executable_sql() -> str:
    return "\n".join(line for line in _sql().splitlines() if not line.lstrip().startswith("--"))


def test_v6_is_additive_and_previous_migrations_are_unchanged() -> None:
    executable = _executable_sql().upper()
    assert "CREATE TABLE LEDGER_JOBS" in executable
    assert "CREATE TABLE LEDGER_JOB_CLAIMS" in executable
    assert "CREATE TABLE LEDGER_OUTBOX" in executable
    assert "CREATE TABLE LEDGER_INBOX" in executable
    assert "ALTER TABLE" not in executable
    assert "DROP TABLE" not in executable
    assert "DROP COLUMN" not in executable
    assert "TRUNCATE" not in executable
    assert "DELETE FROM" not in executable
    assert all(
        not re.search(r"ledger_(jobs|job_claims|outbox|inbox)", path.read_text(encoding="utf-8"), re.I)
        for path in PREVIOUS
    )


def test_v6_documents_manual_rollback_without_executing_it() -> None:
    migration = _sql()
    assert "Manual rollback only" in migration
    assert "Reverse order" in migration
    assert "DROP TABLE ledger_inbox" in migration
    assert "DROP TABLE ledger_jobs" in migration
    assert "DROP TRIGGER ledger_job_claims_append_only" in migration
    assert "DROP FUNCTION ledger_aggregate_counts_valid" in migration
    assert not re.search(r"(?m)^[^\-\s].*\bDROP\b", migration, re.I)


def test_v6_jobs_have_durable_identity_status_and_aggregate_only_result() -> None:
    normalized = _normalized_sql()
    assert "UNIQUE (tenant_id, job_type, idempotency_key)" in normalized
    assert re.search(
        r"status IN \(\s*'queued', 'claimed', 'running', 'succeeded', 'duplicate', 'failed', 'uncertain', 'dead_letter'",
        normalized,
    )
    assert "ledger_aggregate_counts_valid(aggregate_counts)" in normalized
    assert "last_error_code ~ '^[a-z][a-z0-9_]{0,63}$'" in normalized
    assert "completed_at IS NOT NULL" in normalized
    assert "FOREIGN KEY (tenant_id) REFERENCES tenants (id)" in normalized


def test_v6_job_completion_check_requires_exact_nullability() -> None:
    normalized = _normalized_sql()
    completion = normalized.split("CONSTRAINT ck_ledger_jobs_completion", 1)[1].split(");", 1)[0]
    assert (
        "status IN ('succeeded', 'duplicate', 'failed', 'uncertain', 'dead_letter') AND completed_at IS NOT NULL"
        in completion
    )
    assert (
        "status NOT IN ('succeeded', 'duplicate', 'failed', 'uncertain', 'dead_letter') AND completed_at IS NULL"
        in completion
    )


def test_v6_claims_are_leased_unique_and_append_only() -> None:
    normalized = _normalized_sql()
    assert "UNIQUE (job_id, attempt)" in normalized
    assert "CREATE UNIQUE INDEX uq_ledger_job_claims_active" in normalized
    assert "WHERE completed_at IS NULL" in normalized
    assert "ledger_job_claims_append_only" in normalized
    assert "BEFORE UPDATE OR DELETE ON ledger_job_claims" in normalized
    assert "lease_until > claimed_at" in normalized
    assert "OLD.completed_at IS NOT NULL" in normalized


def test_v6_outbox_and_inbox_enforce_durable_dedupe() -> None:
    normalized = _normalized_sql()
    assert "UNIQUE (job_id, event_type)" in normalized
    assert "UNIQUE (job_id, idempotency_key)" in normalized
    assert "PRIMARY KEY (event_id, consumer_name)" in normalized
    assert "CREATE INDEX ix_ledger_outbox_pending" in normalized
    assert "CREATE INDEX ix_ledger_outbox_lease" in normalized
    assert "CREATE INDEX ix_ledger_inbox_unprocessed" in normalized
    assert "status IN ('queued', 'claimed', 'published', 'failed', 'uncertain')" in normalized
    assert "status <> 'claimed' OR lease_until IS NOT NULL" in normalized
    assert "status <> 'published' OR published_at IS NOT NULL" in normalized


def test_v6_contains_no_source_content_columns_or_secret_terms() -> None:
    migration = _sql().upper()
    assert "BYTEA" not in migration
    assert "RAW_PAYLOAD" not in migration
    assert "SOAP" not in migration
    assert "XML" not in migration
    assert "ZIP" not in migration
    assert "TXT" not in migration
    assert "RFC" not in migration
    assert "UUID" not in migration
    assert "PASSWORD" not in migration
    assert "PRIVATE KEY" not in migration
    assert "JSONB" in migration
    assert "AGGREGATE_COUNTS JSONB" in migration


def test_v6_indexes_cover_due_leases_and_unprocessed_queries() -> None:
    normalized = _normalized_sql()
    assert "ON LEDGER_JOBS (STATUS, AVAILABLE_AT)" in normalized.upper()
    assert "ON LEDGER_JOB_CLAIMS (LEASE_UNTIL)" in normalized.upper()
    assert "ON LEDGER_OUTBOX (STATUS, AVAILABLE_AT)" in normalized.upper()
    assert "ON LEDGER_OUTBOX (LEASE_UNTIL)" in normalized.upper()
    assert "ON LEDGER_INBOX (CONSUMER_NAME, RECEIVED_AT)" in normalized.upper()
    assert "FOR EACH ROW" in normalized.upper()


def test_v6_transition_guard_does_not_reopen_terminal_jobs() -> None:
    normalized = _normalized_sql()
    assert "ledger_jobs_validate_transition" in normalized
    assert "OLD.STATUS IN ('SUCCEEDED', 'DUPLICATE', 'FAILED', 'UNCERTAIN', 'DEAD_LETTER')" in normalized.upper()
    assert "NEW.STATUS IS DISTINCT FROM OLD.STATUS" in normalized.upper()
    assert "NEW.AGGREGATE_COUNTS IS DISTINCT FROM OLD.AGGREGATE_COUNTS" in normalized.upper()
    assert "NEW.COMPLETED_AT IS DISTINCT FROM OLD.COMPLETED_AT" in normalized.upper()
    assert "LEDGER JOB TERMINAL STATE IS IMMUTABLE" in normalized.upper()
