from __future__ import annotations

import re
from pathlib import Path

MIGRATION = Path("db/migration/V9__sat_campaign_runs.sql")


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_v9_is_additive_and_documents_manual_rollback() -> None:
    migration = _sql()
    executable = "\n".join(line for line in migration.splitlines() if not line.lstrip().startswith("--"))
    assert "CREATE TABLE sat_campaign_runs" in executable
    assert "Manual rollback only" in migration
    assert not re.search(r"(?m)^[^\-\s].*\bDROP\b", migration, re.I)
    assert "ALTER TABLE" not in executable.upper()


def test_v9_stores_no_payload_bytes_or_credential_columns() -> None:
    migration = _sql().upper()
    assert "BYTEA" not in migration
    assert "PASSWORD" not in migration
    assert "PRIVATE KEY" not in migration
    assert "PHRASE" not in migration
    assert "SOAP" not in migration


def test_v9_constrains_the_run_lifecycle_and_completion_pairing() -> None:
    normalized = re.sub(r"\s+", " ", _sql())
    assert (
        "CONSTRAINT ck_sat_campaign_runs_status CHECK (status IN ( 'queued', 'claimed', "
        "'running', 'succeeded', 'failed', 'abandoned' ))" in normalized
    )
    assert "requested_via IN ('panel', 'cli')" in normalized
    assert "result_code IS NULL OR result_code ~ '^[a-z][a-z0-9._-]{0,63}$'" in normalized
    assert (
        "(status IN ('succeeded', 'failed', 'abandoned')) = (finished_at IS NOT NULL)" in normalized
    )
    assert "FOREIGN KEY (campaign_id) REFERENCES sat_campaigns (id)" in normalized


def test_v9_indexes_support_idempotency_claiming_and_the_reaper() -> None:
    normalized = re.sub(r"\s+", " ", _sql())
    assert (
        "CREATE UNIQUE INDEX uq_sat_campaign_runs_active ON sat_campaign_runs (campaign_id, grant_ref) "
        "WHERE status IN ('queued', 'claimed', 'running')" in normalized
    )
    assert "CREATE INDEX ix_sat_campaign_runs_queued" in normalized
    assert "WHERE status = 'queued'" in normalized
    assert "CREATE INDEX ix_sat_campaign_runs_lease ON sat_campaign_runs (lease_until)" in normalized
    assert "CREATE INDEX ix_sat_campaign_runs_campaign_requested" in normalized


def test_v9_makes_terminal_runs_immutable_like_ledger_jobs() -> None:
    migration = _sql()
    assert "CREATE FUNCTION sat_campaign_runs_validate_transition()" in migration
    assert "CREATE TRIGGER sat_campaign_runs_validate_transition" in migration
    assert "BEFORE UPDATE ON sat_campaign_runs" in migration
    assert "FOR EACH ROW" in migration
    assert "terminal state is immutable" in migration


def test_v9_documents_that_the_broker_message_is_only_a_wake_hint() -> None:
    migration = _sql()
    assert "wake hint" in migration
    assert "PostgreSQL remains the source of truth" in migration
    assert "never retried automatically" in migration
