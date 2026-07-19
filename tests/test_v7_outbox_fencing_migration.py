from __future__ import annotations

import re
from pathlib import Path

MIGRATION = Path("db/migration/V7__ledger_outbox_fencing.sql")


def _sql() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_v7_is_additive_and_documents_manual_rollback() -> None:
    migration = _sql()
    executable = "\n".join(line for line in migration.splitlines() if not line.lstrip().startswith("--"))
    assert "ALTER TABLE ledger_outbox" in executable
    assert "ADD COLUMN claim_id VARCHAR(96)" in executable
    assert "ADD COLUMN claimed_by VARCHAR(128)" in executable
    assert "DROP TABLE" not in executable
    assert "DROP COLUMN" not in executable
    assert "Manual rollback only" in migration
    assert not re.search(r"(?m)^[^\-\s].*\bDROP\b", migration, re.I)


def test_v7_requires_claim_token_and_worker_for_claimed_rows() -> None:
    normalized = re.sub(r"\s+", " ", _sql())
    assert "UNIQUE (claim_id)" in normalized
    assert "ck_ledger_outbox_claim_fields" in normalized
    assert "status = 'claimed' AND claim_id IS NOT NULL AND claimed_by IS NOT NULL" in normalized
    assert "status <> 'claimed' AND claim_id IS NULL AND claimed_by IS NULL" in normalized
    assert "NOT VALID" in normalized
