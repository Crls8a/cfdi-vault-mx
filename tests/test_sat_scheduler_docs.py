from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_scheduler_docs_are_review_only_and_cross_platform() -> None:
    scheduler = (ROOT / "docs/sat-download/async-verify-scheduler.md").read_text(encoding="utf-8")
    runbook = (ROOT / "docs/runbooks/sat-campaign.md").read_text(encoding="utf-8")

    assert "Register-ScheduledTask" in scheduler
    assert "*/5 * * * *" in scheduler
    assert "SAT_MONITOR_ADAPTIVE_ENABLED=0" in scheduler
    assert "does not install or activate" in scheduler
    assert "No task is registered by Compose or by the CLI" in runbook
    assert "C:\\Users\\" not in scheduler + runbook


def test_compose_autostart_runbook_documents_restart_boundary() -> None:
    runbook = (ROOT / "docs/runbooks/compose-autostart.md").read_text(encoding="utf-8")
    normalized = " ".join(runbook.split())

    assert "PM2 is not used" in normalized
    assert "restart: unless-stopped" in runbook
    assert "sat-monitor" in runbook
    assert "docker compose up -d postgres rabbitmq redis worker" in runbook
    assert "LEDGER_OUTBOX_ENABLED = '1'" in runbook
    assert "docker compose down --volumes" in runbook
    assert "C:\\Users\\" not in runbook
