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
