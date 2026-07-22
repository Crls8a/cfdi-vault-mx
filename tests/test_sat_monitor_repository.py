from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import delete, update
from sqlalchemy.exc import IntegrityError

from cfdi_vault.db import create_engine_from_url, create_session_factory
from cfdi_vault.recovery_db import SatMonitorRunRecord, SatRequestRecord, Tenant
from cfdi_vault.sat_campaign_repository import SatCampaignRepository

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
MIGRATION = Path("db/migration/V8__sat_monitor_schedule.sql")


def test_v8_declares_append_only_monitor_history_and_generic_schedule_hint() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    normalized = re.sub(r"\s+", " ", sql)

    assert "CREATE TABLE sat_monitor_runs" in sql
    assert "CREATE FUNCTION sat_monitor_runs_append_only()" in sql
    assert "CREATE TRIGGER sat_monitor_runs_append_only" in sql
    assert "pg_notify('sat_schedule_changed', '')" in normalized
    assert "NEW.next_check_at IS DISTINCT FROM OLD.next_check_at" in normalized
    assert "BYTEA" not in sql.upper()
    assert "SOAP" not in sql.upper()
    assert "RFC" not in sql.upper()
    assert "DROP TABLE" not in "\n".join(
        line for line in sql.splitlines() if not line.lstrip().startswith("--")
    ).upper()


def test_monitor_run_model_has_only_sanitized_aggregate_fields() -> None:
    columns = set(SatMonitorRunRecord.__table__.columns.keys())

    assert {
        "run_ref", "started_at", "finished_at", "wake_reason", "due_count",
        "contacted_count", "package_count", "no_data_count", "error_count",
        "terminal_category", "duration_ms", "watchdog_wake", "created_at",
    }.issubset(columns)
    assert "raw_response" not in columns
    assert "message" not in columns


def _prepare_repository(database_url: str) -> SatCampaignRepository:
    engine = create_engine_from_url(database_url)
    factory = create_session_factory(engine)
    with factory() as session:
        session.add(Tenant(id="monitor-tenant", name="Synthetic", rfc="SYNTHETIC", created_at=NOW))
        session.commit()
    repository = SatCampaignRepository(factory)
    repository._test_engine = engine  # type: ignore[attr-defined]
    return repository


@pytest.mark.integration
def test_earliest_due_and_monitor_history_are_durable(reset_postgres_database: str) -> None:
    repository = _prepare_repository(reset_postgres_database)
    try:
        campaign = repository.create_campaign(
            campaign_ref="monitor-campaign", tenant_id="monitor-tenant", profile_ref="profile",
            manifest_sha256="a" * 64, commit_ref="commit", phase="metadata-proof",
            status="planned", budget=2, now=NOW,
        )
        window = repository.reserve_window(
            campaign_ref=campaign.campaign_ref, work_ref="monitor-work", direction="received",
            start_date=date(2026, 1, 1), end_date=date(2026, 1, 14), now=NOW,
        )
        with repository._session_factory() as session:  # noqa: SLF001
            session.add(SatRequestRecord(
                tenant_id="monitor-tenant", id_solicitud="monitor-request",
                criteria_hash="b" * 64, direction="received", request_type="Metadata",
                sat_state="pending", requested_at=NOW, raw_response={}, campaign_id=campaign.id,
                window_id=window.id, work_ref=window.work_ref, status="submitted",
                next_check_at=NOW + timedelta(minutes=15),
                service_window_expires_at=NOW + timedelta(minutes=5),
            ))
            session.commit()

        assert repository.get_next_due_at(now=NOW) == NOW + timedelta(minutes=5)
        assert repository.get_next_due_at(now=NOW + timedelta(minutes=16)) == NOW + timedelta(minutes=5)

        run = repository.record_monitor_run(
            started_at=NOW, finished_at=NOW + timedelta(milliseconds=12), wake_reason="watchdog",
            due_count=1, contacted_count=1, package_count=0, no_data_count=0, error_count=0,
            terminal_category=None, duration_ms=12, watchdog_wake=True, now=NOW,
        )

        assert run.run_ref.startswith("monitor-run-")
        status = repository.get_monitor_status()
        assert status["total_runs"] == 1
        assert status["last_wake_reason"] == "watchdog"
        assert status["contacted_count"] == 1
        assert "id_solicitud" not in status

        with pytest.raises(IntegrityError):
            with repository._session_factory() as session:  # noqa: SLF001
                session.execute(update(SatMonitorRunRecord).values(duration_ms=13))
                session.commit()
        with pytest.raises(IntegrityError):
            with repository._session_factory() as session:  # noqa: SLF001
                session.execute(delete(SatMonitorRunRecord))
                session.commit()
    finally:
        repository._test_engine.dispose()  # type: ignore[attr-defined]
