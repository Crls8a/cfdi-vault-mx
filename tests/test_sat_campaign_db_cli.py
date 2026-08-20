from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from cfdi_vault.db import create_engine_from_url, create_session_factory
from cfdi_vault.recovery_db import (
    SatArtifactRecord,
    SatCampaignRecord,
    SatCampaignWindowRecord,
    SatMetadataImportRecord,
)
from cfdi_vault.sat_campaign_db_cli import (
    CampaignDatabaseError,
    _commit_ref,
    authorize_campaign,
    campaign_status,
    create_campaign,
    enqueue_campaign_run,
    publish_campaign_run_hint,
    run_from_environment,
    run_without_adapter,
)

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


def _persist_metadata_evidence(database_url: str, campaign_ref: str) -> None:
    """Persist synthetic worker output for the authorization gate tests."""

    engine = create_engine_from_url(database_url)
    factory = create_session_factory(engine)
    try:
        with factory() as session:
            campaign = session.scalar(select(SatCampaignRecord).where(
                SatCampaignRecord.campaign_ref == campaign_ref,
            ))
            assert campaign is not None
            window = session.scalar(select(SatCampaignWindowRecord).where(
                SatCampaignWindowRecord.campaign_id == campaign.id,
            ).order_by(SatCampaignWindowRecord.id))
            assert window is not None
            artifact = SatArtifactRecord(
                campaign_id=campaign.id,
                window_id=window.id,
                artifact_ref="artifact-synthetic-metadata",
                kind="metadata_txt",
                storage_key="sat-metadata/synthetic/metadata.txt",
                sha256="a" * 64,
                size_bytes=128,
                validation_status="processed",
                counts={"records": 1, "eligible": 1},
                created_at=NOW,
            )
            session.add(artifact)
            session.flush()
            session.add(SatMetadataImportRecord(
                campaign_id=campaign.id,
                window_id=window.id,
                artifact_id=artifact.id,
                encoding="utf-8-sig",
                delimiter="~",
                header_compatible=True,
                record_count=1,
                eligible_count=1,
                cancelled_count=0,
                duplicate_count=0,
                conflict_count=0,
                unknown_count=0,
                created_at=NOW,
            ))
            session.commit()
    finally:
        engine.dispose()


def test_db_cli_requires_database_url_without_touching_private_state() -> None:
    with pytest.raises(CampaignDatabaseError, match="campaign-database-required"):
        create_campaign("db-profile", environ={"CFDI_VAULT_COMMIT_REF": "synthetic-commit"})


def test_empty_environment_does_not_inherit_database_url(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://host-only.invalid/db")
    with pytest.raises(CampaignDatabaseError, match="campaign-database-required"):
        create_campaign("db-profile", environ={})


def test_empty_environment_does_not_inherit_commit_ref(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("CFDI_VAULT_COMMIT_REF", "host-only-commit")
    with pytest.raises(CampaignDatabaseError, match="campaign-commit-ref-required"):
        _commit_ref({})


def test_run_from_environment_forwards_explicit_empty_environment(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: list[object] = []
    monkeypatch.setenv("CFDI_VAULT_LIVE_WORKER_ENABLED", "1")
    monkeypatch.setattr(
        "cfdi_vault.sat_campaign_db_cli.run_without_adapter",
        lambda *_args, **kwargs: captured.append(kwargs["environ"]) or {"status": "offline"},
    )

    result = run_from_environment("profile", "campaign", "grant", environ={})

    assert result == {"status": "offline"}
    assert captured == [{}]


@pytest.mark.integration
def test_db_cli_create_is_idempotent_and_status_is_aggregate(reset_postgres_database: str) -> None:
    environment = {"DATABASE_URL": reset_postgres_database, "CFDI_VAULT_COMMIT_REF": "synthetic-commit"}
    first = create_campaign("db-profile", environ=environment)
    second = create_campaign("db-profile", environ=environment)
    assert first == second
    assert first["base_count"] == 28
    assert first["planned_count"] == 28
    status = campaign_status("db-profile", str(first["campaign_ref"]), environ=environment)
    assert status["total_count"] == 28
    assert status["next_check_at"] == ""


@pytest.mark.integration
def test_db_cli_authorize_persists_exact_phase_without_sat_contact(reset_postgres_database: str) -> None:
    environment = {"DATABASE_URL": reset_postgres_database, "CFDI_VAULT_COMMIT_REF": "synthetic-commit"}
    created = create_campaign("db-profile", environ=environment)
    grant = authorize_campaign(
        "db-profile", str(created["campaign_ref"]), "metadata-proof", 14, "synthetic review",
        environ=environment,
    )
    assert grant["phase"] == "metadata-proof"
    result = run_without_adapter("db-profile", str(created["campaign_ref"]), str(grant["grant_ref"]), environ=environment)
    assert result == {"status": "no_due_operations", "contacted_count": 0, "next_check_at": None}


@pytest.mark.integration
def test_db_cli_rejects_cfdi_grant_without_metadata_evidence(reset_postgres_database: str) -> None:
    environment = {"DATABASE_URL": reset_postgres_database, "CFDI_VAULT_COMMIT_REF": "synthetic-commit"}
    created = create_campaign("db-profile", environ=environment)

    with pytest.raises(CampaignDatabaseError, match="campaign-metadata-evidence-required"):
        authorize_campaign(
            "db-profile", str(created["campaign_ref"]), "cfdi-proof", 14,
            "synthetic CFDI review", environ=environment,
        )


@pytest.mark.integration
def test_db_cli_accepts_cfdi_grant_after_valid_metadata_import(reset_postgres_database: str) -> None:
    environment = {"DATABASE_URL": reset_postgres_database, "CFDI_VAULT_COMMIT_REF": "synthetic-commit"}
    created = create_campaign("db-profile", environ=environment)
    campaign_ref = str(created["campaign_ref"])
    _persist_metadata_evidence(reset_postgres_database, campaign_ref)

    grant = authorize_campaign(
        "db-profile", campaign_ref, "cfdi-proof", 14,
        "synthetic CFDI review", environ=environment,
    )

    assert grant["phase"] == "cfdi-proof"


@pytest.mark.integration
def test_db_cli_gates_continue_once_campaign_is_in_cfdi_phase(reset_postgres_database: str) -> None:
    environment = {"DATABASE_URL": reset_postgres_database, "CFDI_VAULT_COMMIT_REF": "synthetic-commit"}
    created = create_campaign("db-profile", environ=environment)
    campaign_ref = str(created["campaign_ref"])
    engine = create_engine_from_url(reset_postgres_database)
    factory = create_session_factory(engine)
    try:
        with factory() as session:
            campaign = session.scalar(select(SatCampaignRecord).where(
                SatCampaignRecord.campaign_ref == campaign_ref,
            ))
            assert campaign is not None
            campaign.phase = "cfdi-proof"
            session.commit()
    finally:
        engine.dispose()

    with pytest.raises(CampaignDatabaseError, match="campaign-metadata-evidence-required"):
        authorize_campaign(
            "db-profile", campaign_ref, "continue", 14,
            "synthetic continuation", environ=environment,
        )

    _persist_metadata_evidence(reset_postgres_database, campaign_ref)
    grant = authorize_campaign(
        "db-profile", campaign_ref, "continue", 14,
        "synthetic continuation", environ=environment,
    )
    assert grant["phase"] == "continue"


def test_publishing_a_wake_hint_without_a_broker_is_a_no_op() -> None:
    """A missing broker must never raise into an already accepted request."""

    assert publish_campaign_run_hint("profile", "campaign", "grant", "run-a", environ={}) is False


def test_publishing_a_wake_hint_never_raises_when_the_broker_is_unreachable() -> None:
    assert publish_campaign_run_hint(
        "profile", "campaign", "grant", "run-a",
        environ={"RABBITMQ_URL": "amqp://guest:guest@127.0.0.1:1/", "DATABASE_URL": ""},
    ) is False


@pytest.mark.integration
def test_enqueue_campaign_run_queues_without_contacting_sat(reset_postgres_database: str) -> None:
    """The panel path must persist intent, not execute the live sequence."""

    environment = {"DATABASE_URL": reset_postgres_database, "CFDI_VAULT_COMMIT_REF": "synthetic-commit"}
    created = create_campaign("db-profile", environ=environment)
    campaign_ref = str(created["campaign_ref"])
    grant = authorize_campaign(
        "db-profile", campaign_ref, "metadata-proof", 14, "synthetic review", environ=environment,
    )

    queued = enqueue_campaign_run(
        "db-profile", campaign_ref, str(grant["grant_ref"]), environ=environment,
    )

    assert queued["status"] == "queued"
    assert str(queued["run_ref"]).startswith("run-")
    assert queued["campaign_ref"] == campaign_ref
    assert datetime.fromisoformat(str(queued["requested_at"])).tzinfo is not None


@pytest.mark.integration
def test_enqueue_campaign_run_is_idempotent_while_the_run_is_active(
    reset_postgres_database: str,
) -> None:
    environment = {"DATABASE_URL": reset_postgres_database, "CFDI_VAULT_COMMIT_REF": "synthetic-commit"}
    created = create_campaign("db-profile", environ=environment)
    campaign_ref = str(created["campaign_ref"])
    grant = authorize_campaign(
        "db-profile", campaign_ref, "metadata-proof", 14, "synthetic review", environ=environment,
    )

    first = enqueue_campaign_run("db-profile", campaign_ref, str(grant["grant_ref"]), environ=environment)
    second = enqueue_campaign_run("db-profile", campaign_ref, str(grant["grant_ref"]), environ=environment)

    assert first["run_ref"] == second["run_ref"]


@pytest.mark.integration
def test_enqueue_campaign_run_applies_the_same_pre_checks_as_the_runner(
    reset_postgres_database: str,
) -> None:
    """A request that could never succeed must fail now, not in a background process."""

    environment = {"DATABASE_URL": reset_postgres_database, "CFDI_VAULT_COMMIT_REF": "synthetic-commit"}
    created = create_campaign("db-profile", environ=environment)
    campaign_ref = str(created["campaign_ref"])
    grant = authorize_campaign(
        "db-profile", campaign_ref, "metadata-proof", 14, "synthetic review", environ=environment,
    )

    with pytest.raises(CampaignDatabaseError, match="campaign-not-found"):
        enqueue_campaign_run("db-profile", "campaign-missing", str(grant["grant_ref"]), environ=environment)
    with pytest.raises(CampaignDatabaseError, match="campaign-profile-mismatch"):
        enqueue_campaign_run("other-profile", campaign_ref, str(grant["grant_ref"]), environ=environment)
    with pytest.raises(CampaignDatabaseError, match="campaign-grant-invalid"):
        enqueue_campaign_run("db-profile", campaign_ref, "grant-does-not-exist", environ=environment)
    with pytest.raises(CampaignDatabaseError, match="campaign-commit-ref-required"):
        enqueue_campaign_run(
            "db-profile", campaign_ref, str(grant["grant_ref"]),
            environ={"DATABASE_URL": reset_postgres_database},
        )


@pytest.mark.integration
def test_campaign_status_exposes_the_last_run_even_before_any_verify_attempt(
    reset_postgres_database: str,
) -> None:
    """Without this projection a run that failed early is completely invisible."""

    environment = {"DATABASE_URL": reset_postgres_database, "CFDI_VAULT_COMMIT_REF": "synthetic-commit"}
    created = create_campaign("db-profile", environ=environment)
    campaign_ref = str(created["campaign_ref"])
    assert campaign_status("db-profile", campaign_ref, environ=environment)["last_run"] is None

    grant = authorize_campaign(
        "db-profile", campaign_ref, "metadata-proof", 14, "synthetic review", environ=environment,
    )
    queued = enqueue_campaign_run(
        "db-profile", campaign_ref, str(grant["grant_ref"]), environ=environment,
    )

    last_run = campaign_status("db-profile", campaign_ref, environ=environment)["last_run"]

    assert last_run == {
        "run_ref": queued["run_ref"],
        "status": "queued",
        "result_code": None,
        "requested_at": queued["requested_at"],
        "finished_at": None,
    }
    assert campaign_status("db-profile", campaign_ref, environ=environment)["verify_attempts"] == 0
