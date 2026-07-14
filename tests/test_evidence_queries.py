from __future__ import annotations

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError

from cfdi_vault.evidence_queries import (
    documents_by_parser_status,
    job_events_for_job,
    jobs_by_status,
    reconciliation_by_state,
    xml_evidence_by_parser_status,
    xml_evidence_by_sha256,
    xml_evidence_by_storage_key,
)


def _sql(statement: object) -> str:
    return str(
        statement.compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )


@pytest.mark.parametrize(
    ("statement", "expected_fragments"),
    [
        (
            xml_evidence_by_storage_key(
                "SYN-TENANT", "SYN-TENANT/xml/2026/01/SYN-EVIDENCE.xml"
            ),
            ("xml_evidence.tenant_id = 'SYN-TENANT'", "xml_evidence.storage_key ="),
        ),
        (
            xml_evidence_by_sha256("SYN-TENANT", "0" * 64),
            ("xml_evidence.tenant_id = 'SYN-TENANT'", "xml_evidence.xml_sha256 ="),
        ),
        (
            xml_evidence_by_parser_status("SYN-TENANT", "partial"),
            ("xml_evidence.parser_status = 'partial'", "xml_evidence.created_at DESC"),
        ),
        (
            documents_by_parser_status("SYN-TENANT", "partial"),
            ("cfdi_documents.parser_status = 'partial'", "cfdi_documents.updated_at DESC"),
        ),
        (
            reconciliation_by_state("SYN-TENANT", "XML_PENDING"),
            ("cfdi_metadata_ledger.reconciliation_state = 'XML_PENDING'", "last_seen_at DESC"),
        ),
        (
            jobs_by_status("SYN-TENANT", "running"),
            ("download_jobs.status = 'running'", "download_jobs.updated_at DESC"),
        ),
        (
            job_events_for_job("SYN-JOB-005"),
            ("queue_job_events.job_id = 'SYN-JOB-005'", "queue_job_events.created_at DESC"),
        ),
    ],
)
def test_evidence_queries_match_composite_index_prefixes(
    statement: object,
    expected_fragments: tuple[str, ...],
) -> None:
    compiled = _sql(statement)

    assert all(fragment in compiled for fragment in expected_fragments)
    assert "LIMIT 100" in compiled


def test_storage_lookup_rejects_absolute_adapter_paths() -> None:
    with pytest.raises(ValueError, match="storage key"):
        xml_evidence_by_storage_key("SYN-TENANT", "C:/private/evidence.xml")


@pytest.mark.parametrize("digest", ["", "abc", "g" * 64])
def test_hash_lookup_rejects_invalid_sha256(digest: str) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        xml_evidence_by_sha256("SYN-TENANT", digest)


def test_query_limits_must_be_positive() -> None:
    with pytest.raises(ValueError, match="limit"):
        jobs_by_status("SYN-TENANT", "running", limit=0)


@pytest.mark.integration
def test_evidence_lookup_executes_against_migrated_postgres(
    reset_postgres_database: str,
) -> None:
    from datetime import datetime, timezone

    from sqlalchemy.orm import Session

    from cfdi_vault.db import create_engine_from_url
    from cfdi_vault.recovery_db import XmlEvidence

    engine = create_engine_from_url(reset_postgres_database)
    try:
        with Session(engine) as session:
            session.add(
                XmlEvidence(
                    tenant_id="SYN-TENANT",
                    uuid="00000000-0000-4000-8000-000000000005",
                    source_package_id="SYN-PACKAGE-005",
                    xml_sha256="0" * 64,
                    size_bytes=128,
                    storage_key="SYN-TENANT/xml/2026/01/SYN-EVIDENCE.xml",
                    parser_version="matrix-v1",
                    parser_status="partial",
                    created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
                )
            )
            session.commit()

            stored = session.scalars(
                xml_evidence_by_storage_key(
                    "SYN-TENANT", "SYN-TENANT/xml/2026/01/SYN-EVIDENCE.xml"
                )
            ).one()
            assert stored.xml_sha256 == "0" * 64
            assert stored.size_bytes == 128
            assert session.scalars(
                xml_evidence_by_parser_status("SYN-TENANT", "partial")
            ).one().id == stored.id

            session.add(
                XmlEvidence(
                    tenant_id=stored.tenant_id,
                    uuid=stored.uuid,
                    source_package_id="SYN-PACKAGE-006",
                    xml_sha256=stored.xml_sha256,
                    size_bytes=stored.size_bytes,
                    storage_key="SYN-TENANT/xml/2026/01/DUPLICATE.xml",
                    parser_version=stored.parser_version,
                    parser_status=stored.parser_status,
                    created_at=stored.created_at,
                )
            )
            with pytest.raises(IntegrityError):
                session.commit()
            session.rollback()
    finally:
        engine.dispose()
