from __future__ import annotations

from datetime import datetime, timezone

from cfdi_vault.domain import QueueName
from cfdi_vault.sat_campaign_jobs import publish_artifact_parse_job


def test_metadata_parse_job_contains_only_opaque_reference() -> None:
    published = []
    message = publish_artifact_parse_job(
        published.append,
        tenant_id="tenant-synthetic",
        artifact_ref="artifact-synthetic",
        kind="metadata_zip",
        profile_id="profile-synthetic",
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert published == [message]
    assert message.queue is QueueName.CFDI_PARSE_METADATA
    assert message.job_id == "artifact-synthetic"
    assert message.correlation_id == "artifact-synthetic"
    assert message.idempotency_key == "parse:artifact-synthetic"
    assert "payload" not in message.as_dict()


def test_xml_parse_job_uses_xml_queue() -> None:
    published = []
    message = publish_artifact_parse_job(
        published.append,
        tenant_id="tenant-synthetic",
        artifact_ref="artifact-xml",
        kind="cfdi_zip",
    )

    assert message.queue is QueueName.CFDI_PARSE_XML
