"""Reference-only queue handoff for SAT artifact parsing."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone

from cfdi_vault.domain import QueueMessage, QueueName


def publish_artifact_parse_job(
    publisher: Callable[[QueueMessage], None],
    *,
    tenant_id: str,
    artifact_ref: str,
    kind: str,
    profile_id: str | None = None,
    now: datetime | None = None,
) -> QueueMessage:
    """Publish only an opaque artifact job; bytes remain in external storage."""

    if kind not in {"metadata_zip", "cfdi_zip", "metadata_txt", "cfdi_xml"}:
        raise ValueError("artifact job kind is invalid")
    queue = QueueName.CFDI_PARSE_METADATA if kind in {"metadata_zip", "metadata_txt"} else QueueName.CFDI_PARSE_XML
    message = QueueMessage(
        queue=queue,
        tenant_id=tenant_id,
        profile_id=profile_id,
        job_id=artifact_ref,
        correlation_id=artifact_ref,
        idempotency_key=f"parse:{artifact_ref}",
        created_at=now or datetime.now(timezone.utc),
    )
    publisher(message)
    return message
