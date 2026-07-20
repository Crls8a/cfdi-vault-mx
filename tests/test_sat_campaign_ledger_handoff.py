from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cfdi_vault.sat_campaign_ledger_handoff import DurableArtifactJobHandoff


class _Transaction:
    def __enter__(self) -> object:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _Store:
    def __init__(self) -> None:
        self.jobs: list[dict[str, object]] = []
        self.events: list[dict[str, object]] = []
        self._engine = self

    def begin(self) -> _Transaction:
        return _Transaction()

    def create_job_on_connection(self, connection: object, **kwargs: object) -> bool:
        self.jobs.append({"connection": connection, **kwargs})
        return True

    def create_outbox_event_on_connection(self, connection: object, **kwargs: object) -> bool:
        self.events.append({"connection": connection, **kwargs})
        return True


class _Publisher:
    def __init__(self) -> None:
        self.calls = 0

    def run_once(self, **kwargs: object):
        self.calls += 1
        return type("Report", (), {"status": "published"})()


class _ConnectionStore(_Store):
    def create_job_on_connection(self, connection: object, **kwargs: object) -> bool:
        self.jobs.append({"connection": connection, **kwargs})
        return True

    def create_outbox_event_on_connection(self, connection: object, **kwargs: object) -> bool:
        self.events.append({"connection": connection, **kwargs})
        return True


def test_handoff_is_idempotent_reference_only_and_dispatches_after_persistence() -> None:
    store = _Store()
    publisher = _Publisher()
    result = DurableArtifactJobHandoff(store, publisher=publisher).enqueue(
        tenant_id="synthetic-tenant",
        artifact_ref="artifact-opaque",
        kind="metadata_zip",
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert result.job_created is True
    assert result.event_created is True
    assert result.dispatch is not None
    assert publisher.calls == 1
    assert store.jobs[0]["queue_name"] == "cfdi.parse.metadata"
    assert store.jobs[0]["job_type"] == "metadata_parse"
    assert store.events[0]["event_type"] == "metadata_parse"
    assert set(store.jobs[0]) == {
        "connection",
        "job_id",
        "tenant_id",
        "job_type",
        "queue_name",
        "artifact_ref",
        "idempotency_key",
        "available_at",
    }


def test_handoff_can_leave_event_queued_for_a_separate_publisher_pass() -> None:
    store = _Store()
    result = DurableArtifactJobHandoff(store).enqueue(
        tenant_id="synthetic-tenant",
        artifact_ref="artifact-opaque",
        kind="cfdi_zip",
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert result.dispatch is None
    assert store.events[0]["routing_key"] == "cfdi.parse.xml"


def test_atomic_handoff_does_not_publish_before_caller_commit() -> None:
    store = _ConnectionStore()
    publisher = _Publisher()
    handoff = DurableArtifactJobHandoff(store, publisher=publisher)
    connection = object()

    result = handoff.persist_on_connection(
        connection,
        tenant_id="synthetic-tenant",
        artifact_ref="artifact-opaque",
        kind="metadata_txt",
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert result.dispatch is None
    assert publisher.calls == 0
    assert store.jobs[0]["connection"] is connection
    assert store.events[0]["connection"] is connection

    dispatch = handoff.publish_after_commit(now=datetime(2026, 1, 1, tzinfo=timezone.utc))

    assert dispatch is not None
    assert publisher.calls == 1


def test_enqueue_rejects_a_non_atomic_store() -> None:
    class NonAtomicStore:
        pass

    with pytest.raises(TypeError, match="atomic handoff"):
        DurableArtifactJobHandoff(NonAtomicStore()).enqueue(
            tenant_id="synthetic-tenant",
            artifact_ref="artifact-opaque",
            kind="metadata_zip",
            now=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
