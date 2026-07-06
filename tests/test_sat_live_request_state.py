from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_live_request_state import (
    LiveRequestStateError,
    list_live_metadata_requests,
    live_metadata_state_path,
    load_live_metadata_request,
    persist_live_metadata_request,
)

REQUEST_ID = "648a0000-1111-2222-3333-444444447b27"


def test_persist_live_metadata_request_stores_full_id_locally_and_redacted_ref(tmp_path: Path) -> None:
    record = _persist(tmp_path, permit_ref="permit-secret-local-ref", now=datetime(2026, 7, 6, tzinfo=timezone.utc))

    assert record.id_solicitud == REQUEST_ID
    assert record.id_solicitud_redacted == "648a...7b27"
    assert record.request_ref.startswith("req-")
    assert record.permit_id_hash

    raw = live_metadata_state_path(tmp_path).read_text(encoding="utf-8")
    assert REQUEST_ID in raw
    assert "648a...7b27" in raw
    assert "permit-secret-local-ref" not in raw
    assert "SYNTHETIC_TOKEN" not in raw
    assert "<soap" not in raw.lower()

    stored = json.loads(raw)["requests"][0]
    assert stored["live"] is True
    assert stored["status"] == "accepted"
    assert stored["sourceCommand"] == "sat metadata-request-smoke"
    assert {
        "profileId",
        "direction",
        "kind",
        "operation",
        "fechaInicial",
        "fechaFinal",
        "criteriaHash",
        "satCode",
        "satMessage",
        "createdAt",
        "permitIdHash",
        "requestRef",
    }.issubset(stored)


def test_persist_live_metadata_request_upserts_same_request_without_duplicate(tmp_path: Path) -> None:
    first = _persist(tmp_path, message="Accepted")
    second = _persist(tmp_path, message="Accepted again")

    assert first.request_ref == second.request_ref
    assert len(list_live_metadata_requests(tmp_path)) == 1
    assert load_live_metadata_request(tmp_path, first.request_ref).sat_message == "Accepted again"


def test_load_live_metadata_request_missing_ref_aborts_without_guessing(tmp_path: Path) -> None:
    with pytest.raises(LiveRequestStateError) as exc:
        load_live_metadata_request(tmp_path, "req-missing")

    assert exc.value.reason == "request-state-not-found"


def test_persist_live_metadata_request_wraps_io_errors_without_local_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "cfdi_vault.sat_live_request_state.os.replace",
        lambda _source, _target: (_ for _ in ()).throw(OSError("synthetic local path failure")),
    )

    with pytest.raises(LiveRequestStateError) as exc:
        _persist(tmp_path)

    assert exc.value.reason == "request-state-io-error"
    assert str(tmp_path) not in exc.value.reason


def _persist(
    root: Path,
    *,
    message: str = "Accepted",
    permit_ref: str | None = None,
    now: datetime | None = None,
):
    return persist_live_metadata_request(
        storage_root=root,
        profile_id="default",
        query=_query(),
        operation="SolicitaDescargaRecibidos",
        id_solicitud=REQUEST_ID,
        sat_code="5000",
        sat_message=message,
        source_command="sat metadata-request-smoke",
        permit_ref=permit_ref,
        now=now,
    )


def _query() -> DownloadQuery:
    return DownloadQuery(
        "default",
        "XAXX010101000",
        DownloadDirection.RECEIVED,
        RequestType.METADATA,
        DateTimePeriod(
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            datetime(2024, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
        ),
    )
