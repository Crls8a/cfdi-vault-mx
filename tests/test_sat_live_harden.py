from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from cfdi_vault.domain import DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_campaign_artifacts import CampaignArtifactError, SatCampaignArtifactCoordinator
from cfdi_vault.sat_contract import SatOutcomeAction, SatRequestResult
from cfdi_vault.sat_db_campaign_runner import SatCampaignRunner

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _query() -> DownloadQuery:
    return DownloadQuery(
        tenant_id="tenant-synthetic", requester_rfc="SYNTHETIC",
        direction=DownloadDirection.RECEIVED, request_type=RequestType.METADATA,
    )


def test_package_lane_fails_before_submit_without_external_handoff() -> None:
    calls: list[str] = []

    class Repository:
        def list_submission_windows(self, _campaign: str, *, limit: int):
            return (SimpleNamespace(work_ref="work", direction="received"),)

        def claim_operation(self, **_kwargs):
            raise AssertionError("claim must not be created")

    runner = SatCampaignRunner(
        Repository(), lambda _request: object(), campaign_ref="campaign",
        downloader_factory=lambda _package: object(),
        submitter_factory=lambda _query: calls.append("submit") or object(),
        query_factory=lambda _window: _query(),
    )

    with pytest.raises(RuntimeError, match="artifact-runtime-required"):
        runner.run(now=NOW)
    assert calls == []


def test_package_lane_rejects_unsafe_coordinator_before_sat() -> None:
    calls: list[str] = []

    class Coordinator:
        def store_package(self, **_kwargs):
            pass

        def ensure_ready(self, *, require_handoff: bool):
            assert require_handoff is True
            raise ValueError("private-storage-detail")

    class Repository:
        def list_submission_windows(self, _campaign: str, *, limit: int):
            return (SimpleNamespace(work_ref="work", direction="received"),)

    runner = SatCampaignRunner(
        Repository(), lambda _request: object(), campaign_ref="campaign",
        downloader_factory=lambda _package: object(), artifact_coordinator=Coordinator(),
        submitter_factory=lambda _query: calls.append("submit") or object(),
        query_factory=lambda _window: _query(),
    )

    with pytest.raises(RuntimeError, match="artifact-runtime-unavailable"):
        runner.run(now=NOW)
    assert calls == []


def test_artifact_runtime_rejects_checkout_mount_path() -> None:
    coordinator = SatCampaignArtifactCoordinator(
        object(), "/app", job_publisher=lambda _message: None,
    )
    with pytest.raises(CampaignArtifactError) as error:
        coordinator.ensure_ready(require_handoff=True)
    assert getattr(error.value, "reason", None) == "artifact-runtime-unavailable"


@pytest.mark.parametrize(
    ("sat_code", "action", "expected"),
    [
        ("5003", SatOutcomeAction.PERMANENT_FAILURE, "sat_too_many_results"),
        ("5004", SatOutcomeAction.PERMANENT_FAILURE, "no_data"),
        ("5005", SatOutcomeAction.DUPLICATE, "duplicate_active_request"),
    ],
)
def test_nonaccepted_submission_never_persists_request(
    sat_code: str, action: SatOutcomeAction, expected: str,
) -> None:
    failures: list[dict[str, object]] = []
    submissions: list[dict[str, object]] = []

    class Repository:
        def list_submission_windows(self, _campaign: str, *, limit: int):
            return (SimpleNamespace(work_ref="work", direction="received"),)

        def claim_operation(self, **_kwargs):
            return SimpleNamespace(claim_ref="claim")

        def record_submission_failure(self, **kwargs):
            failures.append(kwargs)

        def record_submission(self, **kwargs):
            submissions.append(kwargs)

        def claim_due_operations(self, *args, **kwargs):
            return ()

        def get_campaign_status(self, _campaign: str):
            return {}

    result = SatCampaignRunner(
        Repository(), lambda _request: object(), campaign_ref="campaign",
        submitter_factory=lambda _query: SimpleNamespace(submit_request=lambda _value: SatRequestResult(
            request_id="request-must-not-be-stored", sat_code=sat_code,
            message="synthetic", action=action,
        )),
        query_factory=lambda _window: _query(), grant_ref="grant",
    ).run(now=NOW)

    assert result.submission_categories == {expected: 1}
    assert submissions == []
    assert failures == [{
        "claim_ref": "claim", "result_code": expected,
        "result": "error", "now": NOW,
    }]


def test_metadata_txt_is_extracted_and_enqueued_as_opaque_reference(tmp_path: Path) -> None:
    records: list[dict[str, object]] = []
    messages: list[object] = []

    class Repository:
        def get_request(self, _request_id: int):
            return SimpleNamespace(
                id=1, campaign_id=1, window_id=1, work_ref="work",
                tenant_id="tenant-synthetic", grant_ref=None,
                id_solicitud="request-synthetic",
            )

        def get_campaign_ref_for_request(self, _request_id: int) -> str:
            return "campaign"

        def claim_operation(self, **_kwargs):
            return SimpleNamespace(claim_ref="claim-download")

        def record_artifact(self, **kwargs):
            records.append(kwargs)
            return SimpleNamespace(id=len(records), artifact_ref=kwargs["artifact_ref"])

        def record_package(self, **kwargs):
            records.append(kwargs)

        def record_download_uncertain(self, **kwargs):
            raise AssertionError(kwargs)

    payload = BytesIO()
    with ZipFile(payload, "w", ZIP_DEFLATED) as archive:
        archive.writestr(
            "metadata.txt",
            "uuid~rfcEmisor~rfcReceptor~fechaEmision~estadoComprobante~tipoComprobante\n"
            "synthetic~synthetic~synthetic~2026-01-01~Vigente~I\n",
        )

    coordinator = SatCampaignArtifactCoordinator(
        Repository(), str(tmp_path), job_publisher=messages.append,
    )
    coordinator.store_package(
        campaign_ref="campaign", work_ref="work", request_id=1,
        package_ref="package-synthetic", ordinal=1, kind="metadata_zip",
        chunks=(payload.getvalue(),), max_bytes=1024, now=NOW,
    )

    artifacts = [item for item in records if item.get("kind") == "metadata_txt"]
    assert len(artifacts) == 1
    assert artifacts[0]["storage_key"].endswith(".txt")
    assert "Vigente" not in repr(messages[0])
    assert "uuid~" not in repr(messages[0])
    assert messages[0].idempotency_key.startswith("parse:artifact-")
    assert any(path.suffix == ".txt" for path in tmp_path.rglob("*.txt"))
