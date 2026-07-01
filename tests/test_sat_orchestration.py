from datetime import datetime, timezone

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.reconciliation import decide_metadata_state
from cfdi_vault.sat_contract import SatOutcomeAction
from cfdi_vault.sat_orchestration import MetadataFirstSatOrchestrator, SatOrchestrationStatus
from cfdi_vault.sat_simulator import FakeSatScenario, FakeSatScenarioClient


def _query() -> DownloadQuery:
    return DownloadQuery(
        tenant_id="default",
        requester_rfc="XAXX010101000",
        direction=DownloadDirection.RECEIVED,
        request_type=RequestType.CFDI,
        period=DateTimePeriod(
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        ),
        issuer_rfc="AAA010101AAA",
        receiver_rfcs=("BBB010101BBB",),
    )


def _orchestrator(client: FakeSatScenarioClient) -> MetadataFirstSatOrchestrator:
    return MetadataFirstSatOrchestrator(
        authenticator=client,
        requester=client,
        verifier=client,
        downloader=client,
    )


def test_orchestration_skips_sat_when_reconciliation_has_no_xml_work() -> None:
    client = FakeSatScenarioClient()
    decisions = [
        decide_metadata_state("Vigente", has_xml=True),
        decide_metadata_state("Cancelado", has_xml=False),
    ]

    result = _orchestrator(client).run(_query(), decisions)

    assert result.status == SatOrchestrationStatus.SKIPPED
    assert result.action is None
    assert client.submitted_queries == []
    assert client.verified_request_ids == []
    assert client.downloaded_package_ids == []


def test_orchestration_downloads_packages_when_xml_is_missing() -> None:
    client = FakeSatScenarioClient(FakeSatScenario.VERIFY_FINISHED_WITH_PACKAGES)
    decisions = [decide_metadata_state("Vigente", has_xml=False, is_new=True)]

    result = _orchestrator(client).run(_query(), decisions)

    assert result.status == SatOrchestrationStatus.DOWNLOADED
    assert result.action == SatOutcomeAction.FINISHED
    assert len(result.downloaded_packages) == 2
    assert client.downloaded_package_ids == ["SYN-PKG-001", "SYN-PKG-002"]


def test_orchestration_waits_when_sat_request_is_in_process() -> None:
    client = FakeSatScenarioClient(FakeSatScenario.VERIFY_IN_PROCESS)

    result = _orchestrator(client).run(_query(), [decide_metadata_state("Vigente", has_xml=False)])

    assert result.status == SatOrchestrationStatus.WAITING
    assert result.action == SatOutcomeAction.IN_PROGRESS
    assert client.downloaded_package_ids == []


def test_orchestration_returns_terminal_download_outcome() -> None:
    client = FakeSatScenarioClient(FakeSatScenario.PACKAGE_EXPIRED)

    result = _orchestrator(client).run(_query(), [decide_metadata_state("Vigente", has_xml=False)])

    assert result.status == SatOrchestrationStatus.TERMINAL
    assert result.action == SatOutcomeAction.EXPIRED
    assert len(result.downloaded_packages) == 1


def test_orchestration_returns_retry_for_retryable_sat_error() -> None:
    client = FakeSatScenarioClient(FakeSatScenario.INTERNAL_RETRYABLE_ERROR)

    result = _orchestrator(client).run(_query(), [decide_metadata_state("Vigente", has_xml=False)])

    assert result.status == SatOrchestrationStatus.RETRY
    assert result.action == SatOutcomeAction.RETRY
    assert result.should_retry is True
