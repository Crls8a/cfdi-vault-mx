from datetime import datetime, timezone

import pytest

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType, SatRequestState
from cfdi_vault.sat_contract import SatOutcomeAction, SatRequestResult, SatVerificationResult
from cfdi_vault.sat_orchestration import DownloadRequestOrchestrator, InMemorySatRequestRegistry
from cfdi_vault.sat_simulator import FakeSatScenario, FakeSatScenarioClient


def _query(*, direction: DownloadDirection = DownloadDirection.RECEIVED) -> DownloadQuery:
    return DownloadQuery(
        tenant_id="default",
        requester_rfc="XAXX010101000",
        direction=direction,
        request_type=RequestType.CFDI,
        period=DateTimePeriod(
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        ),
        issuer_rfc="AAA010101AAA" if direction == DownloadDirection.RECEIVED else None,
        receiver_rfcs=("BBB010101BBB",) if direction == DownloadDirection.ISSUED else (),
    )


def _orchestrator(client: FakeSatScenarioClient) -> DownloadRequestOrchestrator:
    return DownloadRequestOrchestrator(requester=client, verifier=client)


def test_duplicate_criteria_does_not_resubmit() -> None:
    client = FakeSatScenarioClient()
    orchestrator = _orchestrator(client)
    query = _query()

    first = orchestrator.submit_once(query)
    duplicate = orchestrator.submit_once(query)

    assert duplicate == first
    assert len(client.submitted_queries) == 1


def test_accepted_request_is_persisted_and_returned_with_request_id() -> None:
    client = FakeSatScenarioClient()

    registered = _orchestrator(client).submit_once(_query())

    assert registered.request_id == f"SYN-REQ-{registered.criteria_hash[:12].upper()}"
    assert registered.request_result.action == SatOutcomeAction.ACCEPTED
    assert registered.message == "Synthetic request accepted"


def test_poll_in_process_records_state_and_no_packages() -> None:
    client = FakeSatScenarioClient(FakeSatScenario.VERIFY_IN_PROCESS)
    orchestrator = _orchestrator(client)
    registered = orchestrator.submit_once(_query())

    polled = orchestrator.poll_once(registered.request_id)

    assert polled.state == SatRequestState.IN_PROCESS
    assert polled.action == SatOutcomeAction.IN_PROGRESS
    assert polled.message == "Synthetic request in process"
    assert polled.package_ids == ()


def test_poll_finished_registers_package_ids_once() -> None:
    client = FakeSatScenarioClient(FakeSatScenario.VERIFY_FINISHED_WITH_PACKAGES)
    orchestrator = _orchestrator(client)
    registered = orchestrator.submit_once(_query())

    first_poll = orchestrator.poll_once(registered.request_id)
    second_poll = orchestrator.poll_once(registered.request_id)

    assert first_poll.package_ids == ("SYN-PKG-001", "SYN-PKG-002")
    assert second_poll.package_ids == ("SYN-PKG-001", "SYN-PKG-002")
    assert client.downloaded_package_ids == []


@pytest.mark.parametrize(
    ("state", "action"),
    [
        (SatRequestState.REJECTED, SatOutcomeAction.PERMANENT_FAILURE),
        (SatRequestState.EXPIRED, SatOutcomeAction.EXPIRED),
        (SatRequestState.ERROR, SatOutcomeAction.PERMANENT_FAILURE),
    ],
)
def test_terminal_verification_states_are_persisted_without_package_ids(
    state: SatRequestState,
    action: SatOutcomeAction,
) -> None:
    client = _TerminalVerificationClient(state=state, action=action)
    orchestrator = DownloadRequestOrchestrator(requester=client, verifier=client)
    registered = orchestrator.submit_once(_query())

    polled = orchestrator.poll_once(registered.request_id)

    assert polled.state == state
    assert polled.action == action
    assert polled.message == f"Synthetic terminal {state.value}"
    assert polled.package_ids == ()


def test_supports_issued_and_received_date_range_queries() -> None:
    client = FakeSatScenarioClient()
    registry = InMemorySatRequestRegistry()
    orchestrator = DownloadRequestOrchestrator(requester=client, verifier=client, registry=registry)

    received = orchestrator.submit_once(_query(direction=DownloadDirection.RECEIVED))
    issued = orchestrator.submit_once(_query(direction=DownloadDirection.ISSUED))

    assert received.request_id != issued.request_id
    assert received.criteria_hash != issued.criteria_hash
    assert len(client.submitted_queries) == 2


class _TerminalVerificationClient:
    def __init__(self, *, state: SatRequestState, action: SatOutcomeAction) -> None:
        self.state = state
        self.action = action
        self.submitted_queries: list[DownloadQuery] = []

    def submit_request(self, query: DownloadQuery) -> SatRequestResult:
        self.submitted_queries.append(query)
        return SatRequestResult(
            request_id=f"SYN-REQ-{query.criteria_hash()[:12].upper()}",
            sat_code="5000",
            message="Synthetic request accepted",
            action=SatOutcomeAction.ACCEPTED,
        )

    def verify_request(self, request_id: str) -> SatVerificationResult:
        return SatVerificationResult(
            request_id=request_id,
            state=self.state,
            sat_code="5000",
            message=f"Synthetic terminal {self.state.value}",
            action=self.action,
            package_ids=("SYN-PKG-001",),
        )
