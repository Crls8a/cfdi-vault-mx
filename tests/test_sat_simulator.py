from datetime import datetime, timezone
from decimal import Decimal
from io import BytesIO
from zipfile import ZipFile, is_zipfile

from cfdi_vault.domain import (
    CfdiStatusOutcome,
    CfdiStatusQuery,
    DateTimePeriod,
    DownloadDirection,
    DownloadQuery,
    RequestType,
)
from cfdi_vault.sat_contract import SatOutcomeAction
from cfdi_vault.sat_simulator import FakeSatScenario, FakeSatScenarioClient


def _status_query() -> CfdiStatusQuery:
    return CfdiStatusQuery(
        uuid="00000000-0000-4000-8000-000000000009",
        issuer_rfc="AAA010101AAA",
        receiver_rfc="BBB010101BBB",
        total=Decimal("42.00"),
    )


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


def test_fake_sat_scenarios_cover_request_outcomes() -> None:
    query = _query()

    assert FakeSatScenarioClient(FakeSatScenario.REQUEST_ACCEPTED).submit_request(query).action == SatOutcomeAction.ACCEPTED
    assert FakeSatScenarioClient(FakeSatScenario.REQUEST_DUPLICATE).submit_request(query).action == SatOutcomeAction.DUPLICATE
    assert FakeSatScenarioClient(FakeSatScenario.UNAUTHORIZED).submit_request(query).action == SatOutcomeAction.UNAUTHORIZED
    assert FakeSatScenarioClient(FakeSatScenario.INTERNAL_RETRYABLE_ERROR).submit_request(query).action == SatOutcomeAction.RETRY


def test_fake_sat_scenarios_cover_verification_outcomes() -> None:
    processing = FakeSatScenarioClient(FakeSatScenario.VERIFY_IN_PROCESS).verify_request("SYN-REQ-001")
    finished = FakeSatScenarioClient(FakeSatScenario.VERIFY_FINISHED_WITH_PACKAGES).verify_request("SYN-REQ-001")

    assert processing.action == SatOutcomeAction.IN_PROGRESS
    assert processing.package_ids == ()
    assert finished.action == SatOutcomeAction.FINISHED
    assert finished.package_ids == ("SYN-PKG-001", "SYN-PKG-002")


def test_fake_sat_scenarios_cover_download_outcomes() -> None:
    expired = FakeSatScenarioClient(FakeSatScenario.PACKAGE_EXPIRED).download_package("SYN-PKG-001")
    exhausted = FakeSatScenarioClient(FakeSatScenario.DOWNLOADS_EXHAUSTED).download_package("SYN-PKG-001")
    downloaded = FakeSatScenarioClient(FakeSatScenario.VERIFY_FINISHED_WITH_PACKAGES).download_package("SYN-PKG-001")

    assert expired.action == SatOutcomeAction.EXPIRED
    assert expired.content is None
    assert exhausted.action == SatOutcomeAction.DOWNLOADS_EXHAUSTED
    assert exhausted.content is None
    assert downloaded.action == SatOutcomeAction.FINISHED
    assert downloaded.content is not None
    assert is_zipfile(BytesIO(downloaded.content))
    with ZipFile(BytesIO(downloaded.content)) as package:
        assert sorted(package.namelist()) == ["metadata.txt", "synthetic.xml"]


def test_fake_sat_scenarios_cover_status_outcomes() -> None:
    query = _status_query()

    results = {
        scenario: FakeSatScenarioClient(scenario).query_status(query)
        for scenario in (
            FakeSatScenario.STATUS_ACTIVE,
            FakeSatScenario.STATUS_CANCELLED,
            FakeSatScenario.STATUS_NOT_FOUND,
            FakeSatScenario.STATUS_UNAUTHORIZED,
            FakeSatScenario.STATUS_RETRYABLE,
            FakeSatScenario.STATUS_PERMANENT,
            FakeSatScenario.STATUS_UNKNOWN,
        )
    }

    assert (
        results[FakeSatScenario.STATUS_ACTIVE].uuid
        == "00000000-0000-4000-8000-000000000009"
    )
    assert results[FakeSatScenario.STATUS_ACTIVE].outcome == CfdiStatusOutcome.ACTIVE
    assert results[FakeSatScenario.STATUS_CANCELLED].outcome == CfdiStatusOutcome.CANCELLED
    assert results[FakeSatScenario.STATUS_NOT_FOUND].outcome == CfdiStatusOutcome.NOT_FOUND
    assert results[FakeSatScenario.STATUS_UNAUTHORIZED].outcome == CfdiStatusOutcome.UNAUTHORIZED
    assert results[FakeSatScenario.STATUS_RETRYABLE].outcome == CfdiStatusOutcome.RETRYABLE
    assert results[FakeSatScenario.STATUS_PERMANENT].outcome == CfdiStatusOutcome.PERMANENT
    assert results[FakeSatScenario.STATUS_UNKNOWN].outcome == CfdiStatusOutcome.UNKNOWN
