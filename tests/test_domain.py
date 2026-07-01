from datetime import datetime, timezone

import pytest

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType


def test_criteria_hash_is_stable_for_rfc_case_and_receiver_order() -> None:
    period = DateTimePeriod(
        start=datetime(2024, 1, 1, tzinfo=timezone.utc),
        end=datetime(2024, 1, 31, tzinfo=timezone.utc),
    )
    first = DownloadQuery(
        tenant_id="tenant",
        requester_rfc="xaxx010101000",
        direction=DownloadDirection.RECEIVED,
        request_type=RequestType.METADATA,
        period=period,
        receiver_rfcs=("BBB010101BBB", "AAA010101AAA"),
    )
    second = DownloadQuery(
        tenant_id="tenant",
        requester_rfc="XAXX010101000",
        direction=DownloadDirection.RECEIVED,
        request_type=RequestType.METADATA,
        period=period,
        receiver_rfcs=("aaa010101aaa", "bbb010101bbb"),
    )

    assert first.criteria_hash() == second.criteria_hash()


def test_download_query_validation_limits_receiver_rfcs() -> None:
    query = DownloadQuery(
        tenant_id="tenant",
        requester_rfc="XAXX010101000",
        direction=DownloadDirection.RECEIVED,
        request_type=RequestType.METADATA,
        period=DateTimePeriod(
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 31, tzinfo=timezone.utc),
        ),
        receiver_rfcs=("A", "B", "C", "D", "E", "F"),
    )

    assert "receiver_rfcs accepts at most 5 RFC values" in query.validate()


def test_period_rejects_inverted_range() -> None:
    with pytest.raises(ValueError, match="period end"):
        DateTimePeriod(
            start=datetime(2024, 2, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
