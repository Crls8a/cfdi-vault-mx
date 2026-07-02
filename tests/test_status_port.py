from datetime import datetime, timezone
from decimal import Decimal

from cfdi_vault.domain import CfdiStatusOutcome, CfdiStatusQuery, CfdiStatusResult
from cfdi_vault.ports import CfdiStatusClientPort


class FakeStatusClient:
    def query_status(self, query: CfdiStatusQuery) -> CfdiStatusResult:
        return CfdiStatusResult(
            uuid=query.uuid,
            status="Vigente",
            checked_at=datetime(2024, 1, 18, tzinfo=timezone.utc),
            sat_code="SYNTHETIC",
            outcome=CfdiStatusOutcome.ACTIVE,
            raw_response={"source": "synthetic"},
        )


def test_status_client_port_uses_minimal_cfdi_status_query() -> None:
    client: CfdiStatusClientPort = FakeStatusClient()

    result = client.query_status(
        CfdiStatusQuery(
            uuid="00000000-0000-4000-8000-000000000009",
            issuer_rfc="AAA010101AAA",
            receiver_rfc="BBB010101BBB",
            total=Decimal("42.00"),
        )
    )

    assert result.uuid == "00000000-0000-4000-8000-000000000009"
    assert result.status == "Vigente"
    assert result.sat_code == "SYNTHETIC"
    assert result.outcome == CfdiStatusOutcome.ACTIVE


def test_status_result_preserves_legacy_positional_raw_response_argument() -> None:
    result = CfdiStatusResult(
        "00000000-0000-4000-8000-000000000010",
        "Vigente",
        datetime(2024, 1, 18, tzinfo=timezone.utc),
        "SYNTHETIC",
        {"source": "legacy-positional"},
    )

    assert result.raw_response == {"source": "legacy-positional"}
    assert result.outcome == CfdiStatusOutcome.UNKNOWN
