from datetime import datetime, timezone
from decimal import Decimal

from cfdi_vault.domain import CfdiStatusQuery, CfdiStatusResult
from cfdi_vault.ports import CfdiStatusClientPort


class FakeStatusClient:
    def query_status(self, query: CfdiStatusQuery) -> CfdiStatusResult:
        return CfdiStatusResult(
            uuid=query.uuid,
            status="Vigente",
            checked_at=datetime(2024, 1, 18, tzinfo=timezone.utc),
            sat_code="SYNTHETIC",
            raw_response={"source": "synthetic"},
        )


def test_status_client_port_uses_minimal_cfdi_status_query() -> None:
    client: CfdiStatusClientPort = FakeStatusClient()

    result = client.query_status(
        CfdiStatusQuery(
            uuid="00000000-0000-4000-8000-000000000004",
            issuer_rfc="AAA010101AAA",
            receiver_rfc="BBB010101BBB",
            total=Decimal("42.00"),
        )
    )

    assert result.uuid == "00000000-0000-4000-8000-000000000004"
    assert result.status == "Vigente"
    assert result.sat_code == "SYNTHETIC"
