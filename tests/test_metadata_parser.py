from decimal import Decimal

from cfdi_vault.metadata_parser import parse_metadata_bytes


def test_parse_pipe_metadata_accepts_synthetic_rows() -> None:
    content = "\n".join(
        [
            "uuid|rfcEmisor|nombreEmisor|rfcReceptor|nombreReceptor|fechaEmision|montoTotal|estadoComprobante|tipoComprobante|idPaquete",
            "00000000-0000-4000-8000-000000000001|AAA010101AAA|Synthetic Issuer|BBB010101BBB|Synthetic Receiver|2024-01-15T10:30:00Z|123.45|Vigente|I|SYN-PACKAGE-001",
            "00000000-0000-4000-8000-000000000002|BBB010101BBB|Synthetic Issuer Two|XAXX010101000|Synthetic Receiver Two|2024-01-16|10.00|Cancelado|E|SYN-PACKAGE-001",
        ]
    ).encode("utf-8")

    result = parse_metadata_bytes(content)

    assert result.accepted_count == 2
    assert result.rejected_count == 0
    first = result.entries[0]
    assert first.uuid == "00000000-0000-4000-8000-000000000001"
    assert first.issuer_rfc == "AAA010101AAA"
    assert first.receiver_rfc == "BBB010101BBB"
    assert first.total == Decimal("123.45")
    assert first.status == "Vigente"
    assert first.effect == "I"
    assert first.source_package_id == "SYN-PACKAGE-001"


def test_parse_comma_metadata_accepts_alias_headers_and_default_package() -> None:
    content = "\n".join(
        [
            "uuid,issuer_rfc,receiver_rfc,issue_date,total,status,effect",
            "00000000-0000-4000-8000-000000000003,AAA010101AAA,BBB010101BBB,2024-01-17T08:00:00,99.99,Vigente,I",
        ]
    ).encode("utf-8")

    result = parse_metadata_bytes(content, source_package_id="SYN-PACKAGE-CSV")

    assert result.accepted_count == 1
    assert result.entries[0].source_package_id == "SYN-PACKAGE-CSV"


def test_parse_metadata_reports_invalid_rows_without_ingesting_them() -> None:
    content = "\n".join(
        [
            "uuid|rfcEmisor|rfcReceptor|fechaEmision|montoTotal|estadoComprobante|tipoComprobante",
            "NOT-A-UUID|AAA010101AAA|BBB010101BBB|bad-date|not-decimal||I",
        ]
    ).encode("utf-8")

    result = parse_metadata_bytes(content)

    assert result.accepted_count == 0
    assert result.rejected_count == 1
    assert result.invalid_rows[0].line_number == 2
    assert "uuid must be a valid UUID" in result.invalid_rows[0].errors
    assert "fechaEmision must be ISO datetime or YYYY-MM-DD" in result.invalid_rows[0].errors
    assert "montoTotal must be decimal" in result.invalid_rows[0].errors
    assert "estadoComprobante is required" in result.invalid_rows[0].errors
