from __future__ import annotations

from decimal import Decimal

import pytest

from cfdi_vault.parser import CfdiParseError, parse_cfdi_xml


def test_parser_extracts_required_cfdi_fields(sample_xml: bytes) -> None:
    parsed = parse_cfdi_xml(sample_xml)

    assert parsed.uuid == "00000000-0000-4000-8000-000000000101"
    assert parsed.issuer_rfc == "SYN-ISSUER-101"
    assert parsed.issuer_name == "Synthetic Issuer Test"
    assert parsed.receiver_rfc == "SYN-RECEIVER-101"
    assert parsed.receiver_name == "Synthetic Receiver Test"
    assert parsed.issue_date.isoformat() == "2026-03-10T08:00:00"
    assert parsed.subtotal == Decimal("123.45")
    assert parsed.total == Decimal("143.20")
    assert parsed.currency == "MXN"
    assert parsed.comprobante_type == "I"
    assert parsed.payment_method == "PUE"
    assert parsed.payment_form == "03"


def test_parser_rejects_missing_stamp(sample_xml: bytes) -> None:
    invalid = sample_xml.replace(b"TimbreFiscalDigital", b"OtherComplement")

    with pytest.raises(CfdiParseError, match="TimbreFiscalDigital"):
        parse_cfdi_xml(invalid)
