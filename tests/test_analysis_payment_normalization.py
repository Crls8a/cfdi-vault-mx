from __future__ import annotations

from decimal import Decimal

import pytest

from cfdi_vault.analysis.payments import (
    PARSER_STATUS_COMPLETE,
    PARSER_STATUS_EMPTY,
    PARSER_STATUS_PARTIAL,
    PARSER_STATUS_UNSUPPORTED_ERROR,
    normalize_payments,
)
from cfdi_vault.parser import CfdiParseError


def _xml(*, version: str = "4.0", payments: str = "", complement: str = "") -> bytes:
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<cfdi:Comprobante xmlns:cfdi="urn:synthetic:cfdi" Version="{version}">
  <cfdi:Complemento>{payments}{complement}</cfdi:Complemento>
</cfdi:Comprobante>'''.encode()


def _payments(*, version: str = "2.0", body: str = "") -> str:
    return f'<p:Pagos xmlns:p="urn:synthetic:pagos" Version="{version}">{body}</p:Pagos>'


def test_multiple_payments_normalize_fields_and_redact_related_ids() -> None:
    body = (
        '<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-02T03:04:05Z" '
        'FormaDePagoP="03" MonedaP="mxn" TipoCambioP="1.25" Monto="100.50">'
        '<p:DoctoRelacionado IdDocumento="not-retained"/> <p:DoctoRelacionado/></p:Pago>'
        '<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-02-03T00:00:00" '
        'FormaDePagoP="01" MonedaP="USD" Monto="25"/>'
    )
    result = normalize_payments(_xml(payments=_payments(body=body)), document_ref="run-1")

    assert result.parser_status == PARSER_STATUS_COMPLETE
    assert result.cfdi_version == "4.0"
    assert result.payment_version == "2.0"
    assert len(result) == 2
    assert result[0].payment_date is not None and result[0].payment_date.isoformat().endswith("+00:00")
    assert result[0].currency == "MXN"
    assert result[0].amount == Decimal("100.50")
    assert result[0].exchange_rate == Decimal("1.25")
    assert result[0].related_document_count == 2
    assert result[0].provenance == "run-1"
    assert "not-retained" not in repr(result[0])


def test_optional_payment_attributes_are_empty_but_valid() -> None:
    result = normalize_payments(
        _xml(payments=_payments(body='<p:Pago xmlns:p="urn:synthetic:pagos"/>'))
    )

    assert result.records[0].payment_date is None
    assert result.records[0].payment_form is None
    assert result.records[0].currency is None
    assert result.records[0].amount is None
    assert result.records[0].exchange_rate is None


@pytest.mark.parametrize(
    ("attribute", "value", "message"),
    [
        ("FechaPago", "2026-02-30T00:00:00", "payment-date-invalid"),
        ("Monto", "-1", "payment-amount-decimal-negative"),
        ("Monto", "NaN", "payment-amount-decimal-invalid"),
        ("TipoCambioP", "-1", "payment-exchange-rate-decimal-negative"),
    ],
)
def test_invalid_dates_and_decimals_are_rejected(attribute: str, value: str, message: str) -> None:
    body = f'<p:Pago xmlns:p="urn:synthetic:pagos" {attribute}="{value}"/>'
    with pytest.raises(CfdiParseError, match=message):
        normalize_payments(_xml(payments=_payments(body=body)))


def test_unsafe_declarations_and_utf16_are_rejected() -> None:
    unsafe = b'<!DOCTYPE x [<!ENTITY e "unsafe">]><Comprobante Version="4.0"/>'
    with pytest.raises(CfdiParseError, match="payment-doctype-rejected"):
        normalize_payments(unsafe)
    with pytest.raises(CfdiParseError, match="payment-xml-encoding-invalid"):
        normalize_payments(unsafe.decode().encode("utf-16"))


def test_no_payment_complement_is_explicitly_empty() -> None:
    result = normalize_payments(
        b'<cfdi:Comprobante xmlns:cfdi="urn:synthetic:cfdi" Version="4.0"/>'
    )

    assert result.records == ()
    assert result.parser_status == PARSER_STATUS_EMPTY
    assert result.payment_version is None
    assert result.complement_present is False


def test_unknown_versions_and_complements_are_not_inferred() -> None:
    unknown_payment = normalize_payments(_xml(payments=_payments(version="9.0")))
    unknown_cfdi = normalize_payments(_xml(version="9.9"))
    unknown_complement = normalize_payments(
        _xml(complement='<x:Unknown xmlns:x="urn:synthetic:other"/>')
    )
    old_cfdi = normalize_payments(_xml(version="3.3", payments=_payments(version="1.0")))

    assert unknown_payment.parser_status == PARSER_STATUS_UNSUPPORTED_ERROR
    assert unknown_payment.records == ()
    assert unknown_cfdi.parser_status == PARSER_STATUS_UNSUPPORTED_ERROR
    assert unknown_complement.parser_status == PARSER_STATUS_PARTIAL
    assert old_cfdi.parser_status == PARSER_STATUS_PARTIAL


def test_reprocessing_is_deterministic_and_provenance_rejects_identifiers() -> None:
    xml = _xml(payments=_payments(body='<p:Pago xmlns:p="urn:synthetic:pagos" Monto="1"/>'))
    assert normalize_payments(xml, document_ref="run-1") == normalize_payments(xml, document_ref="run-1")
    for document_ref in ("AAA010101AAA", "SAT-123", "run/ref", "123456"):
        with pytest.raises(ValueError, match="payment-document-ref-invalid"):
            normalize_payments(xml, document_ref=document_ref)
