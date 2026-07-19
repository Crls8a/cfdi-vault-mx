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


def _payments(*, version: str = "2.0", body: str = "", include_totals: bool = True) -> str:
    totals = ""
    if version == "2.0" and include_totals and "Totales" not in body:
        totals = '<p:Totales xmlns:p="urn:synthetic:pagos" MontoTotalPagos="1"/>'
    return f'<p:Pagos xmlns:p="urn:synthetic:pagos" Version="{version}">{totals}{body}</p:Pagos>'


def test_multiple_payments_normalize_fields_and_redact_related_ids() -> None:
    body = (
        '<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-02T03:04:05Z" '
        'FormaDePagoP="03" MonedaP="usd" TipoCambioP="1.25" Monto="100.50">'
        '<p:DoctoRelacionado IdDocumento="not-retained"/> <p:DoctoRelacionado/></p:Pago>'
        '<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-02-03T00:00:00-06:00" '
        'FormaDePagoP="01" MonedaP="MXN" Monto="25"/>'
    )
    result = normalize_payments(_xml(payments=_payments(body=body)), document_ref="run-1")

    assert result.parser_status == PARSER_STATUS_COMPLETE
    assert result.cfdi_version == "4.0"
    assert result.payment_version == "2.0"
    assert len(result) == 2
    assert result[0].payment_date is not None and result[0].payment_date.isoformat().endswith("+00:00")
    assert result[0].currency == "USD"
    assert result[0].amount == Decimal("100.50")
    assert result[0].exchange_rate == Decimal("1.25")
    assert result[0].related_document_count == 2
    assert result[1].payment_date is not None and result[1].payment_date.isoformat() == "2026-02-03T06:00:00+00:00"
    assert result[0].provenance == "run-1"
    assert "not-retained" not in repr(result[0])


def test_optional_payment_attributes_are_empty_but_valid() -> None:
    result = normalize_payments(
        _xml(
            payments=_payments(
                body='<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-02-01T00:00:00Z" '
                'FormaDePagoP="03" MonedaP="MXN" Monto="1"/>'
            )
        )
    )

    assert result.records[0].payment_date is not None
    assert result.records[0].payment_form == "03"
    assert result.records[0].currency == "MXN"
    assert result.records[0].amount == Decimal("1")
    assert result.records[0].exchange_rate is None


@pytest.mark.parametrize("missing", ["FechaPago", "FormaDePagoP", "MonedaP", "Monto"])
def test_required_payment_attributes_are_rejected_when_missing(missing: str) -> None:
    attrs = {
        "FechaPago": "2026-02-01T00:00:00Z",
        "FormaDePagoP": "03",
        "MonedaP": "MXN",
        "Monto": "1",
    }
    del attrs[missing]
    rendered = " ".join(f'{name}="{item}"' for name, item in attrs.items())
    body = f'<p:Pago xmlns:p="urn:synthetic:pagos" {rendered}/>'

    with pytest.raises(CfdiParseError, match="payment-required-attribute-missing"):
        normalize_payments(_xml(payments=_payments(body=body)))


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
    attrs = {
        "FechaPago": "2026-02-01T00:00:00",
        "FormaDePagoP": "03",
        "MonedaP": "MXN",
        "Monto": "1",
    }
    attrs[attribute] = value
    if attribute == "TipoCambioP":
        attrs["MonedaP"] = "USD"
    rendered = " ".join(f'{name}="{item}"' for name, item in attrs.items())
    body = f'<p:Pago xmlns:p="urn:synthetic:pagos" {rendered}/>'
    with pytest.raises(CfdiParseError, match=message):
        normalize_payments(_xml(payments=_payments(body=body)))


def test_unsafe_declarations_and_utf16_are_rejected() -> None:
    unsafe = b'<!DOCTYPE x [<!ENTITY e "unsafe">]><Comprobante Version="4.0"/>'
    with pytest.raises(CfdiParseError, match="payment-doctype-rejected"):
        normalize_payments(unsafe)
    with pytest.raises(CfdiParseError, match="payment-xml-encoding-invalid"):
        normalize_payments(unsafe.decode().encode("utf-16"))


def test_no_payment_complement_is_explicitly_empty() -> None:
    result = normalize_payments(b'<cfdi:Comprobante xmlns:cfdi="urn:synthetic:cfdi" Version="4.0"/>')

    assert result.records == ()
    assert result.parser_status == PARSER_STATUS_EMPTY
    assert result.payment_version is None
    assert result.complement_present is False


def test_unknown_versions_and_complements_are_not_inferred() -> None:
    unknown_payment = normalize_payments(_xml(payments=_payments(version="9.0")))
    unknown_cfdi = normalize_payments(_xml(version="9.9"))
    unknown_complement = normalize_payments(_xml(complement='<x:Unknown xmlns:x="urn:synthetic:other"/>'))
    old_cfdi = normalize_payments(_xml(version="3.3", payments=_payments(version="1.0")))

    assert unknown_payment.parser_status == PARSER_STATUS_UNSUPPORTED_ERROR
    assert unknown_payment.records == ()
    assert unknown_cfdi.parser_status == PARSER_STATUS_UNSUPPORTED_ERROR
    assert unknown_complement.parser_status == PARSER_STATUS_PARTIAL
    assert old_cfdi.parser_status == PARSER_STATUS_PARTIAL


def test_payment_version_must_match_cfdi_version_and_totales_are_valid_for_v20() -> None:
    mismatch = normalize_payments(_xml(payments=_payments(version="1.0")))
    valid_v20 = normalize_payments(
        _xml(
            payments=_payments(
                body=(
                    '<p:Totales xmlns:p="urn:synthetic:pagos" MontoTotalPagos="1"/>'
                    '<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-01T00:00:00Z" '
                    'FormaDePagoP="03" MonedaP="MXN" Monto="1"/>'
                )
            )
        )
    )

    assert mismatch.parser_status == PARSER_STATUS_UNSUPPORTED_ERROR
    assert mismatch.records == ()
    assert valid_v20.parser_status == PARSER_STATUS_COMPLETE


def test_payment_cardinality_is_explicit_for_payment_versions() -> None:
    no_payment_v10 = normalize_payments(_xml(version="3.3", payments=_payments(version="1.0")))
    no_totals_v20 = normalize_payments(_xml(payments=_payments(version="2.0", body="", include_totals=False)))
    two_totals_v20 = normalize_payments(
        _xml(
            payments=_payments(
                body=(
                    '<p:Totales xmlns:p="urn:synthetic:pagos" MontoTotalPagos="1"/>'
                    '<p:Totales xmlns:p="urn:synthetic:pagos" MontoTotalPagos="1"/>'
                    '<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-01T00:00:00Z" '
                    'FormaDePagoP="03" MonedaP="MXN" Monto="1"/>'
                )
            )
        )
    )

    assert no_payment_v10.parser_status == PARSER_STATUS_PARTIAL
    assert no_totals_v20.parser_status == PARSER_STATUS_PARTIAL
    assert two_totals_v20.parser_status == PARSER_STATUS_PARTIAL
    assert no_payment_v10.records == no_totals_v20.records == two_totals_v20.records == ()


def test_payment_v20_requires_totals_before_payments() -> None:
    wrong_order = _xml(
        payments=_payments(
            body=(
                '<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-01T00:00:00Z" '
                'FormaDePagoP="03" MonedaP="MXN" Monto="1"/>'
                '<p:Totales xmlns:p="urn:synthetic:pagos" MontoTotalPagos="1"/>'
            )
        )
    )
    result = normalize_payments(wrong_order)

    assert result.parser_status == PARSER_STATUS_PARTIAL
    assert result.records == ()


def test_payment_date_requires_time_component() -> None:
    xml = _xml(
        payments=_payments(
            body=(
                '<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-01" '
                'FormaDePagoP="03" MonedaP="MXN" Monto="1"/>'
            )
        )
    )

    with pytest.raises(CfdiParseError, match="payment-date-invalid"):
        normalize_payments(xml)


@pytest.mark.parametrize(
    ("attribute", "value", "message"),
    [
        ("MonedaP", "XXX", "payment-currency-invalid"),
        ("FormaDePagoP", "99", "payment-form-invalid"),
    ],
)
def test_restricted_payment_attributes_are_rejected(attribute: str, value: str, message: str) -> None:
    attrs = {
        "FechaPago": "2026-01-01T00:00:00Z",
        "FormaDePagoP": "03",
        "MonedaP": "MXN",
        "Monto": "1",
    }
    attrs[attribute] = value
    rendered = " ".join(f'{name}="{item}"' for name, item in attrs.items())
    body = f'<p:Pago xmlns:p="urn:synthetic:pagos" {rendered}/>'

    with pytest.raises(CfdiParseError, match=message):
        normalize_payments(_xml(payments=_payments(body=body)))


def test_exchange_rate_rules_are_enforced() -> None:
    missing = '<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-01T00:00:00Z" FormaDePagoP="03" MonedaP="USD" Monto="1"/>'
    forbidden = '<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-01T00:00:00Z" FormaDePagoP="03" MonedaP="MXN" Monto="1" TipoCambioP="1"/>'
    zero = '<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-01T00:00:00Z" FormaDePagoP="03" MonedaP="USD" Monto="1" TipoCambioP="0"/>'

    for body, message in (
        (missing, "payment-exchange-rate-required"),
        (forbidden, "payment-exchange-rate-forbidden"),
        (zero, "payment-exchange-rate-nonpositive"),
    ):
        with pytest.raises(CfdiParseError, match=message):
            normalize_payments(_xml(payments=_payments(body=body)))


def test_multiple_payment_complements_are_partial_without_selecting_one() -> None:
    xml = _xml(
        payments=(
            _payments(
                body='<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-01T00:00:00Z" FormaDePagoP="03" MonedaP="MXN" Monto="1"/>'
            )
            + _payments(
                body='<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-02T00:00:00Z" FormaDePagoP="03" MonedaP="MXN" Monto="2"/>'
            )
        )
    )
    result = normalize_payments(xml)

    assert result.parser_status == PARSER_STATUS_PARTIAL
    assert result.records == ()


def test_reprocessing_is_deterministic_and_provenance_rejects_identifiers() -> None:
    xml = _xml(
        payments=_payments(
            body='<p:Pago xmlns:p="urn:synthetic:pagos" FechaPago="2026-01-01T00:00:00Z" '
            'FormaDePagoP="03" MonedaP="MXN" Monto="1"/>'
        )
    )
    assert normalize_payments(xml, document_ref="run-1") == normalize_payments(xml, document_ref="run-1")
    for document_ref in ("AAA010101AAA", "SAT-123", "run/ref", "123456"):
        with pytest.raises(ValueError, match="payment-document-ref-invalid"):
            normalize_payments(xml, document_ref=document_ref)
