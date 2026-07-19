from __future__ import annotations

from decimal import Decimal

import pytest

from cfdi_vault.analysis.payroll import (
    NOMINA_NAMESPACE,
    PARSER_STATUS_COMPLETE,
    PARSER_STATUS_EMPTY,
    PARSER_STATUS_PARTIAL,
    PARSER_STATUS_UNSUPPORTED_ERROR,
    normalize_payroll,
)
from cfdi_vault.parser import CfdiParseError


def _xml(*, cfdi_version: str = "4.0", complement: str = "") -> bytes:
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<cfdi:Comprobante xmlns:cfdi="urn:synthetic:cfdi" Version="{cfdi_version}">
  <cfdi:Complemento>{complement}</cfdi:Complemento>
</cfdi:Comprobante>'''.encode()


def _nomina(*, version: str = "1.2", body: str = "", extra: str = "") -> str:
    return (
        f'<n:Nomina xmlns:n="{NOMINA_NAMESPACE}" Version="{version}" '
        'TipoNomina="O" FechaPago="2026-01-15T12:00:00Z" '
        'FechaInicialPago="2026-01-01T00:00:00Z" FechaFinalPago="2026-01-15T00:00:00Z" '
        'NumDiasPagados="15" TotalPercepciones="1000" TotalDeducciones="200" '
        f'TotalOtrosPagos="50">{body}{extra}</n:Nomina>'
    )


def test_normalizes_period_type_totals_and_counts_without_identifiers() -> None:
    body = (
        '<n:Percepciones xmlns:n="http://www.sat.gob.mx/nomina">'
        '<n:Percepcion ImporteGravado="900" ImporteExento="100"/>'
        '<n:Percepcion ImporteGravado="0" ImporteExento="0"/>'
        "</n:Percepciones>"
        '<n:Deducciones xmlns:n="http://www.sat.gob.mx/nomina">'
        '<n:Deduccion Importe="200"/>'
        "</n:Deducciones>"
        '<n:OtrosPagos xmlns:n="http://www.sat.gob.mx/nomina">'
        '<n:OtroPago Importe="50"/>'
        "</n:OtrosPagos>"
    )
    result = normalize_payroll(_xml(complement=_nomina(body=body)), document_ref="run-1")

    assert result.parser_status == PARSER_STATUS_COMPLETE
    assert result.cfdi_version == "4.0"
    assert result.payroll_version == "1.2"
    assert result.namespace == NOMINA_NAMESPACE
    record = result[0]
    assert record.payroll_type == "O"
    assert record.period_start.isoformat() == "2026-01-01T00:00:00+00:00"
    assert record.payment_date.isoformat() == "2026-01-15T12:00:00+00:00"
    assert record.paid_days == Decimal("15")
    assert record.total_perceptions == Decimal("1000")
    assert record.total_deductions == Decimal("200")
    assert record.total_other_payments == Decimal("50")
    assert (record.perception_count, record.deduction_count, record.other_payment_count) == (2, 1, 1)
    assert record.incomplete_count == 0
    assert record.provenance == "run-1"
    assert "run-1" not in repr(record)
    assert "run-1" not in repr(result)


def test_serialization_contains_only_aggregate_fields() -> None:
    result = normalize_payroll(_xml(complement=_nomina()), document_ref="safe-ref")
    payload = result.as_dict()

    assert payload["records"][0]["total_perceptions"] == "1000"
    assert "safe-ref" not in repr(payload)
    assert "RFC" not in repr(payload)


def test_missing_amounts_are_partial_not_zero() -> None:
    body = '<n:Percepciones xmlns:n="http://www.sat.gob.mx/nomina"><n:Percepcion/></n:Percepciones>'
    result = normalize_payroll(_xml(complement=_nomina(body=body, extra="")))

    assert result.parser_status == PARSER_STATUS_PARTIAL
    assert result[0].total_perceptions == Decimal("1000")
    assert result[0].incomplete_count == 2


def test_no_payroll_complement_is_explicitly_empty() -> None:
    result = normalize_payroll(_xml())

    assert result.records == ()
    assert result.parser_status == PARSER_STATUS_EMPTY
    assert result.complement_present is False


def test_unknown_complement_version_or_namespace_is_not_inferred() -> None:
    unknown_complement = normalize_payroll(_xml(complement='<x:Unknown xmlns:x="urn:other"/>'))
    unknown_version = normalize_payroll(_xml(complement=_nomina(version="9.0")))
    wrong_namespace = normalize_payroll(_xml(complement=_nomina().replace(NOMINA_NAMESPACE, "urn:not-nomina")))
    old_cfdi = normalize_payroll(_xml(cfdi_version="3.3", complement=_nomina(version="1.1")))

    assert unknown_complement.parser_status == PARSER_STATUS_PARTIAL
    assert unknown_version.parser_status == PARSER_STATUS_UNSUPPORTED_ERROR
    assert wrong_namespace.parser_status == PARSER_STATUS_UNSUPPORTED_ERROR
    assert old_cfdi.parser_status == PARSER_STATUS_PARTIAL


def test_duplicate_containers_and_unknown_nested_children_are_partial() -> None:
    duplicate = _nomina(
        body=(
            '<n:Percepciones xmlns:n="http://www.sat.gob.mx/nomina"/>'
            '<n:Percepciones xmlns:n="http://www.sat.gob.mx/nomina"/>'
        )
    )
    unknown_nested = _nomina(
        body=('<n:Percepciones xmlns:n="http://www.sat.gob.mx/nomina"><n:Unexpected/></n:Percepciones>')
    )

    duplicate_result = normalize_payroll(_xml(complement=duplicate))
    nested_result = normalize_payroll(_xml(complement=unknown_nested))

    assert duplicate_result.parser_status == PARSER_STATUS_PARTIAL
    assert duplicate_result.records == ()
    assert nested_result.parser_status == PARSER_STATUS_PARTIAL


def test_unsafe_unknown_version_and_namespace_are_not_echoed() -> None:
    unsafe_version = normalize_payroll(_xml(complement=_nomina(version="user-secret")))
    unsafe_namespace = normalize_payroll(_xml(complement=_nomina().replace(NOMINA_NAMESPACE, "urn:leak")))

    assert unsafe_version.payroll_version == "unknown"
    assert unsafe_namespace.namespace == "unknown"
    assert "user-secret" not in repr(unsafe_version)
    assert "urn:leak" not in repr(unsafe_namespace)
    assert "user-secret" not in repr(unsafe_version.as_dict())
    assert "urn:leak" not in repr(unsafe_namespace.as_dict())


@pytest.mark.parametrize(
    ("attribute", "value", "message"),
    [
        ("NumDiasPagados", "-1", "payroll-paid-days-decimal-negative"),
        ("TotalPercepciones", "NaN", "payroll-total-perceptions-decimal-invalid"),
        ("TotalDeducciones", "-1", "payroll-total-deductions-decimal-negative"),
    ],
)
def test_negative_and_nonfinite_amounts_are_rejected(attribute: str, value: str, message: str) -> None:
    xml = _xml(
        complement=_nomina().replace(
            f'{attribute}="{_nomina().split(attribute + '="')[1].split('"')[0]}"', f'{attribute}="{value}"'
        )
    )

    with pytest.raises(CfdiParseError, match=message):
        normalize_payroll(xml)


def test_required_fields_dates_and_type_are_validated() -> None:
    missing_type = _nomina().replace('TipoNomina="O" ', "")
    invalid_type = _nomina().replace('TipoNomina="O"', 'TipoNomina="X"')
    invalid_date = _nomina().replace('FechaPago="2026-01-15T12:00:00Z"', 'FechaPago="2026-01-15"')

    with pytest.raises(CfdiParseError, match="payroll-required-attribute-missing"):
        normalize_payroll(_xml(complement=missing_type))
    with pytest.raises(CfdiParseError, match="payroll-type-invalid"):
        normalize_payroll(_xml(complement=invalid_type))
    with pytest.raises(CfdiParseError, match="payroll-payment-date-invalid"):
        normalize_payroll(_xml(complement=invalid_date))


def test_unsafe_declarations_and_utf16_are_rejected() -> None:
    unsafe = b'<!DOCTYPE x [<!ENTITY e "unsafe">]><Comprobante Version="4.0"/>'
    with pytest.raises(CfdiParseError, match="payroll-doctype-rejected"):
        normalize_payroll(unsafe)
    with pytest.raises(CfdiParseError, match="payroll-xml-encoding-invalid"):
        normalize_payroll(_xml(complement=_nomina()).decode().encode("utf-16"))


@pytest.mark.parametrize("document_ref", ["", "123", "ABC" + "010101" + "AAA", "C:\\private\\x", "not a ref"])
def test_provenance_must_be_opaque_and_is_not_public(document_ref: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        normalize_payroll(_xml(complement=_nomina()), document_ref=document_ref)
