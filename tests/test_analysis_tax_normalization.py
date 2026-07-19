from __future__ import annotations

from decimal import Decimal

import pytest

from cfdi_vault.analysis.taxes import (
    PARSER_STATUS_COMPLETE,
    PARSER_STATUS_PARTIAL,
    PARSER_STATUS_UNSUPPORTED_ERROR,
    normalize_taxes,
)
from cfdi_vault.parser import CfdiParseError


def _xml(*, version: str = "4.0", concepts: str = "", taxes: str = "", complement: str = "") -> bytes:
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<cfdi:Comprobante xmlns:cfdi="urn:synthetic:cfdi" xmlns:x="urn:synthetic:other" Version="{version}">
  <cfdi:Conceptos>{concepts}</cfdi:Conceptos>
  {taxes}
  {complement}
</cfdi:Comprobante>'''.encode()


def _concept_tax(*, tax: str = "002", factor: str = "Tasa", extra: str = "") -> str:
    return (
        '<cfdi:Concepto xmlns:cfdi="urn:synthetic:cfdi"><cfdi:Impuestos>'
        f'<cfdi:Traslados><cfdi:Traslado Impuesto="{tax}" TipoFactor="{factor}" '
        f'Base="100" TasaOCuota="0.160000" Importe="16" {extra}/></cfdi:Traslados>'
        "</cfdi:Impuestos></cfdi:Concepto>"
    )


def test_transfers_withholdings_and_document_summary_are_ordered() -> None:
    concepts = _concept_tax() + (
        '<cfdi:Concepto xmlns:cfdi="urn:synthetic:cfdi"><cfdi:Impuestos>'
        '<cfdi:Retenciones><cfdi:Retencion Impuesto="001" TipoFactor="Tasa" '
        'Base="100" TasaOCuota="0.100000" Importe="10"/></cfdi:Retenciones>'
        "</cfdi:Impuestos></cfdi:Concepto>"
    )
    summary = (
        '<cfdi:Impuestos xmlns:cfdi="urn:synthetic:cfdi"><cfdi:Traslados>'
        '<cfdi:Traslado Impuesto="002" TipoFactor="Tasa" TasaOCuota="0.160000" Importe="16"/>'
        '</cfdi:Traslados><cfdi:Retenciones><cfdi:Retencion Impuesto="001" Importe="10"/>'
        "</cfdi:Retenciones></cfdi:Impuestos>"
    )
    result = normalize_taxes(_xml(concepts=concepts, taxes=summary), document_ref="run-1")

    assert result.parser_status == PARSER_STATUS_COMPLETE
    assert [(record.tax_type, record.concept_ordinal, record.document_scope) for record in result] == [
        ("transferred", 1, "concept"),
        ("withheld", 2, "concept"),
        ("transferred", None, "document"),
        ("withheld", None, "document"),
    ]
    assert result[0].amount == Decimal("16")
    assert result[-1].base is None
    assert result[-1].factor_type is None


def test_factor_types_and_optional_attributes_are_supported_namespace_tolerantly() -> None:
    xml = _xml(
        taxes=(
            '<x:Impuestos xmlns:x="urn:synthetic:other"><x:Traslados>'
            '<x:Traslado Impuesto="003" TipoFactor="Cuota" TasaOCuota="1.5" Importe="3"/>'
            '<x:Traslado Impuesto="002" TipoFactor="Exento"/>'
            "</x:Traslados></x:Impuestos>"
        )
    )
    result = normalize_taxes(xml)

    assert [(record.tax, record.factor_type) for record in result] == [("003", "Cuota"), ("002", "Exento")]
    assert result[1].rate_or_quota is None
    assert result[1].amount is None


@pytest.mark.parametrize(
    ("fragment", "message"),
    [
        ('Impuesto="999" TipoFactor="Tasa"', "tax-unknown"),
        ('Impuesto="002" TipoFactor="Proporcional"', "tax-factor-unknown"),
        ('Impuesto="002" TipoFactor="Tasa" Importe="NaN"', "tax-decimal-invalid"),
        ('Impuesto="002" TipoFactor="Tasa" Importe="-1"', "tax-decimal-negative"),
    ],
)
def test_invalid_tax_values_are_rejected(fragment: str, message: str) -> None:
    xml = _xml(
        taxes=(
            '<cfdi:Impuestos xmlns:cfdi="urn:synthetic:cfdi"><cfdi:Traslados>'
            f"<cfdi:Traslado {fragment}/></cfdi:Traslados></cfdi:Impuestos>"
        )
    )
    with pytest.raises(CfdiParseError, match=message):
        normalize_taxes(xml)


def test_unsafe_or_malformed_xml_is_rejected() -> None:
    with pytest.raises(CfdiParseError, match="tax-doctype-rejected"):
        normalize_taxes(b'<!DOCTYPE x [<!ENTITY e "unsafe">]><Comprobante Version="4.0"/>')
    utf16 = '<!DOCTYPE x [<!ENTITY e "unsafe">]><Comprobante Version="4.0"/>'.encode("utf-16")
    with pytest.raises(CfdiParseError, match="tax-xml-encoding-invalid"):
        normalize_taxes(utf16)
    with pytest.raises(CfdiParseError, match="tax-xml-invalid"):
        normalize_taxes(b"<Comprobante Version='4.0'>")


def test_version_status_and_unknown_complement_are_explicit() -> None:
    partial = normalize_taxes(_xml(version="3.3", taxes="<Impuestos/>"))
    unknown = normalize_taxes(_xml(version="9.9"))
    complement = normalize_taxes(
        _xml(complement='<cfdi:Complemento xmlns:cfdi="urn:synthetic:cfdi"><x:Unknown /></cfdi:Complemento>')
    )

    assert partial.parser_status == PARSER_STATUS_PARTIAL
    assert partial.records == ()
    assert unknown.parser_status == PARSER_STATUS_UNSUPPORTED_ERROR
    assert complement.parser_status == PARSER_STATUS_PARTIAL


def test_reprocess_is_deterministic_and_repr_is_redacted() -> None:
    xml = _xml(
        taxes='<cfdi:Impuestos xmlns:cfdi="urn:synthetic:cfdi"><cfdi:Traslados>'
        '<cfdi:Traslado Impuesto="002" TipoFactor="Tasa" Importe="16"/>'
        "</cfdi:Traslados></cfdi:Impuestos>"
    )
    first = normalize_taxes(xml, document_ref="run-1")
    second = normalize_taxes(xml, document_ref="run-1")

    assert first == second
    assert "run-1" not in repr(first[0])
    assert "16" not in repr(first[0])


@pytest.mark.parametrize("document_ref", ["AAA010101AAA", "SAT-123", "run/ref", "123456"])
def test_provenance_rejects_identifier_like_values(document_ref: str) -> None:
    with pytest.raises(ValueError, match="tax-document-ref-invalid"):
        normalize_taxes(_xml(), document_ref=document_ref)
