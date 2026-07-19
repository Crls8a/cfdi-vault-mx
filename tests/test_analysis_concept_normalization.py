from __future__ import annotations

from decimal import Decimal

import pytest

from cfdi_vault.analysis.normalization import (
    PARSER_STATUS_COMPLETE,
    PARSER_STATUS_PARTIAL,
    PARSER_STATUS_UNSUPPORTED_ERROR,
    normalize_concepts,
)
from cfdi_vault.parser import CfdiParseError


def _xml(*, version: str = "4.0", concepts: str = "", complement: str = "") -> bytes:
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<cfdi:Comprobante xmlns:cfdi="urn:synthetic:cfdi" xmlns:extra="urn:synthetic:extra" Version="{version}">
  <cfdi:Conceptos>{concepts}</cfdi:Conceptos>
  {complement}
</cfdi:Comprobante>'''.encode()


def _concept(
    *,
    description: str = "Service",
    extra: str = "",
    overrides: dict[str, str] | None = None,
) -> str:
    attributes = {
        "ClaveProdServ": "01010101",
        "Cantidad": "2",
        "ClaveUnidad": "H87",
        "Descripcion": description,
        "ValorUnitario": "10.50",
        "Importe": "21.00",
        "ObjetoImp": "02",
    }
    if overrides:
        attributes.update(overrides)
    rendered = " ".join(f'{name}="{value}"' for name, value in attributes.items())
    return f'<cfdi:Concepto xmlns:cfdi="urn:synthetic:cfdi" {rendered} {extra}/>'


def test_v40_multi_concept_normalization_is_ordered_and_bounded() -> None:
    result = normalize_concepts(
        _xml(concepts=_concept() + _concept(description="Second", extra='Descuento="1.00"')),
        document_ref="run-1",
    )

    assert result.version == "4.0"
    assert result.parser_status == PARSER_STATUS_COMPLETE
    assert [record.ordinal for record in result] == [1, 2]
    assert result[0].description == "Service"
    assert result[1].discount == Decimal("1.00")
    assert all(record.provenance == "run-1" for record in result)


def test_optional_attributes_are_none_and_namespaces_are_tolerated() -> None:
    xml = _xml(
        concepts=_concept()
        .replace("cfdi:Concepto", "x:Concepto", 1)
        .replace(
            'xmlns:cfdi="urn:synthetic:cfdi"',
            'xmlns:x="urn:synthetic:other"',
            1,
        )
    )
    result = normalize_concepts(xml)

    assert result.records[0].discount is None


@pytest.mark.parametrize(
    ("xml", "message"),
    [
        (
            _xml(concepts=_concept(overrides={"Importe": "oops"})),
            "concept-decimal-invalid",
        ),
        (
            _xml(concepts=_concept(extra='Descuento="-1"')),
            "concept-decimal-negative",
        ),
        (
            _xml(concepts=_concept(overrides={"Descripcion": ""})),
            "concept-required-attribute-missing",
        ),
    ],
)
def test_invalid_concept_fields_are_rejected(xml: bytes, message: str) -> None:
    with pytest.raises(CfdiParseError, match=message):
        normalize_concepts(xml)


def test_doctype_and_entities_are_rejected_before_parsing() -> None:
    xml = b'<!DOCTYPE x [<!ENTITY e "unsafe">]><Comprobante Version="4.0"/>'

    with pytest.raises(CfdiParseError, match="concept-doctype-rejected"):
        normalize_concepts(xml)

    utf16 = '<!DOCTYPE x [<!ENTITY e "unsafe">]><Comprobante Version="4.0"/>'.encode("utf-16")
    with pytest.raises(CfdiParseError, match="concept-xml-encoding-invalid"):
        normalize_concepts(utf16)


def test_reprocess_is_deterministic_and_does_not_duplicate_records() -> None:
    xml = _xml(concepts=_concept() + _concept(description="Second"))

    first = normalize_concepts(xml, document_ref="same")
    second = normalize_concepts(xml, document_ref="same")

    assert first == second
    assert len(first) == 2


@pytest.mark.parametrize(
    "document_ref",
    [
        "00000000-0000-4000-8000-000000000001",
        "AAA010101AAA",
        "123456",
        "SAT-123",
        "IdSolicitud-123",
        r"C:\\private\\artifact",
        "run/ref",
    ],
)
def test_provenance_rejects_identifier_like_or_path_values(document_ref: str) -> None:
    with pytest.raises(ValueError, match="concept-document-ref-invalid"):
        normalize_concepts(_xml(concepts=_concept()), document_ref=document_ref)


def test_concept_repr_does_not_expose_provenance_or_description() -> None:
    record = normalize_concepts(_xml(concepts=_concept()), document_ref="run-1").records[0]

    rendered = repr(record)
    assert "run-1" not in rendered
    assert "Service" not in rendered


def test_unknown_version_and_business_complement_are_explicitly_partial() -> None:
    unknown = normalize_concepts(_xml(version="9.9", concepts=_concept()))
    partial = normalize_concepts(
        _xml(
            concepts=_concept(),
            complement='<cfdi:Complemento xmlns:cfdi="urn:synthetic:cfdi"><extra:Unknown /></cfdi:Complemento>',
        )
    )

    assert unknown.parser_status == PARSER_STATUS_UNSUPPORTED_ERROR
    assert unknown.records == ()
    assert partial.parser_status == PARSER_STATUS_PARTIAL
    assert len(partial.records) == 1
