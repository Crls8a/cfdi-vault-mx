from __future__ import annotations

from decimal import Decimal

import pytest

from cfdi_vault.analysis.projection import (
    AccountingProjection,
    AccountingProjectionDispatcher,
    project_accounting_xml,
)
from cfdi_vault.parser import CfdiParseError


def _complete_xml() -> bytes:
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<cfdi:Comprobante xmlns:cfdi="urn:synthetic:cfdi" Version="4.0">
  <cfdi:Conceptos>
    <cfdi:Concepto ClaveProdServ="01010101" Cantidad="2" ClaveUnidad="H87"
      Descripcion="Service" ValorUnitario="10.00" Importe="20.00" ObjetoImp="02"/>
  </cfdi:Conceptos>
  <cfdi:Impuestos>
    <cfdi:Traslados>
      <cfdi:Traslado Impuesto="002" TipoFactor="Tasa" TasaOCuota="0.160000"
        Base="20.00" Importe="3.20"/>
    </cfdi:Traslados>
  </cfdi:Impuestos>
</cfdi:Comprobante>"""


def _partial_xml() -> bytes:
    return b"""<cfdi:Comprobante xmlns:cfdi="urn:synthetic:cfdi"
    xmlns:x="urn:synthetic:other" Version="4.0">
  <cfdi:Conceptos>
    <cfdi:Concepto ClaveProdServ="01010101" Cantidad="1" ClaveUnidad="H87"
      Descripcion="Service" ValorUnitario="1" Importe="1" ObjetoImp="02"/>
  </cfdi:Conceptos>
  <cfdi:Complemento><x:Unknown/></cfdi:Complemento>
</cfdi:Comprobante>"""


def test_complete_projection_returns_typed_records_and_aggregate_counts() -> None:
    projection = project_accounting_xml(_complete_xml())

    assert isinstance(projection, AccountingProjection)
    assert projection.completeness == "complete"
    assert projection.parser_statuses == {
        "concepts": "complete",
        "taxes": "complete",
        "payments": "empty",
        "payroll": "empty",
    }
    assert projection.record_counts == {"concepts": 1, "taxes": 1, "payments": 0, "payroll": 0}
    assert projection.concepts[0].description == "Service"
    assert projection.taxes[0].amount == Decimal("3.20")
    assert projection.as_dict()["record_counts"] == dict(projection.record_counts)


def test_partial_projection_preserves_records_and_statuses() -> None:
    projection = project_accounting_xml(_partial_xml())

    assert projection.completeness == "partial"
    assert projection.record_counts["concepts"] == 1
    assert all(status == "partial" for status in projection.parser_statuses.values())


def test_unsupported_version_is_not_inferred() -> None:
    xml = _complete_xml().replace(b'Version="4.0"', b'Version="9.9"')
    projection = project_accounting_xml(xml)

    assert projection.completeness == "unsupported"
    assert projection.record_counts == {"concepts": 0, "taxes": 0, "payments": 0, "payroll": 0}
    assert set(projection.parser_statuses.values()) == {"unsupported-error"}


def test_dispatcher_reuses_same_projection_for_duplicate_input() -> None:
    dispatcher = AccountingProjectionDispatcher()

    first = dispatcher.dispatch(_complete_xml())
    second = dispatcher.dispatch(_complete_xml())

    assert first.duplicate is False
    assert second.duplicate is True
    assert second.projection is first.projection
    assert second.projection.idempotency_key == first.projection.idempotency_key


def test_same_input_is_deterministic_without_dispatcher_state() -> None:
    first = project_accounting_xml(_complete_xml())
    second = project_accounting_xml(_complete_xml())

    assert first == second
    assert first.source_ref.startswith("xml-")
    assert first.idempotency_key.startswith("accounting-v1-")


def test_projection_repr_and_dict_never_expose_xml_derived_rows() -> None:
    xml = (
        _complete_xml()
        .replace(b"Service", b"SECRET-DESC")
        .replace(b"<cfdi:Impuestos>", b'<cfdi:Emisor Rfc="AAA010101AAA"/><cfdi:Impuestos>')
    )
    projection = project_accounting_xml(xml)

    rendered = repr(projection) + repr(projection.as_dict())
    assert "SECRET-DESC" not in rendered
    assert "AAA010101AAA" not in rendered
    assert "<cfdi:" not in rendered
    assert "UUID" not in rendered
    assert "source_ref" not in projection.as_dict()
    assert "idempotency_key" not in projection.as_dict()


def test_projection_rejects_non_utf8_and_unsafe_declarations() -> None:
    unsafe = b'<!DOCTYPE x [<!ENTITY e "unsafe">]><Comprobante Version="4.0"/>'

    with pytest.raises(CfdiParseError, match="accounting-projection-unsafe-declaration"):
        project_accounting_xml(unsafe)
    with pytest.raises(CfdiParseError, match="accounting-projection-xml-encoding-invalid"):
        project_accounting_xml(unsafe.decode().encode("utf-16"))


def test_projection_rejects_non_bytes() -> None:
    with pytest.raises(TypeError, match="accounting-projection-xml-bytes-required"):
        project_accounting_xml("not-bytes")  # type: ignore[arg-type]
