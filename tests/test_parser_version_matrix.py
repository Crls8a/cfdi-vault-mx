from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest


MATRIX_DOC = Path(__file__).resolve().parents[1] / "docs" / "parser-version-matrix.md"


@dataclass(frozen=True)
class ScenarioExpectation:
    scenario_id: str
    target_parser_result: str
    target_workflow: str


SCENARIOS = (
    ScenarioExpectation("cfdi-32-income", "complete", "completed"),
    ScenarioExpectation("cfdi-33-income", "complete", "completed"),
    ScenarioExpectation("cfdi-40-income", "complete", "completed"),
    ScenarioExpectation("cfdi-40-expense", "complete", "completed"),
    ScenarioExpectation("payments", "complete", "completed"),
    ScenarioExpectation("payroll", "complete", "completed"),
    ScenarioExpectation("unknown-complement", "partial", "partial"),
    ScenarioExpectation("unknown-version", "unsupported-error", "manual-review"),
)


def _scenario_rows() -> dict[str, list[str]]:
    rows: dict[str, list[str]] = {}
    for line in MATRIX_DOC.read_text(encoding="utf-8").splitlines():
        columns = [column.strip() for column in line.strip().strip("|").split("|")]
        if len(columns) == 8 and columns[0].startswith("`"):
            rows[columns[0].strip("`")] = columns
    return rows


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda item: item.scenario_id)
def test_documented_matrix_has_explicit_target_outcome(
    scenario: ScenarioExpectation,
) -> None:
    row = _scenario_rows()[scenario.scenario_id]

    assert row[3] == f"`{scenario.target_parser_result}`"
    assert row[4] == f"`{scenario.target_workflow}`"
    assert row[5]
    assert row[6]
    assert row[7]


@pytest.mark.parametrize("comprobante_type", ["I", "E"])
def test_income_and_expense_fixtures_are_synthetic(comprobante_type: str) -> None:
    xml_bytes = _build_synthetic_fixture(comprobante_type)
    root = ET.fromstring(xml_bytes)

    assert root.attrib["Version"] == "4.0"
    assert root.attrib["TipoDeComprobante"] == comprobante_type
    assert b"SYN-ISSUER-005" in xml_bytes
    assert b"SYN-RECEIVER-005" in xml_bytes
    assert b"TimbreFiscalDigital" in xml_bytes
    assert b"00000000-0000-4000-8000-000000000005" in xml_bytes


@pytest.mark.parametrize("complement_root", ["Pagos", "Nomina", "Unregistered"])
def test_complement_scenarios_have_synthetic_fixture_roots(
    complement_root: str,
) -> None:
    root = ET.fromstring(_build_synthetic_fixture("I", complement_root=complement_root))
    complemento = next(child for child in root if child.tag.endswith("}Complemento"))
    business_roots = [
        child for child in complemento if not child.tag.endswith("}TimbreFiscalDigital")
    ]

    assert len(business_roots) == 1
    assert business_roots[0].tag.endswith(f"}}{complement_root}")


def _build_synthetic_fixture(
    comprobante_type: str,
    *,
    complement_root: str | None = None,
) -> bytes:
    business_complement = (
        f"<comp:{complement_root} />"
        if complement_root
        else ""
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<cfdi:Comprobante xmlns:cfdi="urn:synthetic:cfdi"
    xmlns:comp="urn:synthetic:complement" xmlns:tfd="urn:synthetic:stamp"
    Version="4.0"
    Fecha="2026-01-01T00:00:00" SubTotal="100.00" Total="100.00"
    Moneda="MXN" TipoDeComprobante="{comprobante_type}">
  <cfdi:Emisor Rfc="SYN-ISSUER-005" Nombre="Synthetic Issuer" />
  <cfdi:Receptor Rfc="SYN-RECEIVER-005" Nombre="Synthetic Receiver" />
  <cfdi:Complemento>
    <tfd:TimbreFiscalDigital UUID="00000000-0000-4000-8000-000000000005" />
    {business_complement}
  </cfdi:Complemento>
</cfdi:Comprobante>
""".encode("utf-8")
