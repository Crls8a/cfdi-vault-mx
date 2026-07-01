from cfdi_vault.cfdi_parser import CfdiVersionDetector, CfdiParserV40, ComplementParserRegistry


SIMPLE_CFDI_40 = b"""<?xml version="1.0" encoding="UTF-8"?>
<cfdi:Comprobante xmlns:cfdi="http://www.sat.gob.mx/cfd/4" xmlns:tfd="http://www.sat.gob.mx/TimbreFiscalDigital" Version="4.0" Fecha="2024-01-01T00:00:00" SubTotal="100.00" Total="116.00" Moneda="MXN" TipoDeComprobante="I">
  <cfdi:Emisor Rfc="AAA010101AAA" Nombre="Issuer" />
  <cfdi:Receptor Rfc="XAXX010101000" Nombre="Receiver" />
  <cfdi:Complemento>
    <tfd:TimbreFiscalDigital UUID="ABCDEF12-0000-4000-8000-000000000001" />
  </cfdi:Complemento>
</cfdi:Comprobante>
"""


def test_version_detector_and_parser_v40() -> None:
    detector = CfdiVersionDetector()
    parsed = CfdiParserV40(detector).parse(SIMPLE_CFDI_40)

    assert detector.detect(SIMPLE_CFDI_40) == "4.0"
    assert parsed.version == "4.0"
    assert parsed.parser_status == "complete"
    assert parsed.parsed.uuid == "ABCDEF12-0000-4000-8000-000000000001"


def test_complement_registry_returns_known_parser() -> None:
    registry = ComplementParserRegistry()
    parser = object()

    registry.register("Pagos20", parser)

    assert registry.get("pagos20") is parser
    assert registry.known() == ("pagos20",)
