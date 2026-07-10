from __future__ import annotations

from cfdi_vault.cfdi_parser import (
    CfdiParserV32,
    CfdiParserV33,
    CfdiParserV40,
    CfdiVersionDetector,
    CommonCfdiParser,
    ComplementParserRegistry,
    PARSER_STATUS_COMPLETE,
    PARSER_STATUS_PARTIAL,
    PARSER_STATUS_UNSUPPORTED_ERROR,
)


def _synthetic_cfdi(
    *,
    version: str | None = "4.0",
    comprobante_type: str = "I",
    business_complement: str | None = None,
    nested_business_child: str | None = None,
) -> bytes:
    version_attr = f'Version="{version}"' if version is not None else ""
    nested_child = f"<comp:{nested_business_child} />" if nested_business_child else ""
    business = (
        f"<comp:{business_complement}>{nested_child}</comp:{business_complement}>"
        if business_complement
        else ""
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<cfdi:Comprobante xmlns:cfdi="urn:synthetic:cfdi" xmlns:tfd="urn:synthetic:stamp" xmlns:comp="urn:synthetic:complement" {version_attr} Fecha="2026-01-01T00:00:00" SubTotal="100.00" Total="116.00" Moneda="MXN" TipoDeComprobante="{comprobante_type}">
  <cfdi:Emisor Rfc="SYN-ISSUER-005" Nombre="Synthetic Issuer" />
  <cfdi:Receptor Rfc="SYN-RECEIVER-005" Nombre="Synthetic Receiver" />
  <cfdi:Complemento>
    <tfd:TimbreFiscalDigital UUID="00000000-0000-4000-8000-000000000005" />
    {business}
  </cfdi:Complemento>
</cfdi:Comprobante>
""".encode("utf-8")


def test_version_detector_and_parser_v40() -> None:
    detector = CfdiVersionDetector()
    parsed = CfdiParserV40(detector).parse(_synthetic_cfdi(version="4.0"))

    assert detector.detect(_synthetic_cfdi(version="4.0")) == "4.0"
    assert parsed.version == "4.0"
    assert parsed.parser_status == PARSER_STATUS_COMPLETE
    assert parsed.parsed is not None
    assert parsed.parsed.uuid == "00000000-0000-4000-8000-000000000005"


def test_version_specific_parser_scaffolds_accept_supported_versions() -> None:
    assert CfdiParserV32().parse(_synthetic_cfdi(version="3.2")).parser_status == PARSER_STATUS_COMPLETE
    assert CfdiParserV33().parse(_synthetic_cfdi(version="3.3")).parser_status == PARSER_STATUS_COMPLETE
    assert CfdiParserV40().parse(_synthetic_cfdi(version="4.0", comprobante_type="E")).parser_status == PARSER_STATUS_COMPLETE


def test_unknown_version_is_unsupported_without_normalized_parse_result() -> None:
    parsed = CommonCfdiParser().parse(_synthetic_cfdi(version="2.0"))

    assert parsed.version == "2.0"
    assert parsed.parser_status == PARSER_STATUS_UNSUPPORTED_ERROR
    assert parsed.parsed is None


def test_missing_version_is_unsupported_without_normalized_parse_result() -> None:
    parsed = CommonCfdiParser().parse(_synthetic_cfdi(version=None))

    assert parsed.version == "unknown"
    assert parsed.parser_status == PARSER_STATUS_UNSUPPORTED_ERROR
    assert parsed.parsed is None


def test_unknown_business_complement_marks_supported_cfdi_partial() -> None:
    parsed = CfdiParserV40().parse(_synthetic_cfdi(business_complement="Unregistered"))

    assert parsed.complements == ("Unregistered",)
    assert parsed.parser_status == PARSER_STATUS_PARTIAL
    assert parsed.parsed is not None


def test_registered_business_complement_keeps_supported_cfdi_complete() -> None:
    registry = ComplementParserRegistry()
    registry.register("Pagos", object())

    parsed = CfdiParserV40(complement_registry=registry).parse(
        _synthetic_cfdi(business_complement="Pagos")
    )

    assert parsed.complements == ("Pagos",)
    assert parsed.parser_status == PARSER_STATUS_COMPLETE


def test_complement_detector_uses_direct_business_roots_only() -> None:
    parsed = CfdiParserV40().parse(
        _synthetic_cfdi(business_complement="Pagos", nested_business_child="NestedNode")
    )

    assert parsed.complements == ("Pagos",)


def test_complement_registry_returns_known_parser() -> None:
    registry = ComplementParserRegistry()
    parser = object()

    registry.register("Pagos20", parser)

    assert registry.get("pagos20") is parser
    assert registry.known() == ("pagos20",)
