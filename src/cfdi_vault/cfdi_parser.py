"""Version-aware CFDI parser scaffolding.

This module keeps the common-field parser usable while making parser outcomes
explicit for supported CFDI versions, unknown versions, and business
complements that still need dedicated normalization.
"""

from __future__ import annotations

from dataclasses import dataclass
import xml.etree.ElementTree as ET
from typing import Protocol

from cfdi_vault.parser import CfdiParseError, ParsedCfdi, _reject_doctype, parse_cfdi_xml


PARSER_STATUS_COMPLETE = "complete"
PARSER_STATUS_PARTIAL = "partial"
PARSER_STATUS_UNSUPPORTED_ERROR = "unsupported-error"
SUPPORTED_CFDI_VERSIONS = frozenset({"3.2", "3.3", "4.0"})
COMMON_COMPLETE_CFDI_VERSIONS = frozenset({"4.0"})
STAMP_COMPLEMENT = "TimbreFiscalDigital"


class CfdiParserPort(Protocol):
    """Parser contract for one CFDI version family."""

    def parse(self, xml_bytes: bytes) -> "VersionedParsedCfdi":
        """Parse XML and return normalized fields plus version metadata."""


@dataclass(frozen=True)
class VersionedParsedCfdi:
    """Common parse result enriched with version/complement metadata."""

    parsed: ParsedCfdi | None
    version: str
    complements: tuple[str, ...]
    parser_status: str


class CfdiVersionDetector:
    """Detects CFDI version without validating the full document."""

    def detect(self, xml_bytes: bytes) -> str:
        """Return the declared CFDI version or ``unknown`` when absent.

        Detection is namespace and prefix tolerant, but it still requires a
        ``Comprobante`` root so arbitrary XML is not misclassified as CFDI.
        """

        root = _parse_root(xml_bytes)
        if _local_name(root.tag) != "Comprobante":
            raise CfdiParseError("Expected CFDI Comprobante root element")
        return _declared_version(root)

    def complements(self, xml_bytes: bytes) -> tuple[str, ...]:
        """Return direct business complement roots, excluding the CFDI stamp."""

        root = _parse_root(xml_bytes)
        names: list[str] = []
        for complemento in _direct_children(root, "Complemento"):
            for element in complemento:
                local = _local_name(element.tag)
                if local != STAMP_COMPLEMENT:
                    names.append(local)
        return tuple(dict.fromkeys(names))


class CommonCfdiParser:
    """Common parser used until each version gets deeper normalization."""

    supported_versions: tuple[str, ...] = ()

    def __init__(
        self,
        detector: CfdiVersionDetector | None = None,
        complement_registry: "ComplementParserRegistry | None" = None,
    ) -> None:
        self.detector = detector or CfdiVersionDetector()
        self.complement_registry = complement_registry or ComplementParserRegistry()

    def parse(self, xml_bytes: bytes) -> VersionedParsedCfdi:
        version = self.detector.detect(xml_bytes)
        complements = self.detector.complements(xml_bytes)
        if version not in SUPPORTED_CFDI_VERSIONS:
            return VersionedParsedCfdi(
                parsed=None,
                version=version,
                complements=complements,
                parser_status=PARSER_STATUS_UNSUPPORTED_ERROR,
            )

        try:
            parsed = parse_cfdi_xml(xml_bytes)
        except CfdiParseError:
            if version in COMMON_COMPLETE_CFDI_VERSIONS:
                raise
            return VersionedParsedCfdi(
                parsed=None,
                version=version,
                complements=complements,
                parser_status=PARSER_STATUS_PARTIAL,
            )

        status = (
            PARSER_STATUS_COMPLETE
            if (
                self._supports_version(version)
                and version in COMMON_COMPLETE_CFDI_VERSIONS
                and self._all_complements_extracted(xml_bytes)
            )
            else PARSER_STATUS_PARTIAL
        )
        return VersionedParsedCfdi(
            parsed=parsed,
            version=version,
            complements=complements,
            parser_status=status,
        )

    def _supports_version(self, version: str) -> bool:
        return not self.supported_versions or version in self.supported_versions

    def _all_complements_extracted(self, xml_bytes: bytes) -> bool:
        root = _parse_root(xml_bytes)
        for complemento in _direct_children(root, "Complemento"):
            for element in complemento:
                name = _local_name(element.tag)
                if name == STAMP_COMPLEMENT:
                    continue
                parser = self.complement_registry.get(name)
                parse = getattr(parser, "parse", None)
                if parse is None:
                    return False
                try:
                    parse(element)
                except Exception:
                    return False
        return True


class CfdiParserV32(CommonCfdiParser):
    supported_versions = ("3.2",)


class CfdiParserV33(CommonCfdiParser):
    supported_versions = ("3.3",)


class CfdiParserV40(CommonCfdiParser):
    supported_versions = ("4.0",)


class ComplementParserRegistry:
    """Registry for specialized complement parsers.

    Unknown complements are intentionally preserved as raw payload by higher
    layers and should mark parser_status=partial instead of failing the import.
    """

    def __init__(self) -> None:
        self._parsers: dict[str, object] = {}

    def register(self, name: str, parser: object) -> None:
        self._parsers[name.lower()] = parser

    def get(self, name: str) -> object | None:
        return self._parsers.get(name.lower())

    def known(self) -> tuple[str, ...]:
        return tuple(sorted(self._parsers))


def parser_for_version(version: str) -> CommonCfdiParser:
    """Return the parser scaffold for a declared CFDI version."""

    if version == "3.2":
        return CfdiParserV32()
    if version == "3.3":
        return CfdiParserV33()
    if version == "4.0":
        return CfdiParserV40()
    return CommonCfdiParser()


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def _parse_root(xml_bytes: bytes) -> ET.Element:
    _reject_doctype(xml_bytes)
    try:
        return ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise CfdiParseError(f"Invalid XML: {exc}") from exc


def _declared_version(root: ET.Element) -> str:
    return root.attrib.get("Version") or root.attrib.get("version") or "unknown"


def _direct_children(element: ET.Element, local_name: str) -> tuple[ET.Element, ...]:
    return tuple(child for child in element if _local_name(child.tag) == local_name)
