"""Version-aware CFDI parser scaffolding.

This module keeps the current common-field parser usable while making the next
extension point explicit: version-specific parsers plus complement registry.
"""

from __future__ import annotations

from dataclasses import dataclass
import xml.etree.ElementTree as ET
from typing import Protocol

from cfdi_vault.parser import ParsedCfdi, parse_cfdi_xml


class CfdiParserPort(Protocol):
    """Parser contract for one CFDI version family."""

    def parse(self, xml_bytes: bytes) -> "VersionedParsedCfdi":
        """Parse XML and return normalized fields plus version metadata."""


@dataclass(frozen=True)
class VersionedParsedCfdi:
    """Common parse result enriched with version/complement metadata."""

    parsed: ParsedCfdi
    version: str
    complements: tuple[str, ...]
    parser_status: str


class CfdiVersionDetector:
    """Detects CFDI version without validating the full document."""

    def detect(self, xml_bytes: bytes) -> str:
        root = ET.fromstring(xml_bytes)
        return root.attrib.get("Version") or root.attrib.get("version") or "unknown"

    def complements(self, xml_bytes: bytes) -> tuple[str, ...]:
        root = ET.fromstring(xml_bytes)
        names: list[str] = []
        in_complement = False
        for element in root.iter():
            local = _local_name(element.tag)
            if local == "Complemento":
                in_complement = True
                continue
            if in_complement and local != "TimbreFiscalDigital":
                names.append(local)
        return tuple(dict.fromkeys(names))


class CommonCfdiParser:
    """Common parser used until each version gets deeper normalization."""

    supported_versions: tuple[str, ...] = ()

    def __init__(self, detector: CfdiVersionDetector | None = None) -> None:
        self.detector = detector or CfdiVersionDetector()

    def parse(self, xml_bytes: bytes) -> VersionedParsedCfdi:
        version = self.detector.detect(xml_bytes)
        parsed = parse_cfdi_xml(xml_bytes)
        status = "complete" if not self.supported_versions or version in self.supported_versions else "partial"
        return VersionedParsedCfdi(
            parsed=parsed,
            version=version,
            complements=self.detector.complements(xml_bytes),
            parser_status=status,
        )


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
