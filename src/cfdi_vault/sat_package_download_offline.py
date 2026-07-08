"""Offline helpers for SAT package-download contract validation."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from io import BytesIO
from typing import Iterable
from zipfile import BadZipFile, ZIP_DEFLATED, ZipFile

from cfdi_vault.domain import SatRequestState
from cfdi_vault.sat_contract import SatOutcomeAction
from cfdi_vault.sat_soap_parse import SatSoapParseError, parse_package_download_response


class PackageDownloadOfflineError(ValueError):
    """Raised when the offline package-download contract is not satisfied."""


@dataclass(frozen=True)
class PackageDownloadGateResult:
    allowed: bool
    reason: str
    state: str
    package_count: int


@dataclass(frozen=True)
class OfflinePackageDownloadParseResult:
    package_id_redacted: str
    sat_code: str
    action: str
    content_length: int
    content_sha256: str
    zip_valid: bool
    zip_entry_count: int
    txt_entry_count: int
    xml_entry_count: int
    pdf_entry_count: int


@dataclass(frozen=True)
class PackageZipInspectionResult:
    zip_valid: bool
    entry_count: int
    txt_entry_count: int
    xml_entry_count: int
    pdf_entry_count: int


def evaluate_package_download_gate(
    state: SatRequestState | str,
    package_ids: Iterable[str],
) -> PackageDownloadGateResult:
    """Return whether package download may start after verify."""

    normalized_state = _coerce_state(state)
    package_count = sum(1 for item in package_ids if str(item).strip())
    if normalized_state != SatRequestState.FINISHED:
        return PackageDownloadGateResult(False, "estado-solicitud-not-finished", normalized_state.value, package_count)
    if package_count == 0:
        return PackageDownloadGateResult(False, "ids-paquetes-missing", normalized_state.value, package_count)
    return PackageDownloadGateResult(True, "ready", normalized_state.value, package_count)


def require_package_download_gate(
    state: SatRequestState | str,
    package_ids: Iterable[str],
) -> PackageDownloadGateResult:
    """Require EstadoSolicitud=3 plus at least one package id before download."""

    result = evaluate_package_download_gate(state, package_ids)
    if not result.allowed:
        raise PackageDownloadOfflineError(result.reason)
    return result


def build_synthetic_package_zip(entries: dict[str, bytes] | None = None) -> bytes:
    """Build a tiny synthetic ZIP with non-fiscal TXT evidence only."""

    safe_entries = entries or {
        "README.txt": b"synthetic package for offline package-download contract tests\n",
        "metadata.txt": b"kind=synthetic\ncontains_fiscal_data=false\n",
    }
    for name in safe_entries:
        normalized = name.replace("\\", "/").lower()
        if normalized.endswith((".xml", ".pdf")):
            raise PackageDownloadOfflineError("synthetic-package-fixture-must-not-contain-xml-or-pdf")
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as package:
        for name, content in safe_entries.items():
            package.writestr(name.replace("\\", "/"), content)
    return buffer.getvalue()


def build_synthetic_package_download_response(
    package_content: bytes,
    *,
    sat_code: str = "5000",
    message: str = "Synthetic package ready",
) -> bytes:
    """Build a synthetic SOAP response with a base64 Paquete element."""

    payload = base64.b64encode(package_content).decode("ascii")
    return f"""
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:sat="http://DescargaMasivaTerceros.sat.gob.mx">
      <soap:Body>
        <sat:RespuestaDescargaMasivaTercerosSalida CodEstatus="{sat_code}" Mensaje="{message}">
          <sat:Paquete>{payload}</sat:Paquete>
        </sat:RespuestaDescargaMasivaTercerosSalida>
      </soap:Body>
    </soap:Envelope>
    """.encode("utf-8")


def parse_offline_package_download_response(response: bytes | str, *, package_id: str) -> OfflinePackageDownloadParseResult:
    """Decode an offline package response and prove the package is a ZIP."""

    parsed = parse_package_download_response(response, package_id=package_id)
    content = parsed.content or b""
    if parsed.action != SatOutcomeAction.FINISHED:
        return OfflinePackageDownloadParseResult(
            package_id_redacted=_redact_identifier(package_id),
            sat_code=parsed.sat_code,
            action=parsed.action.value,
            content_length=0,
            content_sha256="",
            zip_valid=False,
            zip_entry_count=0,
            txt_entry_count=0,
            xml_entry_count=0,
            pdf_entry_count=0,
        )
    try:
        names = _zip_names(content)
    except BadZipFile as exc:
        raise SatSoapParseError("package content must be a valid ZIP") from exc
    lower_names = tuple(name.lower() for name in names)
    return OfflinePackageDownloadParseResult(
        package_id_redacted=_redact_identifier(package_id),
        sat_code=parsed.sat_code,
        action=parsed.action.value,
        content_length=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
        zip_valid=True,
        zip_entry_count=len(names),
        txt_entry_count=sum(1 for name in lower_names if name.endswith(".txt")),
        xml_entry_count=sum(1 for name in lower_names if name.endswith(".xml")),
        pdf_entry_count=sum(1 for name in lower_names if name.endswith(".pdf")),
    )


def inspect_package_zip_bytes(content: bytes) -> PackageZipInspectionResult:
    """Inspect ZIP shape in memory without extracting or returning entry names."""

    try:
        names = _zip_names(content)
    except BadZipFile:
        return PackageZipInspectionResult(False, 0, 0, 0, 0)
    lower_names = tuple(name.lower() for name in names)
    return PackageZipInspectionResult(
        zip_valid=True,
        entry_count=len(names),
        txt_entry_count=sum(1 for name in lower_names if name.endswith(".txt")),
        xml_entry_count=sum(1 for name in lower_names if name.endswith(".xml")),
        pdf_entry_count=sum(1 for name in lower_names if name.endswith(".pdf")),
    )


def _zip_names(content: bytes) -> tuple[str, ...]:
    with ZipFile(BytesIO(content)) as package:
        return tuple(package.namelist())


def _coerce_state(state: SatRequestState | str) -> SatRequestState:
    if isinstance(state, SatRequestState):
        return state
    key = "".join(character for character in str(state).lower() if character.isalnum())
    aliases = {
        "1": SatRequestState.ACCEPTED,
        "accepted": SatRequestState.ACCEPTED,
        "aceptada": SatRequestState.ACCEPTED,
        "2": SatRequestState.IN_PROCESS,
        "inprocess": SatRequestState.IN_PROCESS,
        "enproceso": SatRequestState.IN_PROCESS,
        "3": SatRequestState.FINISHED,
        "finished": SatRequestState.FINISHED,
        "terminada": SatRequestState.FINISHED,
        "4": SatRequestState.ERROR,
        "error": SatRequestState.ERROR,
        "5": SatRequestState.REJECTED,
        "rejected": SatRequestState.REJECTED,
        "rechazada": SatRequestState.REJECTED,
        "6": SatRequestState.EXPIRED,
        "expired": SatRequestState.EXPIRED,
        "vencida": SatRequestState.EXPIRED,
    }
    try:
        return aliases[key]
    except KeyError as exc:
        raise PackageDownloadOfflineError("unknown-estado-solicitud") from exc


def _redact_identifier(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"
