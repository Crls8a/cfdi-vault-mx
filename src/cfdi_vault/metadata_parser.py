"""Parser for SAT-like metadata TXT/CSV inventories.

The parser accepts only operator-provided bytes and turns synthetic or downloaded
metadata indexes into canonical ``MetadataEntry`` rows. It never reaches SAT and
it never assumes invalid rows are safe to ingest silently.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import csv
from io import StringIO
import re

from cfdi_vault.domain import MetadataEntry


UUID_PATTERN = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$")

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "uuid": ("uuid", "folioFiscal", "uuidComprobante"),
    "issuer_rfc": ("rfcEmisor", "issuer_rfc", "emisorRfc"),
    "issuer_name": ("nombreEmisor", "issuer_name", "emisorNombre"),
    "receiver_rfc": ("rfcReceptor", "receiver_rfc", "receptorRfc"),
    "receiver_name": ("nombreReceptor", "receiver_name", "receptorNombre"),
    "issue_date": ("fechaEmision", "fecha", "issue_date"),
    "total": ("montoTotal", "total", "importeTotal"),
    "status": ("estadoComprobante", "estado", "status"),
    "effect": ("tipoComprobante", "efectoComprobante", "effect"),
    "source_package_id": ("idPaquete", "package_id", "source_package_id"),
}


@dataclass(frozen=True)
class InvalidMetadataRow:
    """One metadata row that could not be converted safely."""

    line_number: int
    errors: tuple[str, ...]
    raw: dict[str, str]


@dataclass(frozen=True)
class MetadataParseResult:
    """Parsed metadata entries plus invalid rows kept for user feedback."""

    entries: tuple[MetadataEntry, ...]
    invalid_rows: tuple[InvalidMetadataRow, ...]

    @property
    def accepted_count(self) -> int:
        return len(self.entries)

    @property
    def rejected_count(self) -> int:
        return len(self.invalid_rows)


def parse_metadata_bytes(content: bytes, *, delimiter: str | None = None, source_package_id: str = "") -> MetadataParseResult:
    """Parse SAT-like metadata bytes as CSV, pipe-delimited TXT, or tab-delimited TXT."""

    text = content.decode("utf-8-sig")
    detected_delimiter = delimiter or _detect_delimiter(text)
    reader = csv.DictReader(StringIO(text), delimiter=detected_delimiter)
    entries: list[MetadataEntry] = []
    invalid_rows: list[InvalidMetadataRow] = []
    for offset, row in enumerate(reader, start=2):
        normalized = {str(key or "").strip(): str(value or "").strip() for key, value in row.items()}
        entry, errors = _entry_from_row(normalized, source_package_id=source_package_id)
        if errors:
            invalid_rows.append(InvalidMetadataRow(line_number=offset, errors=tuple(errors), raw=normalized))
            continue
        entries.append(entry)
    return MetadataParseResult(entries=tuple(entries), invalid_rows=tuple(invalid_rows))


def _entry_from_row(row: dict[str, str], *, source_package_id: str) -> tuple[MetadataEntry, list[str]]:
    errors: list[str] = []
    uuid = _value(row, "uuid").upper()
    issuer_rfc = _value(row, "issuer_rfc").upper()
    issuer_name = _value(row, "issuer_name") or "Synthetic Issuer"
    receiver_rfc = _value(row, "receiver_rfc").upper()
    receiver_name = _value(row, "receiver_name") or "Synthetic Receiver"
    issue_date_raw = _value(row, "issue_date")
    total_raw = _value(row, "total") or "0"
    status = _value(row, "status")
    effect = _value(row, "effect")
    package_id = _value(row, "source_package_id") or source_package_id

    if not UUID_PATTERN.match(uuid):
        errors.append("uuid must be a valid UUID")
    if not issuer_rfc:
        errors.append("rfcEmisor is required")
    if not receiver_rfc:
        errors.append("rfcReceptor is required")
    if not status:
        errors.append("estadoComprobante is required")
    if not effect:
        errors.append("tipoComprobante is required")

    issue_date = _parse_datetime(issue_date_raw)
    if issue_date is None:
        errors.append("fechaEmision must be ISO datetime or YYYY-MM-DD")

    try:
        total = Decimal(total_raw)
    except (InvalidOperation, ValueError):
        total = Decimal("0")
        errors.append("montoTotal must be decimal")

    if errors:
        return _empty_entry(), errors

    return (
        MetadataEntry(
            uuid=uuid,
            issuer_rfc=issuer_rfc,
            issuer_name=issuer_name,
            receiver_rfc=receiver_rfc,
            receiver_name=receiver_name,
            issue_date=issue_date or datetime.now(timezone.utc),
            total=total,
            status=status,
            effect=effect,
            source_package_id=package_id,
        ),
        [],
    )


def _value(row: dict[str, str], canonical: str) -> str:
    for alias in FIELD_ALIASES[canonical]:
        if alias in row and row[alias]:
            return row[alias]
    return ""


def _detect_delimiter(text: str) -> str:
    header = text.splitlines()[0] if text.splitlines() else ""
    candidates = ("~", "|", ",", "\t")
    return max(candidates, key=header.count) if header else ","


def _parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.fromisoformat(value[:10])
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _empty_entry() -> MetadataEntry:
    return MetadataEntry(
        uuid="",
        issuer_rfc="",
        issuer_name="",
        receiver_rfc="",
        receiver_name="",
        issue_date=datetime.now(timezone.utc),
        total=Decimal("0"),
        status="",
        effect="",
        source_package_id="",
    )
