"""Deterministic fake SAT client used before live SOAP integration."""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from cfdi_vault.domain import DownloadQuery, MetadataEntry, SatRequestState


class FakeSatClient:
    """Small SAT simulator for local development and CI."""

    def __init__(self) -> None:
        self._requests: dict[str, DownloadQuery] = {}
        self._packages: dict[str, bytes] = {}
        self._metadata: dict[str, tuple[MetadataEntry, ...]] = {}

    def submit_request(self, query: DownloadQuery) -> str:
        request_id = f"FAKE-{query.criteria_hash()[:16].upper()}"
        self._requests[request_id] = query
        package_id = f"PKG-{query.criteria_hash()[:12].upper()}"
        entries = _fake_metadata_entries(query, package_id)
        self._metadata[package_id] = entries
        self._packages[package_id] = _zip_from_entries(entries)
        return request_id

    def verify_request(self, request_id: str) -> dict[str, object]:
        query = self._requests.get(request_id)
        if query is None:
            return {
                "state": SatRequestState.ERROR.value,
                "sat_code": "FAKE404",
                "message": "Fake request id not found",
                "packages": [],
                "metadata": [],
            }
        package_id = f"PKG-{query.criteria_hash()[:12].upper()}"
        return {
            "state": SatRequestState.FINISHED.value,
            "sat_code": "5000",
            "message": "Fake request finished",
            "packages": [package_id],
            "metadata": [_metadata_to_dict(entry) for entry in self._metadata[package_id]],
        }

    def download_package(self, package_id: str) -> bytes:
        try:
            return self._packages[package_id]
        except KeyError as exc:
            raise RuntimeError(f"Fake package not found: {package_id}") from exc


def _fake_metadata_entries(query: DownloadQuery, package_id: str) -> tuple[MetadataEntry, ...]:
    base_date = query.period.start if query.period else datetime(2024, 1, 15, 12, 0, tzinfo=timezone.utc)
    requester = query.requester_rfc.upper()
    issuer = query.issuer_rfc.upper() if query.issuer_rfc else "AAA010101AAA"
    receiver = query.receiver_rfcs[0].upper() if query.receiver_rfcs else requester
    if query.direction.value == "issued":
        issuer, receiver = requester, receiver
    elif query.direction.value == "received":
        issuer, receiver = issuer, requester

    return (
        MetadataEntry(
            uuid=f"{query.criteria_hash()[:8].upper()}-0000-4000-8000-000000000001",
            issuer_rfc=issuer,
            issuer_name="FAKE ISSUER SA DE CV",
            receiver_rfc=receiver,
            receiver_name="FAKE RECEIVER SA DE CV",
            issue_date=base_date,
            total=Decimal("1160.00"),
            status="vigente",
            effect="I",
            source_package_id=package_id,
        ),
        MetadataEntry(
            uuid=f"{query.criteria_hash()[:8].upper()}-0000-4000-8000-000000000002",
            issuer_rfc=issuer,
            issuer_name="FAKE ISSUER SA DE CV",
            receiver_rfc=receiver,
            receiver_name="FAKE RECEIVER SA DE CV",
            issue_date=base_date,
            total=Decimal("580.00"),
            status="vigente",
            effect="P",
            source_package_id=package_id,
        ),
    )


def _zip_from_entries(entries: tuple[MetadataEntry, ...]) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, mode="w", compression=ZIP_DEFLATED) as archive:
        for entry in sorted(entries, key=lambda item: item.uuid):
            info = ZipInfo(f"{entry.uuid}.xml", date_time=(2024, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.create_system = 0
            info.external_attr = 0
            archive.writestr(info, _xml_from_entry(entry))
    return buffer.getvalue()


def _xml_from_entry(entry: MetadataEntry) -> str:
    subtotal = (entry.total / Decimal("1.16")).quantize(Decimal("0.01"))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<cfdi:Comprobante xmlns:cfdi="http://www.sat.gob.mx/cfd/4" xmlns:tfd="http://www.sat.gob.mx/TimbreFiscalDigital" Version="4.0" Fecha="{entry.issue_date.isoformat()}" SubTotal="{subtotal}" Total="{entry.total}" Moneda="MXN" TipoDeComprobante="{entry.effect}" Exportacion="01">
  <cfdi:Emisor Rfc="{entry.issuer_rfc}" Nombre="{entry.issuer_name}" RegimenFiscal="601" />
  <cfdi:Receptor Rfc="{entry.receiver_rfc}" Nombre="{entry.receiver_name}" UsoCFDI="G03" DomicilioFiscalReceptor="00000" RegimenFiscalReceptor="601" />
  <cfdi:Conceptos>
    <cfdi:Concepto ClaveProdServ="84111506" Cantidad="1" ClaveUnidad="ACT" Descripcion="Fake accounting service" ValorUnitario="{subtotal}" Importe="{subtotal}" ObjetoImp="02" />
  </cfdi:Conceptos>
  <cfdi:Complemento>
    <tfd:TimbreFiscalDigital UUID="{entry.uuid}" FechaTimbrado="{entry.issue_date.isoformat()}" />
  </cfdi:Complemento>
</cfdi:Comprobante>
"""


def _metadata_to_dict(entry: MetadataEntry) -> dict[str, object]:
    return {
        "uuid": entry.uuid,
        "issuer_rfc": entry.issuer_rfc,
        "issuer_name": entry.issuer_name,
        "receiver_rfc": entry.receiver_rfc,
        "receiver_name": entry.receiver_name,
        "issue_date": entry.issue_date.isoformat(),
        "total": str(entry.total),
        "status": entry.status,
        "effect": entry.effect,
        "source_package_id": entry.source_package_id,
    }
