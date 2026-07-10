"""Deterministic offline SAT adapters used before live SOAP integration.

The split fake adapters implement the public LIB-005B ports without credentials,
network, files, clocks, Docker, PostgreSQL, RabbitMQ, Redis, or live SAT side
effects. ``FakeSatClient`` remains as an internal compatibility adapter for the
reference-system recovery service.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from cfdi_vault.domain import DownloadQuery, MetadataEntry, SatRequestState
from cfdi_vault.sat_contract import (
    SatAuthResult,
    SatDownloadResult,
    SatOutcomeAction,
    SatPackageDownloadError,
    SatRequestError,
    SatRequestResult,
    SatVerificationError,
    SatVerificationResult,
)


@dataclass
class FakeSatStore:
    """In-memory synthetic SAT state shared by split fake adapters.

    The store keeps only synthetic request/package references and caller-owned
    package bytes. It is intended for tests and examples, not persistence.
    """

    requests: dict[str, DownloadQuery] = field(default_factory=dict)
    packages: dict[str, bytes] = field(default_factory=dict)
    verifications: dict[str, SatVerificationResult] = field(default_factory=dict)


class FakeSatAuthenticator:
    """Deterministic credential-free implementation of ``SatAuthenticatorPort``."""

    def __init__(self, *, authorization: str = "SYNTHETIC-AUTHORIZATION") -> None:
        self._authorization = authorization

    def authenticate(self) -> SatAuthResult:
        """Return a synthetic authorization result without external side effects."""

        return SatAuthResult(
            authorization=self._authorization,
            expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
            raw_response={"source": "synthetic"},
        )


class FakeSatRequester:
    """Deterministic offline implementation of ``SatRequestPort``."""

    def __init__(self, store: FakeSatStore | None = None) -> None:
        self.store = store or FakeSatStore()

    def submit_request(self, query: DownloadQuery) -> SatRequestResult:
        """Validate and register one synthetic SAT request.

        Raises:
            SatRequestError: If the query violates local request validation.
        """

        errors = query.validate()
        if errors:
            raise SatRequestError(
                operation="request",
                code="invalid-query",
                message="; ".join(errors),
                retryable=False,
                next_action="correct the synthetic request criteria before retrying",
            )
        request_id = f"SYN-REQ-{query.criteria_hash()[:12].upper()}"
        package_id = f"SYN-PKG-{query.criteria_hash()[12:24].upper()}"
        self.store.requests[request_id] = query
        self.store.packages.setdefault(package_id, _synthetic_metadata_package_bytes(query, package_id))
        self.store.verifications[request_id] = SatVerificationResult(
            request_id=request_id,
            state=SatRequestState.FINISHED,
            sat_code="5000",
            message="Synthetic request finished",
            package_ids=(package_id,),
            action=SatOutcomeAction.FINISHED,
            raw_response={"source": "synthetic"},
        )
        return SatRequestResult(
            request_id=request_id,
            sat_code="5000",
            message="Synthetic request accepted",
            action=SatOutcomeAction.ACCEPTED,
            raw_response={"source": "synthetic"},
        )


class FakeSatVerifier:
    """Deterministic offline implementation of ``SatVerificationPort``."""

    def __init__(self, store: FakeSatStore | None = None) -> None:
        self.store = store or FakeSatStore()

    def verify_request(self, request_id: str) -> SatVerificationResult:
        """Return synthetic verification state for one request id.

        Raises:
            SatVerificationError: If the request id is unknown to this store.
        """

        try:
            return self.store.verifications[request_id]
        except KeyError as exc:
            raise SatVerificationError(
                operation="verify",
                code="not-found",
                message="synthetic request id not found",
                retryable=False,
                next_action="submit the request with the same fake store before verifying",
                request_id=request_id,
            ) from exc


class FakeSatDownloader:
    """Deterministic offline implementation of ``SatDownloadPort``."""

    def __init__(self, store: FakeSatStore | None = None, packages: dict[str, bytes] | None = None) -> None:
        self.store = store or FakeSatStore()
        if packages:
            self.store.packages.update(packages)

    def download_package(self, package_id: str) -> SatDownloadResult:
        """Return caller-owned synthetic package bytes for one package id.

        Raises:
            SatPackageDownloadError: If the package id is unknown to this store.
        """

        try:
            content = self.store.packages[package_id]
        except KeyError as exc:
            raise SatPackageDownloadError(
                operation="download",
                code="not-found",
                message="synthetic package id not found",
                retryable=False,
                next_action="verify a finished synthetic request before downloading",
                package_id=package_id,
            ) from exc
        return SatDownloadResult(
            package_id=package_id,
            sat_code="5000",
            message="Synthetic package downloaded",
            action=SatOutcomeAction.FINISHED,
            content=bytes(content),
            raw_response={"source": "synthetic"},
        )


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


def _synthetic_metadata_package_bytes(query: DownloadQuery, package_id: str) -> bytes:
    entries = _fake_metadata_entries(query, package_id)
    buffer = BytesIO()
    with ZipFile(buffer, mode="w", compression=ZIP_DEFLATED) as archive:
        info = ZipInfo("metadata.txt", date_time=(2024, 1, 1, 0, 0, 0))
        info.compress_type = ZIP_DEFLATED
        info.create_system = 0
        info.external_attr = 0
        rows = [
            "uuid|issuer_rfc|receiver_rfc|total|status|source",
            *(
                f"{entry.uuid}|{entry.issuer_rfc}|{entry.receiver_rfc}|"
                f"{entry.total}|{entry.status}|synthetic"
                for entry in entries
            ),
        ]
        archive.writestr(info, "\n".join(rows).encode("utf-8"))
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
