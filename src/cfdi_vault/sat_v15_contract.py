"""Internal SAT v1.5 wire constants and endpoint routing.

This module owns neutral operation names, SOAP actions, and canonical service
endpoints. It does not build envelopes, perform transport, or expose a stable
package API.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from cfdi_vault.sat_auth_constants import AUTH_SOAP_ACTION
from cfdi_vault.sat_auth_endpoints import DEFAULT_AUTH_ENDPOINT

SAT_REQUEST_NS = "http://DescargaMasivaTerceros.sat.gob.mx"
AUTH_ACTION = AUTH_SOAP_ACTION
REQUEST_ACTION_BASE = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService"
VERIFY_ACTION = "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga"
DOWNLOAD_ACTION = "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar"

DEFAULT_REQUEST_ENDPOINT = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc"
DEFAULT_VERIFY_ENDPOINT = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc"
DEFAULT_DOWNLOAD_ENDPOINT = "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc"


class SatV15RequestOperation(StrEnum):
    """Specialized request operations defined by the SAT v1.5 wire contract."""

    ISSUED = "SolicitaDescargaEmitidos"
    RECEIVED = "SolicitaDescargaRecibidos"
    FOLIO = "SolicitaDescargaFolio"


@dataclass(frozen=True)
class SatV15Endpoints:
    """Canonical SAT v1.5 endpoints in transport execution order."""

    auth: str = DEFAULT_AUTH_ENDPOINT
    request: str = DEFAULT_REQUEST_ENDPOINT
    verify: str = DEFAULT_VERIFY_ENDPOINT
    download: str = DEFAULT_DOWNLOAD_ENDPOINT


def v15_request_soap_action(operation: SatV15RequestOperation) -> str:
    """Return the SOAP action for one specialized SAT v1.5 request."""

    return f"{REQUEST_ACTION_BASE}/{operation.value}"
