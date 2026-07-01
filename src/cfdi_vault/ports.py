"""Ports for the CFDI recovery clean architecture."""

from __future__ import annotations

from typing import Protocol

from cfdi_vault.domain import CfdiStatusQuery, CfdiStatusResult, DownloadQuery, QueueMessage, UserFacingError
from cfdi_vault.sat_contract import SatAuthResult, SatDownloadResult, SatRequestResult, SatVerificationResult


class SignerPort(Protocol):
    """Signs SAT SOAP payloads without exposing credentials to callers."""

    def sign(self, xml_payload: bytes) -> bytes:
        """Return the signed XML payload."""


class SatClientPort(Protocol):
    """SAT SOAP operations used by the application layer."""

    def submit_request(self, query: DownloadQuery) -> str:
        """Submit a SAT request and return the SAT request id."""

    def verify_request(self, request_id: str) -> dict[str, object]:
        """Verify SAT request status."""

    def download_package(self, package_id: str) -> bytes:
        """Download raw package bytes."""


class SatAuthenticatorPort(Protocol):
    """SAT authentication boundary for non-live and future live adapters."""

    def authenticate(self) -> SatAuthResult:
        """Return normalized SAT authorization data without exposing secrets."""


class SatRequestPort(Protocol):
    """Boundary for submitting a SAT mass-download request."""

    def submit_request(self, query: DownloadQuery) -> SatRequestResult:
        """Submit one request and return a normalized SAT result."""


class SatVerificationPort(Protocol):
    """Boundary for checking asynchronous SAT request status."""

    def verify_request(self, request_id: str) -> SatVerificationResult:
        """Return request state and package identifiers if available."""


class SatDownloadPort(Protocol):
    """Boundary for downloading one SAT package payload."""

    def download_package(self, package_id: str) -> SatDownloadResult:
        """Download one package and return a normalized outcome."""


class CfdiStatusClientPort(Protocol):
    """Boundary for SAT CFDI status consultation.

    Production adapters must not be mixed into metadata parsing or local
    reconciliation. The application layer should call this only when the
    reconciliation policy marks a UUID as requiring status confirmation.
    """

    def query_status(self, query: CfdiStatusQuery) -> CfdiStatusResult:
        """Return normalized CFDI status details for one UUID."""


class QueuePort(Protocol):
    """Queue abstraction. RabbitMQ is the production adapter."""

    def publish(self, message: QueueMessage) -> None:
        """Publish one message."""

    def pending_count(self, queue_name: str | None = None) -> int:
        """Return pending message count when available."""


class CachePort(Protocol):
    """Fast transient cache abstraction. Redis is the production adapter."""

    def set_json(self, key: str, value: dict[str, object], ttl_seconds: int | None = None) -> None:
        """Store JSON-like data."""

    def get_json(self, key: str) -> dict[str, object] | None:
        """Read JSON-like data."""


class StoragePort(Protocol):
    """Raw package/XML storage abstraction."""

    def write_bytes(self, key: str, content: bytes) -> str:
        """Store bytes and return a storage reference."""


class SearchPort(Protocol):
    """Search abstraction backed by PostgreSQL in v1."""

    def search(self, text: str, *, limit: int = 20) -> list[dict[str, object]]:
        """Search CFDI documents."""


class PrinterPort(Protocol):
    """Invoice print/export abstraction."""

    def render_text(self, uuid: str) -> str:
        """Render an invoice for terminal or file output."""


class ErrorMapperPort(Protocol):
    """Maps low-level errors to user-facing payloads."""

    def map_error(self, error: Exception) -> UserFacingError:
        """Map an exception to a stable error payload."""
