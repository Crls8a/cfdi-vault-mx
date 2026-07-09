"""Ports for the CFDI recovery clean architecture."""

from __future__ import annotations

from typing import Protocol

from cfdi_vault.cache_contract import ProgressObservation, WorkerHeartbeat
from cfdi_vault.domain import CfdiStatusQuery, CfdiStatusResult, DownloadQuery, QueueMessage, UserFacingError
from cfdi_vault.sat_contract import SatAuthResult, SatDownloadResult, SatRequestResult, SatVerificationResult
from cfdi_vault.sat_transport import SoapTransportPort
from cfdi_vault.secrets import CredentialAccessAuditEvent, CredentialReference, SecretValue
from cfdi_vault.storage_contract import EvidenceReference, StorageKey


class SignerPort(Protocol):
    """Signs SAT SOAP payloads without exposing credentials to callers."""

    def sign(self, xml_payload: bytes) -> bytes:
        """Return the signed XML payload."""


class SecretProviderPort(Protocol):
    """Resolves credential references without leaking values to config/logs."""

    @property
    def audit_events(self) -> tuple[CredentialAccessAuditEvent, ...]:
        """Return redacted audit events for resolution attempts."""

    def resolve(self, reference: CredentialReference, *, purpose: str) -> SecretValue:
        """Resolve a credential reference for immediate in-memory use."""


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
    """Transient coordination only; durable job truth remains in PostgreSQL."""

    def set_json(self, key: str, value: dict[str, object], ttl_seconds: int | None = None) -> None:
        """Store JSON-like data."""

    def get_json(self, key: str) -> dict[str, object] | None:
        """Read JSON-like data."""

    def acquire_lock(self, key: str, owner_id: str, ttl_seconds: int) -> bool:
        """Atomically acquire an expiring lock for one opaque owner token."""

    def renew_lock(self, key: str, owner_id: str, ttl_seconds: int) -> bool:
        """Atomically extend a lock only when the owner token matches."""

    def release_lock(self, key: str, owner_id: str) -> bool:
        """Atomically release a lock only when the owner token matches."""

    def set_progress(self, observation: ProgressObservation, ttl_seconds: int) -> None:
        """Store a validated reference-only progress observation."""

    def get_progress(self, tenant_id: str, job_id: str) -> ProgressObservation | None:
        """Return transient progress, or None when absent/expired."""

    def record_heartbeat(self, heartbeat: WorkerHeartbeat, ttl_seconds: int) -> None:
        """Store a validated worker heartbeat with finite lifetime."""

    def get_heartbeat(self, worker_id: str) -> WorkerHeartbeat | None:
        """Return a transient heartbeat, or None when absent/expired."""


class StoragePort(Protocol):
    """Raw evidence storage abstraction.

    Implementations store bytes separately from the stable, indexable metadata
    returned to application code.
    """

    def write_bytes_idempotent(self, key: str | StorageKey, content: bytes) -> EvidenceReference:
        """Store bytes once and return their stable reference metadata."""

    def read_bytes(self, key: str | StorageKey) -> bytes:
        """Read bytes without exposing an adapter-specific local path."""

    def stat(self, key: str | StorageKey) -> EvidenceReference:
        """Return hash and size metadata without returning evidence bytes."""


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
