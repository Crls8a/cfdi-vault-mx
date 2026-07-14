"""Import-first SAT v1.5 facade with an explicitly offline default.

This public module composes the documented request, result, error, port, and
fake contracts. Importing it reads no environment variables, credentials,
certificates, files, or configuration and performs no network or persistence
work. It never selects a live adapter; callers that inject their own port
implementations own and must document those implementations' side effects.

Use :func:`create_offline_facade` for the credential-free deterministic path.
Live SAT gates, probes, transports, signing, SOAP envelopes, storage, CLI, and
reference-system orchestration are intentionally outside this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cfdi_vault.domain import DownloadQuery
from cfdi_vault.fake_sat import (
    FakeSatAuthenticator,
    FakeSatDownloader,
    FakeSatRequester,
    FakeSatStore,
    FakeSatVerifier,
)
from cfdi_vault.ports import (
    SatAuthenticatorPort,
    SatDownloadPort,
    SatRequestPort,
    SatVerificationPort,
)
from cfdi_vault.sat_contract import (
    SatAuthResult,
    SatDownloadResult,
    SatRequestResult,
    SatVerificationResult,
)

__all__ = [
    "SatDownloadFacade",
    "create_offline_facade",
]


@dataclass(frozen=True, slots=True)
class SatDownloadFacade:
    """Delegate the four SAT stages to explicit caller-injected ports.

    Constructing the facade has no side effects. Each method delegates exactly
    one operation and returns its normalized result. Exceptions and operational
    side effects are those documented by the injected port implementation; the
    facade does not catch, log, serialize, or persist sensitive values.

    Use :func:`create_offline_facade` when the caller requires the guaranteed
    credential-free, network-free fake implementation.
    """

    authenticator: SatAuthenticatorPort = field(repr=False)
    requester: SatRequestPort = field(repr=False)
    verifier: SatVerificationPort = field(repr=False)
    downloader: SatDownloadPort = field(repr=False)

    def authenticate(self) -> SatAuthResult:
        """Return the injected authenticator's normalized result.

        The facade itself performs no I/O. ``SatAuthenticationError`` and any
        adapter-specific side effects belong to the injected implementation.
        """

        return self.authenticator.authenticate()

    def submit_request(self, query: DownloadQuery) -> SatRequestResult:
        """Submit validated criteria through the injected request port.

        Args:
            query: Typed SAT v1.5 request criteria.

        Returns:
            The normalized request result.

        Raises:
            SatRequestError: If the injected port rejects the request.
        """

        return self.requester.submit_request(query)

    def verify_request(self, request_id: str) -> SatVerificationResult:
        """Verify one caller-owned request reference through the injected port.

        Args:
            request_id: Opaque request reference. The facade never logs it.

        Returns:
            Normalized request state and package references.

        Raises:
            SatVerificationError: If the injected port cannot verify the request.
        """

        return self.verifier.verify_request(request_id)

    def download_package(self, package_id: str) -> SatDownloadResult:
        """Delegate one caller-owned package reference to the injected port.

        Args:
            package_id: Opaque package reference. The facade never logs it.

        Returns:
            A normalized package result. Content remains caller-owned and is
            redacted by the result's diagnostics.

        Raises:
            SatPackageDownloadError: If the injected port cannot return it.
        """

        return self.downloader.download_package(package_id)


def create_offline_facade(store: FakeSatStore | None = None) -> SatDownloadFacade:
    """Create a deterministic SAT v1.5 facade backed only by in-memory fakes.

    Args:
        store: Optional caller-owned synthetic store shared by all fake ports.

    Returns:
        A credential-free, environment-free, network-free facade.

    This function performs no I/O and never constructs live, transport,
    signing, storage, database, broker, cache, or CLI adapters.
    """

    shared_store = store or FakeSatStore()
    return SatDownloadFacade(
        authenticator=FakeSatAuthenticator(),
        requester=FakeSatRequester(shared_store),
        verifier=FakeSatVerifier(shared_store),
        downloader=FakeSatDownloader(shared_store),
    )
