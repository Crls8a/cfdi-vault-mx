"""Metadata-first simulated SAT orchestration service."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from cfdi_vault.domain import DownloadQuery
from cfdi_vault.ports import SatAuthenticatorPort, SatDownloadPort, SatRequestPort, SatVerificationPort
from cfdi_vault.reconciliation import ReconciliationDecision
from cfdi_vault.sat_contract import SatDownloadResult, SatOutcomeAction


class SatOrchestrationStatus(StrEnum):
    """High-level status for one simulated SAT orchestration run."""

    SKIPPED = "skipped"
    WAITING = "waiting"
    DOWNLOADED = "downloaded"
    RETRY = "retry"
    TERMINAL = "terminal"


@dataclass(frozen=True)
class SatOrchestrationResult:
    """Application-facing result for a metadata-first SAT run."""

    status: SatOrchestrationStatus
    action: SatOutcomeAction | None
    request_id: str | None = None
    downloaded_packages: tuple[SatDownloadResult, ...] = ()
    skipped_reason: str | None = None
    message: str = ""

    @property
    def should_retry(self) -> bool:
        return self.status == SatOrchestrationStatus.RETRY


class MetadataFirstSatOrchestrator:
    """Coordinates non-live SAT contracts without bypassing reconciliation."""

    def __init__(
        self,
        *,
        authenticator: SatAuthenticatorPort,
        requester: SatRequestPort,
        verifier: SatVerificationPort,
        downloader: SatDownloadPort,
    ) -> None:
        self.authenticator = authenticator
        self.requester = requester
        self.verifier = verifier
        self.downloader = downloader

    def run(self, query: DownloadQuery, decisions: Iterable[ReconciliationDecision]) -> SatOrchestrationResult:
        """Submit, verify, and download only when metadata says XML is needed."""

        pending_decisions = tuple(decision for decision in decisions if decision.should_download_xml)
        if not pending_decisions:
            return SatOrchestrationResult(
                status=SatOrchestrationStatus.SKIPPED,
                action=None,
                skipped_reason="metadata-first reconciliation does not require XML download",
                message="No SAT request was submitted.",
            )

        self.authenticator.authenticate()
        request = self.requester.submit_request(query)
        if request.action != SatOutcomeAction.ACCEPTED:
            return _result_from_action(request.action, request.message, request_id=request.request_id)

        verification = self.verifier.verify_request(request.request_id)
        if verification.action in {SatOutcomeAction.ACCEPTED, SatOutcomeAction.IN_PROGRESS}:
            return SatOrchestrationResult(
                status=SatOrchestrationStatus.WAITING,
                action=verification.action,
                request_id=request.request_id,
                message=verification.message,
            )
        if verification.action != SatOutcomeAction.FINISHED:
            return _result_from_action(verification.action, verification.message, request_id=request.request_id)

        downloaded: list[SatDownloadResult] = []
        for package_id in verification.package_ids:
            package = self.downloader.download_package(package_id)
            downloaded.append(package)
            if package.action != SatOutcomeAction.FINISHED:
                return _result_from_action(
                    package.action,
                    package.message,
                    request_id=request.request_id,
                    downloaded_packages=tuple(downloaded),
                )

        return SatOrchestrationResult(
            status=SatOrchestrationStatus.DOWNLOADED,
            action=SatOutcomeAction.FINISHED,
            request_id=request.request_id,
            downloaded_packages=tuple(downloaded),
            message=f"Downloaded {len(downloaded)} synthetic package(s).",
        )


def _result_from_action(
    action: SatOutcomeAction,
    message: str,
    *,
    request_id: str | None = None,
    downloaded_packages: tuple[SatDownloadResult, ...] = (),
) -> SatOrchestrationResult:
    status = SatOrchestrationStatus.RETRY if action == SatOutcomeAction.RETRY else SatOrchestrationStatus.TERMINAL
    return SatOrchestrationResult(
        status=status,
        action=action,
        request_id=request_id,
        downloaded_packages=downloaded_packages,
        message=message,
    )
