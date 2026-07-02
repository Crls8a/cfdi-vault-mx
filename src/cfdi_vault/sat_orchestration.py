"""Metadata-first simulated SAT orchestration service."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Iterable

from cfdi_vault.domain import DownloadQuery, SatRequestState
from cfdi_vault.ports import SatAuthenticatorPort, SatDownloadPort, SatRequestPort, SatVerificationPort
from cfdi_vault.reconciliation import ReconciliationDecision
from cfdi_vault.sat_contract import SatDownloadResult, SatOutcomeAction, SatRequestResult


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


@dataclass(frozen=True)
class RegisteredSatRequest:
    """Offline registry row for one submitted SAT download request."""

    tenant_id: str
    criteria_hash: str
    request_id: str
    request_result: SatRequestResult
    state: SatRequestState | None = None
    action: SatOutcomeAction | None = None
    message: str = ""
    package_ids: tuple[str, ...] = ()


@dataclass
class InMemorySatRequestRegistry:
    """Alpha-test registry for SAT requests and verification outcomes."""

    _by_criteria: dict[tuple[str, str], RegisteredSatRequest] = field(default_factory=dict)
    _by_request_id: dict[str, RegisteredSatRequest] = field(default_factory=dict)

    def find_by_query(self, query: DownloadQuery) -> RegisteredSatRequest | None:
        return self._by_criteria.get((query.tenant_id, query.criteria_hash()))

    def register_submission(self, query: DownloadQuery, result: SatRequestResult) -> RegisteredSatRequest:
        existing = self.find_by_query(query)
        if existing is not None:
            return existing

        registered = RegisteredSatRequest(
            tenant_id=query.tenant_id,
            criteria_hash=query.criteria_hash(),
            request_id=result.request_id,
            request_result=result,
            action=result.action,
            message=result.message,
        )
        self._store(registered)
        return registered

    def get(self, request_id: str) -> RegisteredSatRequest:
        return self._by_request_id[request_id]

    def record_verification(
        self,
        *,
        request_id: str,
        state: SatRequestState,
        action: SatOutcomeAction,
        message: str,
        package_ids: tuple[str, ...] = (),
    ) -> RegisteredSatRequest:
        registered = self.get(request_id)
        merged_package_ids = _append_unique(registered.package_ids, package_ids)
        updated = replace(
            registered,
            state=state,
            action=action,
            message=message,
            package_ids=merged_package_ids if action == SatOutcomeAction.FINISHED else registered.package_ids,
        )
        self._store(updated)
        return updated

    def _store(self, registered: RegisteredSatRequest) -> None:
        key = (registered.tenant_id, registered.criteria_hash)
        self._by_criteria[key] = registered
        self._by_request_id[registered.request_id] = registered


class DownloadRequestOrchestrator:
    """Submits and verifies SAT requests without downloading package bytes."""

    def __init__(
        self,
        *,
        requester: SatRequestPort,
        verifier: SatVerificationPort,
        registry: InMemorySatRequestRegistry | None = None,
    ) -> None:
        self.requester = requester
        self.verifier = verifier
        self.registry = registry or InMemorySatRequestRegistry()

    def submit_once(self, query: DownloadQuery) -> RegisteredSatRequest:
        """Submit only when this tenant and criteria hash are not registered."""

        existing = self.registry.find_by_query(query)
        if existing is not None:
            return existing

        result = self.requester.submit_request(query)
        return self.registry.register_submission(query, result)

    def poll_once(self, request_id: str) -> RegisteredSatRequest:
        """Verify one registered request and persist state plus package ids."""

        verification = self.verifier.verify_request(request_id)
        package_ids = verification.package_ids if verification.action == SatOutcomeAction.FINISHED else ()
        return self.registry.record_verification(
            request_id=request_id,
            state=verification.state,
            action=verification.action,
            message=verification.message,
            package_ids=package_ids,
        )


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


def _append_unique(existing: tuple[str, ...], incoming: tuple[str, ...]) -> tuple[str, ...]:
    merged = list(existing)
    seen = set(existing)
    for package_id in incoming:
        if package_id not in seen:
            merged.append(package_id)
            seen.add(package_id)
    return tuple(merged)
