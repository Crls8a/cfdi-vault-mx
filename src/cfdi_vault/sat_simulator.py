"""Deterministic non-live SAT scenario client for contract tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum

from cfdi_vault.domain import DownloadQuery, SatRequestState
from cfdi_vault.sat_contract import (
    SatAuthResult,
    SatDownloadResult,
    SatOperation,
    SatOutcomeAction,
    SatRequestResult,
    SatVerificationResult,
    classify_sat_outcome,
)


class FakeSatScenario(StrEnum):
    """Scanner-safe scenarios for the simulated SAT mass-download flow."""

    REQUEST_ACCEPTED = "request_accepted"
    REQUEST_DUPLICATE = "request_duplicate"
    UNAUTHORIZED = "unauthorized"
    VERIFY_IN_PROCESS = "verify_in_process"
    VERIFY_FINISHED_WITH_PACKAGES = "verify_finished_with_packages"
    PACKAGE_EXPIRED = "package_expired"
    DOWNLOADS_EXHAUSTED = "downloads_exhausted"
    INTERNAL_RETRYABLE_ERROR = "internal_retryable_error"


@dataclass
class FakeSatScenarioClient:
    """Implements SAT contract ports with deterministic synthetic outcomes."""

    scenario: FakeSatScenario = FakeSatScenario.VERIFY_FINISHED_WITH_PACKAGES
    package_count: int = 2
    submitted_queries: list[DownloadQuery] = field(default_factory=list)
    verified_request_ids: list[str] = field(default_factory=list)
    downloaded_package_ids: list[str] = field(default_factory=list)

    def authenticate(self) -> SatAuthResult:
        """Return scanner-safe synthetic authorization data."""

        return SatAuthResult(
            authorization="SYNTHETIC_AUTHORIZATION",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
            raw_response={"soap": _synthetic_soap("authenticate", "5000")},
        )

    def submit_request(self, query: DownloadQuery) -> SatRequestResult:
        """Return a deterministic request outcome for the selected scenario."""

        self.submitted_queries.append(query)
        if self.scenario == FakeSatScenario.REQUEST_DUPLICATE:
            return _request_result("SYN-REQ-DUPLICATE", "5005", "Synthetic duplicate request")
        if self.scenario == FakeSatScenario.UNAUTHORIZED:
            return _request_result("SYN-REQ-UNAUTHORIZED", "5001", "Synthetic requester is not authorized")
        if self.scenario == FakeSatScenario.INTERNAL_RETRYABLE_ERROR:
            return _request_result("SYN-REQ-RETRY", "404", "Synthetic transient SAT error")
        return _request_result(f"SYN-REQ-{query.criteria_hash()[:12].upper()}", "5000", "Synthetic request accepted")

    def verify_request(self, request_id: str) -> SatVerificationResult:
        """Return a deterministic verification outcome for the selected scenario."""

        self.verified_request_ids.append(request_id)
        if self.scenario == FakeSatScenario.VERIFY_IN_PROCESS:
            return _verification_result(request_id, SatRequestState.IN_PROCESS, "5000", "Synthetic request in process", ())
        if self.scenario == FakeSatScenario.INTERNAL_RETRYABLE_ERROR:
            return _verification_result(request_id, SatRequestState.ERROR, "404", "Synthetic transient verification error", ())
        package_ids = tuple(f"SYN-PKG-{index:03d}" for index in range(1, self.package_count + 1))
        return _verification_result(request_id, SatRequestState.FINISHED, "5000", "Synthetic request finished", package_ids)

    def download_package(self, package_id: str) -> SatDownloadResult:
        """Return synthetic package bytes or a terminal download outcome."""

        self.downloaded_package_ids.append(package_id)
        if self.scenario == FakeSatScenario.PACKAGE_EXPIRED:
            return _download_result(package_id, "5007", "Synthetic package expired", None)
        if self.scenario == FakeSatScenario.DOWNLOADS_EXHAUSTED:
            return _download_result(package_id, "5008", "Synthetic package downloads exhausted", None)
        if self.scenario == FakeSatScenario.INTERNAL_RETRYABLE_ERROR:
            return _download_result(package_id, "404", "Synthetic transient download error", None)
        return _download_result(package_id, "5000", "Synthetic package downloaded", _synthetic_package_bytes(package_id))


def _request_result(request_id: str, sat_code: str, message: str) -> SatRequestResult:
    classification = classify_sat_outcome(SatOperation.REQUEST, sat_code=sat_code)
    return SatRequestResult(
        request_id=request_id,
        sat_code=sat_code,
        message=message,
        action=classification.action,
        raw_response={"soap": _synthetic_soap("request", sat_code), "reason": classification.reason},
    )


def _verification_result(
    request_id: str,
    state: SatRequestState,
    sat_code: str,
    message: str,
    package_ids: tuple[str, ...],
) -> SatVerificationResult:
    classification = classify_sat_outcome(SatOperation.VERIFY, sat_code=sat_code, state=state)
    return SatVerificationResult(
        request_id=request_id,
        state=state,
        sat_code=sat_code,
        message=message,
        package_ids=package_ids,
        action=classification.action,
        raw_response={"soap": _synthetic_soap("verify", sat_code), "reason": classification.reason},
    )


def _download_result(package_id: str, sat_code: str, message: str, content: bytes | None) -> SatDownloadResult:
    classification = classify_sat_outcome(SatOperation.DOWNLOAD, sat_code=sat_code)
    return SatDownloadResult(
        package_id=package_id,
        sat_code=sat_code,
        message=message,
        action=classification.action,
        content=content,
        raw_response={"soap": _synthetic_soap("download", sat_code), "reason": classification.reason},
    )


def _synthetic_soap(operation: str, sat_code: str) -> str:
    return f"<SyntheticEnvelope><Operation>{operation}</Operation><SatCode>{sat_code}</SatCode></SyntheticEnvelope>"


def _synthetic_package_bytes(package_id: str) -> bytes:
    return f"SYNTHETIC-PACKAGE::{package_id}\n".encode("utf-8")
