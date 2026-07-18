"""Validate injected campaign readiness without authorization, mutation, or SAT I/O."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from cfdi_vault.secrets import (
    CredentialKind,
    CredentialReference,
    DummySecretProvider,
)
from cfdi_vault.setup_core import ExistenceProvider, LocalProfile, LocalProfileStatus

_CI_NAMES = ("CI", "GITHUB_ACTIONS", "TF_BUILD")
_FALSE_CI_VALUES = frozenset({"", "0", "false", "no", "off"})
_ENDPOINT_OVERRIDES = (
    "CFDI_VAULT_SAT_AUTH_ENDPOINT", "CFDI_VAULT_SAT_REQUEST_ENDPOINT",
    "CFDI_VAULT_SAT_VERIFY_ENDPOINT", "CFDI_VAULT_SAT_DOWNLOAD_ENDPOINT")
_SUPPORTED_PROVIDER_SCHEMES = frozenset({
    "windows-credential-manager",
    "macos-keychain",
    "linux-secret-service",
    "linux-kwallet",
})
_EVIDENCE_SEAL = object()


class CampaignPreflightError(ValueError):
    """Reject unsafe readiness using one fixed, sanitized reason code."""
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class CampaignPreflightCheck(StrEnum):
    """Injected checks required before any campaign state mutation."""
    PROVIDER_RUNTIME = "provider_runtime"
    DOCTOR = "doctor"
    SCANNER = "scanner"
    CHECKOUT = "checkout"
    IDENTITY = "identity"


class CampaignPreflightOutcome(StrEnum):
    """Closed outcome vocabulary for injected neutral checks."""
    PASSED = "passed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class CampaignPreflightCheckResult:
    """Typed result returned by an injected readiness check."""
    check: CampaignPreflightCheck
    outcome: CampaignPreflightOutcome


@dataclass(frozen=True, slots=True, repr=False)
class CampaignPreflightTarget:
    """Private exact lineage presented only to injected neutral checks."""
    profile_id: str
    repo_root: Path
    storage_root: Path
    provider_scheme: str


class CampaignPreflightEvidence:
    """Redacted immutable readiness sufficient for a later transport guard."""
    __slots__ = ("__proof",)
    profile_ready = credentials_ready = doctor_ok = scanner_passed = True
    repo_clean = runtime_ready = identity_verified = canonical_environment = True
    def __init__(self) -> None:
        raise TypeError("campaign-preflight-evidence-construction-denied")

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("campaign-preflight-evidence-immutable")

    def _matches(self, binding: bytes) -> bool:
        return self.__proof[0] is _EVIDENCE_SEAL and hmac.compare_digest(self.__proof[1], binding)

    def __repr__(self) -> str:
        return "CampaignPreflightEvidence(<verified>)"


NeutralCheck = Callable[[CampaignPreflightTarget], CampaignPreflightCheckResult]


def verify_campaign_preflight(
    *,
    environ: Mapping[str, str],
    profile: LocalProfile,
    provider: ExistenceProvider | None,
    repo_root: Path,
    checks: Mapping[CampaignPreflightCheck, NeutralCheck],
) -> CampaignPreflightEvidence:
    """Validate typed checks and the profile's exact provider-backed phrase reference."""
    _validate_environment(environ)
    if type(profile) is not LocalProfile:
        _deny("campaign-preflight-profile-invalid")
    if profile.status is not LocalProfileStatus.READY:
        _deny("campaign-preflight-profile-not-ready")
    if not isinstance(repo_root, Path):
        _deny("campaign-preflight-lineage-invalid")
    provider_scheme, exists = _validate_provider(profile, provider)
    target = CampaignPreflightTarget(profile.profile_id, repo_root, profile.storage_root, provider_scheme)
    _validate_checks(checks, target)
    try:
        reference = CredentialReference(profile.phrase_ref, CredentialKind.PHRASE)
        present = exists(reference, purpose="sat-campaign-preflight")
    except Exception:
        _deny("campaign-preflight-credential-unavailable")
    if present is False:
        _deny("campaign-preflight-credential-missing")
    if present is not True:
        _deny("campaign-preflight-provider-unsupported")
    return _new_evidence(_target_binding(target, profile.phrase_ref))


def validate_campaign_preflight_evidence(
    evidence: object, *, profile: LocalProfile, repo_root: Path, provider_scheme: str,
) -> None:
    """Reject forged or cross-target evidence without exposing its opaque binding."""
    try:
        target = CampaignPreflightTarget(profile.profile_id, repo_root, profile.storage_root, provider_scheme)
        valid = (type(evidence) is CampaignPreflightEvidence
                 and evidence._matches(_target_binding(target, profile.phrase_ref)))
    except Exception:
        valid = False
    if not valid:
        _deny("campaign-preflight-evidence-invalid")


def validate_campaign_environment(environ: Mapping[str, str]) -> None:
    """Recheck canonical campaign environment policy without other preflight work."""
    _validate_environment(environ)


def _target_binding(target: CampaignPreflightTarget, phrase_ref: str) -> bytes:
    private = json.dumps([target.profile_id, str(target.repo_root), str(target.storage_root),
                          target.provider_scheme, phrase_ref], separators=(",", ":")).encode()
    return hashlib.sha256(private).digest()


def _new_evidence(binding: bytes) -> CampaignPreflightEvidence:
    evidence = object.__new__(CampaignPreflightEvidence)
    object.__setattr__(evidence, "_CampaignPreflightEvidence__proof", (_EVIDENCE_SEAL, binding))
    return evidence


def _validate_environment(environ: Mapping[str, str]) -> None:
    try:
        if not isinstance(environ, Mapping):
            raise TypeError
        ci_forbidden = False
        for name in _CI_NAMES:
            value = environ.get(name)
            if value is not None and (
                not isinstance(value, str)
                or value.strip().casefold() not in _FALSE_CI_VALUES
            ):
                ci_forbidden = True
        endpoint_override = any(name in environ for name in _ENDPOINT_OVERRIDES)
    except Exception:
        _deny("campaign-preflight-environment-invalid")
    if ci_forbidden:
        _deny("campaign-preflight-ci-forbidden")
    if endpoint_override:
        _deny("campaign-preflight-endpoint-override-forbidden")


def _validate_provider(profile: LocalProfile, provider: ExistenceProvider | None):
    if provider is None or isinstance(provider, DummySecretProvider):
        _deny("campaign-preflight-provider-required")
    try:
        reference_scheme = CredentialReference(
            profile.phrase_ref, CredentialKind.PHRASE,
        ).provider_scheme
        provider_scheme = provider.provider_scheme  # type: ignore[attr-defined]
        exists = provider.exists
    except Exception:
        _deny("campaign-preflight-provider-unsupported")
    if (reference_scheme not in _SUPPORTED_PROVIDER_SCHEMES
            or provider_scheme != reference_scheme or not callable(exists)):
        _deny("campaign-preflight-provider-unsupported")
    return provider_scheme, exists


def _validate_checks(
    checks: Mapping[CampaignPreflightCheck, NeutralCheck],
    target: CampaignPreflightTarget,
) -> None:
    failures = {
        CampaignPreflightCheck.PROVIDER_RUNTIME: "campaign-preflight-platform-unsupported",
        CampaignPreflightCheck.DOCTOR: "campaign-preflight-doctor-failed",
        CampaignPreflightCheck.SCANNER: "campaign-preflight-scanner-failed",
        CampaignPreflightCheck.CHECKOUT: "campaign-preflight-checkout-dirty",
        CampaignPreflightCheck.IDENTITY: "campaign-preflight-lineage-invalid",
    }
    try:
        valid = isinstance(checks, Mapping) and set(checks) == set(CampaignPreflightCheck)
    except Exception:
        _deny("campaign-preflight-check-error")
    if not valid:
        _deny("campaign-preflight-check-invalid")
    for kind in CampaignPreflightCheck:
        try:
            result = checks[kind](target)
        except Exception:
            _deny("campaign-preflight-check-error")
        if type(result) is not CampaignPreflightCheckResult or result.check is not kind:
            _deny("campaign-preflight-check-invalid")
        if result.outcome is CampaignPreflightOutcome.FAILED:
            _deny(failures[kind])
        if result.outcome is not CampaignPreflightOutcome.PASSED:
            _deny("campaign-preflight-check-invalid")


def _deny(reason: str):
    raise CampaignPreflightError(reason) from None
