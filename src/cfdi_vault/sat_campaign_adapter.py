"""Lazy, grant-bound construction of the internal SAT v1.5 Metadata adapter."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path

from cfdi_vault.ports import SatRequestPort
from cfdi_vault.sat_campaign_grant import (
    CampaignGrant,
    campaign_manifest_digest,
    load_campaign_grant,
)
from cfdi_vault.sat_campaign_manifest import MAX_OUTSTANDING, SatCampaignManifest
from cfdi_vault.sat_campaign_preflight import (
    CampaignPreflightEvidence,
    validate_campaign_environment,
    validate_campaign_preflight_evidence,
)
from cfdi_vault.sat_transport import GuardedSoapHttpTransport, LiveSatGuardInput, SoapTransportPort
from cfdi_vault.sat_v15_adapter import SatV15Adapter
from cfdi_vault.sat_v15_contract import SatV15Endpoints
from cfdi_vault.secrets import CredentialKind, CredentialReference, DummySecretProvider
from cfdi_vault.setup_core import ExistenceProvider, LocalProfile, LocalProfileStatus, load_profile

GrantLoader = Callable[[str | Path, str, str | Path, datetime | None], CampaignGrant]
ProfileLoader = Callable[[str], LocalProfile]
ProviderSelector = Callable[[LocalProfile], ExistenceProvider]
TransportFactory = Callable[..., SoapTransportPort]
AdapterFactory = Callable[..., SatRequestPort]


class CampaignAdapterError(ValueError):
    """Reject unsafe adapter construction using one fixed sanitized reason."""
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def build_campaign_metadata_request_factory(
    *, storage_root: Path, repo_root: Path, manifest: SatCampaignManifest,
    grant_ref: str, evidence: CampaignPreflightEvidence, environ: Mapping[str, str],
    provider_selector: ProviderSelector, grant_loader: GrantLoader = load_campaign_grant,
    profile_loader: ProfileLoader = load_profile,
    transport_factory: TransportFactory = GuardedSoapHttpTransport,
    adapter_factory: AdapterFactory = SatV15Adapter,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> Callable[[], SatRequestPort]:
    """Return a side-effect-free factory that revalidates all authority on each call."""
    def build() -> SatRequestPort:
        _environment(environ)
        current_time = _current_time(now)
        grant = _load_grant(grant_loader, storage_root, grant_ref, repo_root, current_time)
        _validate_grant(grant, grant_ref, manifest, current_time)
        profile = _load_profile(profile_loader, manifest.profile_id)
        scheme = _validate_profile(profile, manifest, storage_root)
        _evidence(evidence, profile, repo_root, scheme)
        provider = _provider(provider_selector, profile, scheme)

        def guard_input() -> LiveSatGuardInput:
            _environment(environ)
            return LiveSatGuardInput(
                profile_ready=evidence.profile_ready,
                credentials_ready=evidence.credentials_ready,
                doctor_ok=evidence.doctor_ok,
                scanner_passed=evidence.scanner_passed,
                repo_clean=evidence.repo_clean,
                metadata_only=True, range_within_limit=True,
                campaign_grant_verified=True,
                campaign_grant_allows_real_credentials=True,
                environ=environ,
            )

        try:
            transport = transport_factory(guard_input_factory=guard_input)
            return adapter_factory(
                profile=profile, provider=provider, transport=transport, material=None,
                endpoints=SatV15Endpoints(), max_range_days=14,
                _credential_purpose="sat-campaign-metadata",
            )
        except Exception:
            raise CampaignAdapterError("campaign-adapter-construction-failed") from None
    return build


def _environment(environ: Mapping[str, str]) -> None:
    try:
        validate_campaign_environment(environ)
    except Exception:
        raise CampaignAdapterError("campaign-adapter-environment-invalid") from None


def _current_time(now: Callable[[], datetime]) -> datetime:
    try:
        value = now()
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise TypeError
        return value.astimezone(timezone.utc)
    except Exception:
        raise CampaignAdapterError("campaign-adapter-time-invalid") from None


def _load_grant(loader: GrantLoader, storage: Path, ref: str, repo: Path,
                now: datetime) -> CampaignGrant:
    try:
        grant = loader(storage, ref, repo, now)
    except Exception:
        raise CampaignAdapterError("campaign-adapter-grant-load-failed") from None
    if type(grant) is not CampaignGrant:
        raise CampaignAdapterError("campaign-adapter-grant-invalid")
    return grant


def _validate_grant(grant: CampaignGrant, ref: str, manifest: SatCampaignManifest,
                    now: datetime) -> None:
    try:
        active = grant.created_at <= now < grant.expires_at
        lineage = (
            grant.grant_ref == ref and grant.phase == "metadata-proof"
            and grant.campaign_ref == manifest.campaign_ref
            and grant.profile_id == manifest.profile_id
            and grant.manifest_digest == campaign_manifest_digest(manifest)
            and grant.max_outstanding == MAX_OUTSTANDING
            and grant.redaction_required is True
        )
    except Exception:
        active = lineage = False
    if not active:
        raise CampaignAdapterError("campaign-adapter-grant-not-active")
    if not lineage:
        raise CampaignAdapterError("campaign-adapter-grant-lineage-invalid")


def _load_profile(loader: ProfileLoader, profile_id: str) -> LocalProfile:
    try:
        profile = loader(profile_id)
    except Exception:
        raise CampaignAdapterError("campaign-adapter-profile-load-failed") from None
    if type(profile) is not LocalProfile:
        raise CampaignAdapterError("campaign-adapter-profile-invalid")
    return profile


def _validate_profile(profile: LocalProfile, manifest: SatCampaignManifest,
                      storage: Path) -> str:
    try:
        scheme = CredentialReference(profile.phrase_ref, CredentialKind.PHRASE).provider_scheme
    except Exception:
        raise CampaignAdapterError("campaign-adapter-provider-unsupported") from None
    if (profile.profile_id != manifest.profile_id or profile.storage_root != storage
            or profile.status is not LocalProfileStatus.READY):
        raise CampaignAdapterError("campaign-adapter-profile-invalid")
    return scheme


def _evidence(evidence: object, profile: LocalProfile, repo: Path, scheme: str) -> None:
    try:
        validate_campaign_preflight_evidence(
            evidence, profile=profile, repo_root=repo, provider_scheme=scheme)
    except Exception:
        raise CampaignAdapterError("campaign-adapter-evidence-invalid") from None


def _provider(selector: ProviderSelector, profile: LocalProfile,
              scheme: str) -> ExistenceProvider:
    try:
        provider = selector(profile)
        valid = (not isinstance(provider, DummySecretProvider)
                 and provider.provider_scheme == scheme  # type: ignore[attr-defined]
                 and all(callable(getattr(provider, name)) for name in ("store", "exists", "resolve")))
    except Exception:
        valid = False
    if not valid:
        raise CampaignAdapterError("campaign-adapter-provider-unsupported")
    return provider
