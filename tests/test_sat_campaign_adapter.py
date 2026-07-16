from __future__ import annotations

import ast
import inspect
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

import cfdi_vault.sat_campaign_adapter as subject
from cfdi_vault.sat_campaign_grant import CampaignGrant, CampaignGrantError, campaign_manifest_digest
from cfdi_vault.sat_campaign_manifest import build_campaign_manifest
from cfdi_vault.sat_campaign_preflight import (
    CampaignPreflightCheck,
    CampaignPreflightCheckResult,
    CampaignPreflightOutcome,
    verify_campaign_preflight,
)
from cfdi_vault.sat_v15_contract import SatV15Endpoints
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus


class Provider:
    provider_scheme = "windows-credential-manager"

    def __init__(self) -> None:
        self.calls: list[str] = []

    def exists(self, _reference, *, purpose):
        self.calls.append(purpose)
        return True

    def store(self, *_args, **_kwargs):
        raise AssertionError("provider storage is not part of adapter construction")

    def resolve(self, *_args, **_kwargs):
        raise AssertionError("credential resolution must remain lazy")


def test_factory_is_lazy_fresh_and_builds_only_canonical_metadata_adapter(tmp_path) -> None:
    ctx = _context(tmp_path)
    factory = subject.build_campaign_metadata_request_factory(**ctx["arguments"])
    assert ctx["counts"] == {"grant": 0, "profile": 0, "provider": 0}

    first, second = factory(), factory()

    assert first is not second
    assert ctx["counts"] == {"grant": 2, "profile": 2, "provider": 2}
    kwargs = ctx["adapters"][-1]
    assert kwargs["material"] is None
    assert kwargs["endpoints"] == SatV15Endpoints()
    assert kwargs["max_range_days"] == 14
    assert kwargs["_credential_purpose"] == "sat-campaign-metadata"
    assert ctx["provider"].calls == []
    guard = ctx["guards"][-1]()
    assert guard.campaign_grant_verified is True
    assert guard.campaign_grant_allows_real_credentials is True
    assert guard.live_permit_verified is False
    assert guard.live_permit_allows_real_credentials is False
    assert guard.manual_real_sat is False
    assert all((guard.profile_ready, guard.credentials_ready, guard.doctor_ok,
                guard.scanner_passed, guard.repo_clean, guard.metadata_only,
                guard.range_within_limit))


@pytest.mark.parametrize("name", (
    "CI", "GITHUB_ACTIONS", "TF_BUILD", "CFDI_VAULT_SAT_AUTH_ENDPOINT",
    "CFDI_VAULT_SAT_REQUEST_ENDPOINT", "CFDI_VAULT_SAT_VERIFY_ENDPOINT",
    "CFDI_VAULT_SAT_DOWNLOAD_ENDPOINT",
))
def test_canonical_environment_fails_before_load_or_provider(tmp_path, name) -> None:
    ctx = _context(tmp_path)
    ctx["environment"][name] = "1" if name in {"CI", "GITHUB_ACTIONS", "TF_BUILD"} else ""
    factory = subject.build_campaign_metadata_request_factory(**ctx["arguments"])
    with pytest.raises(subject.CampaignAdapterError, match="campaign-adapter-environment-invalid"):
        factory()
    assert ctx["counts"] == {"grant": 0, "profile": 0, "provider": 0}


def test_transport_guard_rechecks_environment_on_every_send_boundary(tmp_path) -> None:
    ctx = _context(tmp_path)
    subject.build_campaign_metadata_request_factory(**ctx["arguments"])()
    ctx["environment"]["CFDI_VAULT_SAT_VERIFY_ENDPOINT"] = ""
    with pytest.raises(subject.CampaignAdapterError, match="campaign-adapter-environment-invalid"):
        ctx["guards"][-1]()


@pytest.mark.parametrize("change", (
    "future", "expired", "grant-lineage", "grant-profile", "grant-budget", "changed-commit", "profile",
    "profile-not-ready", "phrase", "unsupported-provider",
))
def test_stale_or_cross_lineage_state_fails_closed_before_credential_use(tmp_path, change) -> None:
    ctx = _context(tmp_path)
    now, grant, profile = ctx["now"], ctx["grant"], ctx["profile"]
    if change == "future":
        ctx["grant"] = replace(grant, created_at=now + timedelta(seconds=1))
    elif change == "expired":
        ctx["grant"] = replace(grant, expires_at=now)
    elif change == "grant-lineage":
        ctx["grant"] = replace(grant, campaign_ref="cmp-000000000000")
    elif change == "grant-profile":
        ctx["grant"] = replace(grant, profile_id="other-profile")
    elif change == "grant-budget":
        ctx["grant"] = replace(grant, max_outstanding=1)
    elif change == "changed-commit":
        ctx["grant_error"] = CampaignGrantError("campaign-grant-commit-mismatch")
    elif change == "profile":
        ctx["profile"] = replace(profile, profile_id="other-profile")
    elif change == "profile-not-ready":
        ctx["profile"] = replace(profile, status=LocalProfileStatus.MISSING)
    elif change == "phrase":
        ctx["profile"] = replace(profile, phrase_ref="windows-credential-manager://changed")
    else:
        ctx["provider"].provider_scheme = "unsupported"
    factory = subject.build_campaign_metadata_request_factory(**ctx["arguments"])
    with pytest.raises(subject.CampaignAdapterError) as captured:
        factory()
    assert captured.value.reason.startswith("campaign-adapter-")
    assert ctx["provider"].calls == []
    if change not in {"unsupported-provider"}:
        assert ctx["counts"]["provider"] == 0


def test_surface_is_redacted_and_has_no_experimental_or_authority_inputs() -> None:
    parameters = inspect.signature(subject.build_campaign_metadata_request_factory).parameters
    assert not {"tested_commit", "readiness", "authority", "permit"} & set(parameters)
    tree = ast.parse(inspect.getsource(subject))
    imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    forbidden = ("adapters.cli", "smoke", "probe", "diagnose", "live_gate", "live_permit")
    assert not any(token in name for name in imports for token in forbidden)
    error = subject.CampaignAdapterError("campaign-adapter-profile-invalid")
    assert "private-profile" not in repr(error)


def _context(tmp_path):
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)
    profile = LocalProfile(
        "profile-one", "XAXX010101000", tmp_path / "private-storage",
        CredentialMode.COPIED, tmp_path / "certificate", tmp_path / "key",
        "windows-credential-manager://cfdi-vault/private-phrase",
        LocalProfileStatus.READY, "a" * 64,
    )
    manifest = build_campaign_manifest(profile.profile_id)
    grant = CampaignGrant(
        "grt-" + "a" * 24, manifest.campaign_ref, campaign_manifest_digest(manifest),
        "b" * 40, profile.profile_id, now - timedelta(minutes=1),
        now + timedelta(days=1), "synthetic-test",
    )
    provider, environment = Provider(), {}
    checks = {check: (lambda target, check=check: CampaignPreflightCheckResult(
        check, CampaignPreflightOutcome.PASSED)) for check in CampaignPreflightCheck}
    evidence = verify_campaign_preflight(
        environ=environment, profile=profile, provider=provider,
        repo_root=tmp_path / "private-repo", checks=checks,
    )
    provider.calls.clear()
    ctx = {"now": now, "grant": grant, "grant_error": None, "profile": profile,
           "provider": provider, "environment": environment,
           "counts": {"grant": 0, "profile": 0, "provider": 0},
           "guards": [], "adapters": []}

    def grant_loader(*_args, **_kwargs):
        ctx["counts"]["grant"] += 1
        if ctx["grant_error"]:
            raise ctx["grant_error"]
        return ctx["grant"]

    def profile_loader(_profile_id):
        ctx["counts"]["profile"] += 1
        return ctx["profile"]

    def provider_selector(_profile):
        ctx["counts"]["provider"] += 1
        return ctx["provider"]

    def transport_factory(*, guard_input_factory):
        ctx["guards"].append(guard_input_factory)
        return object()

    def adapter_factory(**kwargs):
        ctx["adapters"].append(kwargs)
        return object()

    ctx["arguments"] = dict(
        storage_root=profile.storage_root, repo_root=tmp_path / "private-repo",
        manifest=manifest, grant_ref=grant.grant_ref, evidence=evidence,
        environ=environment, provider_selector=provider_selector,
        grant_loader=grant_loader, profile_loader=profile_loader,
        transport_factory=transport_factory, adapter_factory=adapter_factory,
        now=lambda: now,
    )
    return ctx
