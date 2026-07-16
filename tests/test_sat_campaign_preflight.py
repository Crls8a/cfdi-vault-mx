from __future__ import annotations

import ast
import inspect
from dataclasses import replace
from pathlib import Path

import pytest

import cfdi_vault.sat_campaign_preflight as subject
from cfdi_vault.secrets import CredentialProviderError, DummySecretProvider
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus


class Provider:
    def __init__(self, outcome=True, scheme="windows-credential-manager") -> None:
        self.outcome = outcome
        self.provider_scheme = scheme
        self.calls = []

    def exists(self, reference, *, purpose):
        self.calls.append((reference, purpose))
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


def test_verified_evidence_uses_actual_phrase_reference_and_is_redacted_immutable(tmp_path) -> None:
    profile = _profile(tmp_path)
    provider = Provider()
    observed = []
    checks = _checks(observed)
    repo = tmp_path / "private-repo"
    evidence = subject.verify_campaign_preflight(
        environ={}, profile=profile, provider=provider, repo_root=repo, checks=checks)
    subject.validate_campaign_preflight_evidence(
        evidence, profile=profile, repo_root=repo, provider_scheme=provider.provider_scheme)

    reference, purpose = provider.calls[0]
    assert reference.uri == profile.phrase_ref
    assert purpose == "sat-campaign-preflight"
    assert all((evidence.profile_ready, evidence.credentials_ready, evidence.doctor_ok,
                evidence.scanner_passed, evidence.repo_clean))
    assert (observed[-1].profile_id, observed[-1].storage_root, observed[-1].repo_root) == \
        (profile.profile_id, profile.storage_root, repo)
    assert not hasattr(observed[-1], "phrase_ref")
    assert all(value not in repr(evidence) for value in (
        profile.rfc, profile.profile_id, profile.phrase_ref, str(profile.storage_root),
        str(repo), provider.provider_scheme))
    for name in ("repo_clean", "_CampaignPreflightEvidence__proof"):
        with pytest.raises(AttributeError):
            setattr(evidence, name, False)


@pytest.mark.parametrize("args", ((), (True,) * 8))
def test_direct_evidence_construction_is_denied(args) -> None:
    with pytest.raises(TypeError):
        subject.CampaignPreflightEvidence(*args)


@pytest.mark.parametrize("change", ("repo", "profile", "storage", "phrase", "provider"))
def test_evidence_rejects_cross_target_binding(tmp_path, change) -> None:
    profile, repo, provider = _profile(tmp_path), tmp_path / "repo", Provider()
    evidence = _verify(tmp_path, profile=profile, provider=provider, repo_root=repo)
    if change == "repo":
        repo = tmp_path / "other-repo"
    elif change == "profile":
        profile = replace(profile, profile_id="profile-other")
    elif change == "storage":
        profile = replace(profile, storage_root=tmp_path / "other-storage")
    elif change == "phrase":
        profile = replace(profile, phrase_ref="windows-credential-manager://other-phrase")
    else:
        provider.provider_scheme = "other-provider"
    with pytest.raises(subject.CampaignPreflightError, match="campaign-preflight-evidence-invalid"):
        subject.validate_campaign_preflight_evidence(
            evidence, profile=profile, repo_root=repo, provider_scheme=provider.provider_scheme)


@pytest.mark.parametrize("name", ("CI", "GITHUB_ACTIONS", "TF_BUILD"))
def test_truthy_ci_variants_fail_before_checks(name, tmp_path) -> None:
    observed = []
    checks = _checks(observed)

    with pytest.raises(subject.CampaignPreflightError, match="campaign-preflight-ci-forbidden"):
        _verify(tmp_path, environ={name: " yes "}, checks=checks)
    assert observed == []


@pytest.mark.parametrize("name", (
    "CFDI_VAULT_SAT_AUTH_ENDPOINT", "CFDI_VAULT_SAT_REQUEST_ENDPOINT",
    "CFDI_VAULT_SAT_VERIFY_ENDPOINT", "CFDI_VAULT_SAT_DOWNLOAD_ENDPOINT",
))
def test_even_empty_endpoint_override_fails_closed(name, tmp_path) -> None:
    with pytest.raises(subject.CampaignPreflightError,
                       match="campaign-preflight-endpoint-override-forbidden"):
        _verify(tmp_path, environ={name: ""})


@pytest.mark.parametrize(("provider", "reason"), (
    (None, "provider-required"), (DummySecretProvider(), "provider-required"),
    (Provider(False), "credential-missing"),
    (Provider(CredentialProviderError("private-ref")), "credential-unavailable"),
    (Provider(PermissionError("private-path")), "credential-unavailable"),
    (Provider(scheme="unsupported"), "provider-unsupported")))
def test_missing_dummy_or_failed_provider_is_sanitized(provider, reason, tmp_path) -> None:
    private = "private-path"
    with pytest.raises(subject.CampaignPreflightError,
                       match=f"campaign-preflight-{reason}") as captured:
        _verify(tmp_path, provider=provider, repo_root=tmp_path / private)
    assert private not in str(captured.value)


@pytest.mark.parametrize(("check", "reason"), (
    (subject.CampaignPreflightCheck.DOCTOR, "doctor-failed"),
    (subject.CampaignPreflightCheck.SCANNER, "scanner-failed"),
    (subject.CampaignPreflightCheck.CHECKOUT, "checkout-dirty"),
    (subject.CampaignPreflightCheck.IDENTITY, "lineage-invalid"),
    (subject.CampaignPreflightCheck.PROVIDER_RUNTIME, "platform-unsupported")))
def test_neutral_check_failures_have_fixed_reasons(check, reason, tmp_path) -> None:
    with pytest.raises(subject.CampaignPreflightError,
                       match=f"campaign-preflight-{reason}"):
        _verify(tmp_path, checks=_checks([], failed=check))


def test_profile_must_be_exact_ready_local_profile(tmp_path) -> None:
    profile = _profile(tmp_path, status=LocalProfileStatus.MISSING)
    with pytest.raises(subject.CampaignPreflightError, match="campaign-preflight-profile-not-ready"):
        _verify(tmp_path, profile=profile)


def test_checks_are_typed_and_exceptions_never_leak(tmp_path) -> None:
    checks = _checks([])
    checks[subject.CampaignPreflightCheck.DOCTOR] = lambda _target: True
    with pytest.raises(subject.CampaignPreflightError, match="campaign-preflight-check-invalid"):
        _verify(tmp_path, checks=checks)
    checks = _checks([])
    checks[subject.CampaignPreflightCheck.DOCTOR] = lambda _target: (_ for _ in ()).throw(
        OSError("private-path"))
    with pytest.raises(subject.CampaignPreflightError,
                       match="campaign-preflight-check-error") as captured:
        _verify(tmp_path, checks=checks)
    assert "private-path" not in str(captured.value)


def test_api_has_no_raw_readiness_flags_and_import_graph_is_neutral() -> None:
    forbidden_parameters = {"doctor_ok", "scanner_passed", "repo_clean", "profile_ready",
                            "credentials_ready", "authorized", "ready"}
    assert not forbidden_parameters & set(inspect.signature(
        subject.verify_campaign_preflight).parameters)
    tree = ast.parse(Path(subject.__file__).read_text(encoding="utf-8"))
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names} | {node.module or "" for node in ast.walk(tree)
                                             if isinstance(node, ast.ImportFrom)}
    assert not any(any(term in name for term in (
        "adapters.cli", "smoke", "probe", "diagnose", "live_gate", "live_permit",
    )) for name in imported)


def _profile(tmp_path, *, status=LocalProfileStatus.READY) -> LocalProfile:
    return LocalProfile(
        "profile-synthetic", "XAXX010101000", tmp_path / "private-storage",
        CredentialMode.COPIED, tmp_path / "certificate.cer", tmp_path / "key.key",
        "windows-credential-manager://cfdi-vault/synthetic-phrase", status, "a" * 64,
    )


def _verify(tmp_path, **changes):
    values = dict(environ={}, profile=_profile(tmp_path), provider=Provider(),
                  repo_root=tmp_path / "repo", checks=_checks([]))
    values.update(changes)
    return subject.verify_campaign_preflight(**values)


def _checks(observed, failed=None):
    checks = {}
    for kind in subject.CampaignPreflightCheck:
        result = subject.CampaignPreflightOutcome.FAILED if kind is failed else \
            subject.CampaignPreflightOutcome.PASSED
        def run(target, *, _kind=kind, _result=result):
            observed.append(target)
            return subject.CampaignPreflightCheckResult(_kind, _result)
        checks[kind] = run
    return checks
