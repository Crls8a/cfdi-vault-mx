from __future__ import annotations

import ast
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import cfdi_vault.adapters.cli.sat_campaign_runtime as subject
from cfdi_vault.sat_campaign_preflight import (
    CampaignPreflightCheck as Check,
)
from cfdi_vault.sat_campaign_preflight import (
    CampaignPreflightOutcome as Outcome,
)
from cfdi_vault.sat_campaign_preflight import (
    CampaignPreflightTarget,
)
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus


class Provider:
    provider_scheme = "windows-credential-manager"

    def __init__(self, scheme: str | None = None) -> None:
        if scheme is not None:
            self.provider_scheme = scheme

    def exists(self, _reference, *, purpose):
        return purpose == "setup-status"


class Runner:
    def __init__(self, *, scanner=0, status="", commit="a" * 40) -> None:
        self.scanner, self.status, self.commit, self.calls = scanner, status, commit, []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if command[0] == sys.executable:
            return SimpleNamespace(returncode=self.scanner, stdout=None)
        output = self.status if command[1:3] == ["status", "--short"] else self.commit + "\n"
        return SimpleNamespace(returncode=0, stdout=output)


class HungRunner:
    def __init__(self) -> None:
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    scripts = root / "scripts"
    scripts.mkdir()
    for name in ("scan_sensitive_fixtures.py", "scan_sat_context.py"):
        (scripts / name).write_text("# synthetic\n", encoding="utf-8")
    return root.resolve()


def _profile(tmp_path: Path, *, scheme="windows-credential-manager") -> LocalProfile:
    return LocalProfile(
        "profile-synthetic", "XAXX010101000", (tmp_path / "private").resolve(),
        CredentialMode.COPIED, tmp_path / "certificate.cer", tmp_path / "key.key",
        f"{scheme}://cfdi-vault/synthetic-phrase", LocalProfileStatus.READY, "a" * 64,
    )


def _inspection(profile: LocalProfile, status=LocalProfileStatus.READY):
    return SimpleNamespace(profile_id=profile.profile_id, status=status)


def test_runtime_builds_actual_windows_provider_and_all_exact_checks(tmp_path) -> None:
    root, profile, runner, providers = _repo(tmp_path), _profile(tmp_path), Runner(), []

    def provider_constructor():
        provider = Provider()
        providers.append(provider)
        return provider

    inspections = []
    def inspector(profile_id, *, provider):
        inspections.append((profile_id, provider))
        return _inspection(profile)

    runtime = subject.compose_sat_campaign_windows_runtime(
        root, os_name="nt", provider_constructor=provider_constructor,
        inspector=inspector, subprocess_runner=runner,
    )
    provider = runtime.provider_factory(profile)
    checks = runtime.checks_factory(profile)
    target = CampaignPreflightTarget(
        profile.profile_id, root, profile.storage_root, provider.provider_scheme,
    )
    results = {kind: check(target) for kind, check in checks.items()}

    assert set(checks) == set(Check)
    assert all(result.check is kind and result.outcome is Outcome.PASSED
               for kind, result in results.items())
    assert inspections == [(profile.profile_id, providers[-1])]
    scanner_calls = [call for call in runner.calls if call[0][0] == sys.executable]
    assert len(scanner_calls) == 2
    assert {Path(call[0][1]).name for call in scanner_calls} == {
        "scan_sensitive_fixtures.py", "scan_sat_context.py",
    }
    assert all(call[0][2:] == ["--root", str(root)] for call in scanner_calls)
    assert all(call[1]["stdout"] is subprocess.DEVNULL
               and call[1]["stderr"] is subprocess.DEVNULL for call in scanner_calls)
    assert "profile-synthetic" not in repr(runtime) and str(root) not in repr(runtime)


@pytest.mark.parametrize(("platform", "scheme"), (
    ("linux", "linux-secret-service"),
    ("darwin", "macos-keychain"),
))
def test_runtime_uses_explicit_native_platform_provider(tmp_path, platform, scheme) -> None:
    root, profile, runner = _repo(tmp_path), _profile(tmp_path, scheme=scheme), Runner()
    calls = []

    def provider_constructor(reference, selected_platform):
        calls.append((reference.provider_scheme, selected_platform))
        return Provider(scheme)

    runtime = subject.compose_sat_campaign_runtime(
        root,
        platform=platform,
        provider_constructor=provider_constructor,
        inspector=lambda profile_id, *, provider: _inspection(profile),
        subprocess_runner=runner,
    )
    provider = runtime.provider_factory(profile)
    target = CampaignPreflightTarget(profile.profile_id, root, profile.storage_root, scheme)
    results = {kind: check(target) for kind, check in runtime.checks_factory(profile).items()}

    assert provider.provider_scheme == scheme
    assert calls == [(scheme, platform), (scheme, platform)]
    assert all(result.outcome is Outcome.PASSED for result in results.values())


@pytest.mark.parametrize(("change", "failed"), (
    ("doctor", Check.DOCTOR), ("scanner", Check.SCANNER),
    ("checkout", Check.CHECKOUT), ("commit", Check.IDENTITY),
    ("target", Check.IDENTITY),
))
def test_each_offline_failure_is_typed_and_redacted(tmp_path, change, failed) -> None:
    root, profile = _repo(tmp_path), _profile(tmp_path)
    runner = Runner(scanner=1 if change == "scanner" else 0,
                    status="dirty" if change == "checkout" else "",
                    commit="invalid" if change == "commit" else "a" * 40)
    def inspector(*_args, **_kwargs):
        status = LocalProfileStatus.MISSING if change == "doctor" else LocalProfileStatus.READY
        return _inspection(profile, status)
    runtime = subject.compose_sat_campaign_windows_runtime(
        root, os_name="nt", provider_constructor=Provider,
        inspector=inspector, subprocess_runner=runner,
    )
    target = CampaignPreflightTarget(
        profile.profile_id, root, profile.storage_root, Provider.provider_scheme)
    if change == "target":
        target = replace(target, storage_root=tmp_path / "substitute")
    results = {kind: check(target) for kind, check in runtime.checks_factory(profile).items()}
    assert results[failed].outcome is Outcome.FAILED
    assert all(str(value) not in repr(results[failed]) for value in (
        root, profile.storage_root, profile.profile_id, profile.phrase_ref))


def test_hung_preflight_subprocess_is_bounded_and_sanitized(tmp_path) -> None:
    root, profile, runner = _repo(tmp_path), _profile(tmp_path), HungRunner()
    runtime = subject.compose_sat_campaign_windows_runtime(
        root, os_name="nt", provider_constructor=Provider,
        inspector=lambda *_a, **_k: _inspection(profile),
        subprocess_runner=runner,
    )
    target = CampaignPreflightTarget(
        profile.profile_id, root, profile.storage_root, Provider.provider_scheme,
    )
    results = {kind: check(target) for kind, check in runtime.checks_factory(profile).items()}

    assert results[Check.SCANNER].outcome is Outcome.FAILED
    assert results[Check.CHECKOUT].outcome is Outcome.FAILED
    assert results[Check.IDENTITY].outcome is Outcome.FAILED
    assert runner.calls and all(
        call[1]["timeout"] == subject._SUBPROCESS_TIMEOUT_SECONDS for call in runner.calls
    )
    assert "TimeoutExpired" not in repr(results[Check.SCANNER])


@pytest.mark.parametrize("case", ("os", "scheme", "repo"))
def test_runtime_composition_failures_are_fixed_and_sanitized(tmp_path, case) -> None:
    root, profile = _repo(tmp_path), _profile(tmp_path)
    if case == "repo":
        root = tmp_path / "missing"
    runtime = None
    with pytest.raises(subject.CampaignRuntimeError) as caught:
        runtime = subject.compose_sat_campaign_windows_runtime(
            root, os_name="posix" if case == "os" else "nt",
            provider_constructor=Provider, inspector=lambda *_a, **_k: _inspection(profile),
            subprocess_runner=Runner(),
        )
        runtime.provider_factory(
            _profile(tmp_path, scheme="dummy") if case == "scheme" else profile)
    assert runtime is None or case == "scheme"
    assert (caught.value.error, caught.value.reason) == \
        ("sat_campaign_runtime_failed", "campaign-runtime-unavailable")
    assert all(value not in repr(caught.value) for value in (str(root), profile.phrase_ref))


def test_import_graph_excludes_legacy_and_experimental_dependencies() -> None:
    tree = ast.parse(Path(subject.__file__).read_text(encoding="utf-8"))
    imported = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    forbidden = ("adapters.cli.common", "smoke", "probe", "diagnose", "live_gate",
                 "permit", "backfill", "scheduler")
    assert not any(any(word in name for word in forbidden) for name in imported)
