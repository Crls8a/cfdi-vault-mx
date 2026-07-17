"""Compose the Windows-only local runtime for productive SAT campaigns."""
from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cfdi_vault.sat_campaign_preflight import (
    CampaignPreflightCheck,
    CampaignPreflightCheckResult,
    CampaignPreflightOutcome,
    CampaignPreflightTarget,
    NeutralCheck,
)
from cfdi_vault.sat_campaign_run import ChecksFactory, ProviderFactory
from cfdi_vault.secrets import CredentialKind, CredentialReference
from cfdi_vault.setup_core import ExistenceProvider, LocalProfile, LocalProfileStatus
from cfdi_vault.setup_status import inspect_profile
from cfdi_vault.windows_secrets import WindowsCredentialManagerSecretProvider

_SCHEME = "windows-credential-manager"
_SCANNERS = ("scan_sensitive_fixtures.py", "scan_sat_context.py")
_COMMIT = re.compile(r"[0-9a-fA-F]{40}")
Inspector = Callable[..., object]
SubprocessRunner = Callable[..., object]
ProviderConstructor = Callable[[], ExistenceProvider]


class CampaignRuntimeError(ValueError):
    """Reject unavailable runtime composition without exposing local context."""

    error = "sat_campaign_runtime_failed"

    def __init__(self) -> None:
        self.reason = "campaign-runtime-unavailable"
        super().__init__(self.reason)


@dataclass(frozen=True, slots=True, repr=False)
class SatCampaignRuntime:
    """Redacted provider and check factories accepted by the campaign service."""

    provider_factory: ProviderFactory
    checks_factory: ChecksFactory

    def __repr__(self) -> str:
        return "SatCampaignRuntime(<redacted>)"


def compose_sat_campaign_windows_runtime(
    repo_root: Path,
    *,
    os_name: str = os.name,
    provider_constructor: ProviderConstructor = WindowsCredentialManagerSecretProvider,
    inspector: Inspector = inspect_profile,
    subprocess_runner: SubprocessRunner = subprocess.run,
) -> SatCampaignRuntime:
    """Return fail-closed Windows factories without contacting SAT or credentials."""
    root = _canonical_root(repo_root, os_name)

    def provider_factory(profile: LocalProfile) -> ExistenceProvider:
        try:
            if os_name != "nt" or type(profile) is not LocalProfile:
                raise TypeError
            reference = CredentialReference(profile.phrase_ref, CredentialKind.PHRASE)
            if reference.provider_scheme != _SCHEME:
                raise ValueError
            provider = provider_constructor()
            if (getattr(provider, "provider_scheme", None) != reference.provider_scheme
                    or not callable(getattr(provider, "exists", None))):
                raise TypeError
            return provider
        except CampaignRuntimeError:
            raise
        except Exception:
            raise CampaignRuntimeError() from None

    def checks_factory(profile: LocalProfile) -> Mapping[CampaignPreflightCheck, NeutralCheck]:
        try:
            provider: ExistenceProvider | None = provider_factory(profile)
        except CampaignRuntimeError:
            provider = None
        profile_id = profile.profile_id
        storage_root = profile.storage_root

        def checked(kind: CampaignPreflightCheck, operation: Callable[[CampaignPreflightTarget], bool]) -> NeutralCheck:
            def run(target: CampaignPreflightTarget) -> CampaignPreflightCheckResult:
                try:
                    passed = operation(target) is True
                except Exception:
                    passed = False
                return CampaignPreflightCheckResult(
                    kind,
                    CampaignPreflightOutcome.PASSED if passed else CampaignPreflightOutcome.FAILED,
                )
            return run

        def provider_runtime(_target: CampaignPreflightTarget) -> bool:
            return (
                os_name == "nt" and provider is not None
                and CredentialReference(profile.phrase_ref, CredentialKind.PHRASE).provider_scheme == _SCHEME
                and getattr(provider, "provider_scheme", None) == _SCHEME
                and callable(getattr(provider, "exists", None))
            )

        def doctor(_target: CampaignPreflightTarget) -> bool:
            if provider is None:
                return False
            inspection = inspector(profile_id, provider=provider)
            return (
                getattr(inspection, "profile_id", None) == profile_id
                and getattr(inspection, "status", None) is LocalProfileStatus.READY
            )

        def scanner(_target: CampaignPreflightTarget) -> bool:
            for name in _SCANNERS:
                script = root / "scripts" / name
                if not script.is_file():
                    return False
                completed = subprocess_runner(
                    [sys.executable, str(script), "--root", str(root)],
                    cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False,
                )
                if type(getattr(completed, "returncode", None)) is not int or completed.returncode != 0:
                    return False
            return True

        def checkout(_target: CampaignPreflightTarget) -> bool:
            completed = _git(subprocess_runner, root, "status", "--short")
            return (type(completed.returncode) is int and completed.returncode == 0
                    and type(completed.stdout) is str and completed.stdout == "")

        def identity(target: CampaignPreflightTarget) -> bool:
            exact = (
                type(target) is CampaignPreflightTarget
                and target.repo_root == root and target.profile_id == profile_id
                and target.storage_root == storage_root and target.provider_scheme == _SCHEME
            )
            if not exact:
                return False
            completed = _git(subprocess_runner, root, "rev-parse", "HEAD")
            return (
                type(completed.returncode) is int and completed.returncode == 0
                and type(completed.stdout) is str
                and _COMMIT.fullmatch(completed.stdout.strip()) is not None
            )

        operations = {
            CampaignPreflightCheck.PROVIDER_RUNTIME: provider_runtime,
            CampaignPreflightCheck.DOCTOR: doctor,
            CampaignPreflightCheck.SCANNER: scanner,
            CampaignPreflightCheck.CHECKOUT: checkout,
            CampaignPreflightCheck.IDENTITY: identity,
        }
        return {kind: checked(kind, operation) for kind, operation in operations.items()}

    return SatCampaignRuntime(provider_factory, checks_factory)


def _canonical_root(repo_root: Path, os_name: str) -> Path:
    try:
        if os_name != "nt" or not isinstance(repo_root, Path):
            raise TypeError
        root = repo_root.resolve(strict=True)
        if not (root / ".git").exists():
            raise ValueError
        return root
    except Exception:
        raise CampaignRuntimeError() from None


def _git(runner: SubprocessRunner, root: Path, *arguments: str) -> Any:
    return runner(
        ["git", *arguments], cwd=root, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True, check=False,
    )
