"""Pure, Tk-free logic for the local FIEL onboarding wizard.

This module never imports ``tkinter`` so it can be unit tested headlessly.
It adds no new credential handling: it calls the already-tested
``setup_service.run_setup`` and related setup helpers, and only ever holds
the private-key phrase as a short-lived local variable passed straight
through to the secret provider. See docs/adr/0003-fiel-local-onboarding-wizard.md
for the binding security contract this module must uphold.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cfdi_vault import setup as setup_flow
from cfdi_vault.os_secret_providers import OsSecretProviderError, native_provider_for_reference
from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference


@dataclass(frozen=True)
class WizardSetupOutcome:
    """Redacted result of one wizard onboarding attempt."""

    ok: bool
    profile_id: str
    messages: tuple[str, ...]
    redacted_rfc: str | None = None
    credential_mode: str | None = None
    redacted_fingerprint: str | None = None
    credential_check_detail: str | None = None


def default_provider_for_profile(
    profile_id: str,
    *,
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
) -> object:
    """Select the real OS secret provider for one profile's phrase reference.

    Never falls back to a synthetic/dummy provider; production wizard runs
    must fail closed if no native backend is available on this platform.
    """

    phrase_ref = setup_flow.default_phrase_reference(profile_id, platform=platform)
    reference = CredentialReference(uri=phrase_ref, kind=CredentialKind.PHRASE)
    return native_provider_for_reference(reference, platform=platform, allow_synthetic=False)


def run_wizard_setup(
    *,
    profile_id: str,
    rfc: str,
    certificate_path: Path,
    private_key_path: Path,
    phrase_value: str,
    phrase_confirmation: str,
    credential_mode: str = "referenced",
    provider: object | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
    repo_root: Path | None = None,
    platform: str | None = None,
    run_check: bool = True,
) -> WizardSetupOutcome:
    """Validate wizard input and store credentials through the setup pipeline.

    ``phrase_value`` is used only for the duration of this call and is never
    written to any return value, log, or file.
    """

    messages: list[str] = []
    if not profile_id or not profile_id.strip():
        return WizardSetupOutcome(ok=False, profile_id=profile_id, messages=("profile id is required",))
    if phrase_value != phrase_confirmation:
        return WizardSetupOutcome(ok=False, profile_id=profile_id, messages=("phrase and confirmation do not match",))
    if not phrase_value or not phrase_value.strip():
        return WizardSetupOutcome(ok=False, profile_id=profile_id, messages=("phrase must not be empty",))
    try:
        mode = setup_flow.CredentialMode(credential_mode.strip().lower())
    except ValueError:
        return WizardSetupOutcome(ok=False, profile_id=profile_id, messages=(f"unsupported credential mode: {credential_mode}",))

    active_provider = provider
    if active_provider is None:
        try:
            active_provider = default_provider_for_profile(profile_id, env=env, platform=platform)
        except OsSecretProviderError as exc:
            return WizardSetupOutcome(ok=False, profile_id=profile_id, messages=(f"no local secret store is available: {exc}",))

    try:
        result = setup_flow.run_setup(
            profile_id=profile_id,
            rfc=rfc,
            source_folder=certificate_path.parent,
            certificate_path=certificate_path,
            private_key_path=private_key_path,
            phrase_value=phrase_value,
            provider=active_provider,
            mode=mode,
            env=env,
            home=home,
            repo_root=repo_root,
            platform=platform,
        )
    except setup_flow.SetupError as exc:
        return WizardSetupOutcome(ok=False, profile_id=profile_id, messages=tuple(exc.errors))
    except CredentialProviderError as exc:
        return WizardSetupOutcome(ok=False, profile_id=profile_id, messages=(f"secret store rejected the phrase: {exc}",))

    check_detail: str | None = None
    if run_check:
        try:
            check = setup_flow.run_credential_check(result.profile, active_provider)
            check_detail = check.detail
            if not check.ok:
                messages.append("local credential check failed after save; re-run setup with the correct phrase")
        except setup_flow.SetupError as exc:
            messages.append("; ".join(exc.errors))

    ok = check_detail != "dummy sign/verify failed"
    return WizardSetupOutcome(
        ok=ok,
        profile_id=result.profile.profile_id,
        messages=tuple(messages),
        redacted_rfc=setup_flow.redact_rfc(result.profile.rfc),
        credential_mode=result.profile.credential_mode.value,
        redacted_fingerprint=setup_flow.redact_fingerprint(result.profile.certificate_fingerprint),
        credential_check_detail=check_detail,
    )


def wizard_profile_status_text(
    profile_id: str,
    *,
    provider: object | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
    platform: str | None = None,
) -> str:
    """Return the redacted profile status text shown by ``cfdi-vault status``."""

    active_provider = provider
    if active_provider is None:
        try:
            active_provider = default_provider_for_profile(profile_id, env=env, platform=platform)
        except OsSecretProviderError as exc:
            active_provider = None
            return f"no local secret store is available: {exc}"
    inspection = setup_flow.inspect_profile(profile_id, provider=active_provider, env=env, home=home)
    return setup_flow.format_profile_status(inspection)


@dataclass(frozen=True)
class WizardPrefillFields:
    """Non-secret profile fields safe to prefill back into the wizard form.

    Never includes the phrase or any secret value; the phrase field always
    starts empty and must be re-entered by the operator on purpose.
    """

    rfc: str
    certificate_path: str
    private_key_path: str
    credential_mode: str


def load_existing_profile_for_prefill(
    profile_id: str,
    *,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> WizardPrefillFields | None:
    """Return non-secret fields from an already-saved profile, or None."""

    if not profile_id or not profile_id.strip():
        return None
    try:
        profile = setup_flow.load_profile(profile_id, env=env, home=home)
    except setup_flow.SetupError:
        return None
    return WizardPrefillFields(
        rfc=profile.rfc,
        certificate_path=str(profile.certificate_path),
        private_key_path=str(profile.private_key_path),
        credential_mode=profile.credential_mode.value,
    )


_ALLOWED_DIAGNOSTIC_COMMANDS = ("status", "doctor", "preflight")


#: Local-dev-only default matching docker-compose.yml / .env.example
#: (POSTGRES_USER=POSTGRES_PASSWORD=POSTGRES_DB=cfdi_vault). Not a secret:
#: it is the fixed, publicly committed local development default, reachable
#: only via localhost. A real deployment must override it explicitly.
#: Host port 5433 (not the container-internal 5432) matches this machine's
#: local override in .env (POSTGRES_PORT=5433), needed because a separate
#: native PostgreSQL Windows service already occupies host port 5432.
DEFAULT_LOCAL_DATABASE_URL = "postgresql+psycopg://cfdi_vault:cfdi_vault@localhost:5433/cfdi_vault"

#: Local-dev-only defaults matching docker-compose.yml / .env.example
#: (RABBITMQ_DEFAULT_USER=RABBITMQ_DEFAULT_PASS=cfdi_vault). Not secrets.
DEFAULT_LOCAL_RABBITMQ_URL = "amqp://cfdi_vault:cfdi_vault@localhost:5672/"
DEFAULT_LOCAL_REDIS_URL = "redis://localhost:6379/0"


def default_local_commit_ref() -> str | None:
    """Return the current git commit hash as an opaque, non-secret reference.

    ``CFDI_VAULT_COMMIT_REF`` is not a credential; it is only an opaque
    lineage marker the preflight/campaign checks require to be present.
    Returns None (leaving the field for the operator to fill) if this is not
    a git checkout or git is unavailable.
    """

    import subprocess

    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def default_local_storage_root(
    profile_id: str,
    *,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> str:
    """Return the profile's own AppData storage root as the CFDI_STORAGE_ROOT default.

    This is the same absolute, outside-the-repo path ``run_wizard_setup``
    already created and proved writable, so it always satisfies
    ``RuntimeSettings``'s storage-root requirement.
    """

    paths = setup_flow.build_profile_paths(profile_id, env=env, home=home)
    return str(paths.storage_root)


def run_diagnostic_command(
    command: str,
    *,
    profile_id: str = "default",
    database_url: str | None = None,
    storage_root: str | None = None,
    rabbitmq_url: str | None = None,
    redis_url: str | None = None,
    commit_ref: str | None = None,
    env: Mapping[str, str] | None = None,
) -> str:
    """Invoke one already-redacted, read-only CLI diagnostic in-process.

    Reuses the exact ``cfdi-vault status|doctor|preflight`` commands so the
    wizard never re-implements DB/queue/cache/storage/preflight wiring. Only
    read-only, non-SAT diagnostics are reachable here; ``sat campaign *`` is
    intentionally not exposed through this function.
    """

    if command not in _ALLOWED_DIAGNOSTIC_COMMANDS:
        raise ValueError(f"unsupported diagnostic command: {command}")

    from typer.testing import CliRunner

    from cfdi_vault.cli import app

    args = [command, "--profile-id", profile_id]
    if command in {"doctor", "preflight"}:
        args.extend(["--database-url", database_url or DEFAULT_LOCAL_DATABASE_URL])
    if command == "preflight":
        args.extend(["--storage", storage_root or default_local_storage_root(profile_id, env=env)])
        args.extend(["--rabbitmq-url", rabbitmq_url or DEFAULT_LOCAL_RABBITMQ_URL])
        args.extend(["--redis-url", redis_url or DEFAULT_LOCAL_REDIS_URL])
        resolved_commit_ref = commit_ref or default_local_commit_ref()
        if resolved_commit_ref:
            args.extend(["--commit-ref", resolved_commit_ref])

    runner = CliRunner()
    result = runner.invoke(app, args, env=dict(env) if env is not None else None, catch_exceptions=True)
    output = result.output.strip()
    if result.exception is not None and not output:
        return f"diagnostic '{command}' failed to run (see local logs for detail)"
    return output
