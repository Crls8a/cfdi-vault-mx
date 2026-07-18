"""Setup CLI commands."""

# CLI family shims intentionally import the shared command namespace.
# ruff: noqa: F403, F405

from __future__ import annotations

from pathlib import Path

from cfdi_vault.local_preflight import default_local_probes, run_local_preflight
from cfdi_vault.runtime_settings import RuntimeSettings, RuntimeSettingsError
from cfdi_vault.secrets import CredentialProviderError
from cfdi_vault.setup_core import SetupError, find_repo_root, load_profile

from .common import *


def _prompt_private_key_phrase() -> str:
    prompt_text = "Private-key phrase (masked; stored through secret provider)"
    if _supports_masked_phrase_prompt():
        return _prompt_masked_with_confirmation(prompt_text)
    return str(
        typer.prompt(
            "Private-key phrase (hidden; stored through secret provider)",
            hide_input=True,
            confirmation_prompt=True,
        )
    )

def _supports_masked_phrase_prompt() -> bool:
    return os.name == "nt" and sys.stdin.isatty() and sys.stdout.isatty()

def _prompt_masked_with_confirmation(prompt_text: str, *, attempts: int = 3) -> str:
    for _attempt in range(attempts):
        phrase_value = _read_masked_line(f"{prompt_text}: ")
        confirmation_value = _read_masked_line("Repeat for confirmation: ")
        if phrase_value == confirmation_value:
            return phrase_value
        typer.echo("Error: the two entered values do not match.", err=True)
    raise ValueError("private-key phrase confirmation did not match")

def _read_masked_line(
    prompt_text: str,
    *,
    read_char: Callable[[], str] | None = None,
    write_text: Callable[[str], None] | None = None,
) -> str:
    if read_char is None:
        if os.name != "nt":
            return str(typer.prompt(prompt_text.rstrip(": "), hide_input=True))
        import msvcrt

        read_char = msvcrt.getwch
    if write_text is None:
        write_text = _write_prompt_fragment

    chars: list[str] = []
    write_text(prompt_text)
    while True:
        char = read_char()
        if char in ("\r", "\n"):
            write_text("\n")
            return "".join(chars)
        if char == "\x03":
            raise KeyboardInterrupt
        if char in ("\x00", "\xe0"):
            read_char()
            continue
        if char in ("\b", "\x7f"):
            if chars:
                chars.pop()
                write_text("\b \b")
            continue
        if char in ("\x04", "\x1a"):
            continue
        chars.append(char)
        write_text("*")

def _write_prompt_fragment(text: str) -> None:
    typer.echo(text, nl=False)
    sys.stdout.flush()

def _required_text(value: str | None, prompt: str, *, default: str | None = None) -> str:
    if value is None or not value.strip():
        value = str(typer.prompt(prompt, default=default)).strip()
    if not value:
        raise ValueError(f"{prompt} is required")
    return value

def _required_path(value: Path | None, prompt: str) -> Path:
    if value is None:
        raw_value = str(typer.prompt(prompt)).strip()
        if not raw_value:
            raise ValueError(f"{prompt} is required")
        value = Path(raw_value)
    return value

def config_validate(
    config_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
) -> None:
    """Validate a local RFC profile config file."""

    try:
        config = load_config(config_path)
    except ConfigValidationError as exc:
        typer.echo("Config validation failed:", err=True)
        for error in exc.errors:
            typer.echo(f"- {error}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"Config OK: schemaVersion={config.schema_version}, profiles={len(config.profiles)}")
    for profile in config.profiles:
        typer.echo(
            f"- {profile.profile_id}: rfc={profile.rfc}, "
            f"storageRoot={profile.storage_root}, metadataFirst={profile.download.metadata_first}"
        )

def onboard(
    config_path: Path = typer.Option(Path("cfdi-vault.local.json"), "--config", help="Safe profile config to create or update."),
    profile_id: str | None = typer.Option(None, "--profile-id", help="Local profile identifier."),
    rfc: str | None = typer.Option(None, "--rfc", help="Taxpayer RFC for this local profile."),
    storage_root: Path | None = typer.Option(None, "--storage-root", help="Root folder for metadata, packages, XML, logs, and exports."),
    download_mode: str | None = typer.Option(None, "--download-mode", help="issued, received, or both."),
    start_date: str | None = typer.Option(None, "--start-date", help="Initial download start date: YYYY-MM-DD."),
    end_date: str | None = typer.Option(None, "--end-date", help="Optional initial download end date: YYYY-MM-DD."),
    periodicity: str | None = typer.Option(None, "--periodicity", help="disabled, interval, or daily."),
    interval_minutes: int | None = typer.Option(None, "--interval-minutes", min=1, help="Minutes between runs when periodicity is interval."),
    daily_at: str | None = typer.Option(None, "--daily-at", help="HH:MM local time when periodicity is daily."),
    max_concurrency: int | None = typer.Option(None, "--max-concurrency", min=1, max=10, help="Maximum concurrent SAT/recovery work."),
    certificate_path: Path | None = typer.Option(None, "--cer", help="Local .cer file to validate. The file is not copied."),
    private_key_path: Path | None = typer.Option(None, "--key", help="Local .key file to validate. The file is not copied."),
    timezone_name: str = typer.Option("America/Mexico_City", "--timezone", help="Schedule timezone stored in config."),
    credential_ref_prefix: str | None = typer.Option(None, "--credential-ref-prefix", help="Non-secret reference prefix for external credential custody."),
    replace_existing: bool = typer.Option(False, "--replace-existing", help="Replace an existing profile with the same profile id."),
) -> None:
    """Create the first safe local profile config without storing credential material."""

    typer.echo("Security warnings:")
    typer.echo("- Do not use real e.firma material in test or development fixtures.")
    typer.echo("- Do not share the private key file (`.key`).")
    typer.echo("- The private-key phrase is checked only for presence and is never written to config.")

    try:
        profile_id = _required_text(profile_id, "Profile id")
        rfc = _required_text(rfc, "RFC")
        storage_root = _required_path(storage_root, "Storage root")
        download_mode = _required_text(download_mode, "Download mode [issued/received/both]", default="both")
        start_date = _required_text(start_date, "Initial start date [YYYY-MM-DD]")
        if end_date is None:
            end_date = str(typer.prompt("Initial end date [YYYY-MM-DD, optional]", default="")).strip() or None
        periodicity = _required_text(periodicity, "Periodicity [disabled/interval/daily]", default="disabled")
        if max_concurrency is None:
            max_concurrency = int(typer.prompt("Maximum concurrency", default="2"))
        certificate_path = _required_path(certificate_path, "Path to .cer file")
        private_key_path = _required_path(private_key_path, "Path to .key file")
        schedule_mode = parse_schedule_mode(periodicity)
        if schedule_mode.value == "interval" and interval_minutes is None:
            interval_minutes = int(typer.prompt("Interval minutes"))
        if schedule_mode.value == "daily" and daily_at is None:
            daily_at = str(typer.prompt("Daily time [HH:MM]")).strip()
        request = OnboardingRequest(
            profile_id=profile_id,
            rfc=rfc,
            storage_root=storage_root,
            download_mode=parse_download_mode(download_mode),
            start_date=parse_iso_date(start_date, "start date"),
            end_date=parse_iso_date(end_date, "end date") if end_date else None,
            schedule_mode=schedule_mode,
            interval_minutes=interval_minutes,
            daily_at=daily_at,
            max_concurrency=max_concurrency,
            certificate_path=certificate_path,
            private_key_path=private_key_path,
            output_config=config_path,
            timezone=timezone_name,
            credential_ref_prefix=credential_ref_prefix,
            replace_existing=replace_existing,
        )
        phrase_value = typer.prompt(
            "Private-key phrase (hidden; discarded after validation)",
            hide_input=True,
            confirmation_prompt=True,
        )
        result = run_onboarding(request, str(phrase_value))
    except (OnboardingError, ValueError) as exc:
        typer.echo("Onboarding failed:", err=True)
        errors = exc.errors if isinstance(exc, OnboardingError) else (str(exc),)
        for error in errors:
            typer.echo(f"- {error}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("Onboarding complete.")
    typer.echo(f"Config: {result.output_config}")
    typer.echo(f"Profile: {result.profile_id} ({result.rfc})")
    typer.echo(f"Storage root: {result.storage_root}")
    typer.echo(f"Certificate fingerprint: {result.certificate_fingerprint}")
    typer.echo("Credential material was not copied and the private-key phrase was not stored.")

def setup_command(
    source_folder: Path | None = typer.Option(None, "--source-folder", help="External folder containing the credential files."),
    profile_id: str = typer.Option("default", "--profile-id", help="Local setup profile id."),
    rfc: str | None = typer.Option(None, "--rfc", help="RFC for this local setup profile."),
    certificate_path: Path | None = typer.Option(None, "--cer", help="Explicit certificate file when source folder has more than one candidate."),
    private_key_path: Path | None = typer.Option(None, "--key", help="Explicit private key file when source folder has more than one candidate."),
    credential_mode: str = typer.Option("copied", "--credential-mode", help="copied or referenced."),
    skip_credential_check: bool = typer.Option(
        False,
        "--skip-credential-check",
        help="Skip the local dummy sign/verify credential check after setup.",
    ),
) -> None:
    """Create the local AppData profile and import credentials safely."""

    try:
        if source_folder is None:
            source_folder = Path(str(typer.prompt("External credential folder")).strip())
        rfc = _required_text(rfc, "RFC")
        mode = setup_flow.CredentialMode(credential_mode.strip().lower())
        phrase_value = _prompt_private_key_phrase()
        provider = _setup_provider(profile_id)
        result = setup_flow.run_setup(
            profile_id=profile_id,
            rfc=rfc,
            source_folder=source_folder,
            certificate_path=certificate_path,
            private_key_path=private_key_path,
            phrase_value=str(phrase_value),
            provider=provider,
            mode=mode,
        )
        credential_check = None if skip_credential_check else setup_flow.run_credential_check(result.profile, provider)
    except (setup_flow.SetupError, CredentialProviderError, ValueError) as exc:
        typer.echo("Setup failed:", err=True)
        errors = exc.errors if isinstance(exc, setup_flow.SetupError) else (str(exc),)
        for error in errors:
            typer.echo(f"- {error}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo("Setup complete.")
    typer.echo(f"Profile: {result.profile.profile_id} ({setup_flow.redact_rfc(result.profile.rfc)})")
    typer.echo("Credential files were imported into the local AppData profile.")
    typer.echo("The private-key phrase was stored through the secret provider, not in profile.json.")
    if credential_check is not None:
        typer.echo(f"Credential check: {credential_check.detail} ({credential_check.backend})")
    typer.echo("Run: cfdi-vault status")

def setup_status(
    profile_id: str = typer.Option("default", "--profile-id", help="Local setup profile id."),
) -> None:
    """Show redacted local setup profile readiness."""

    provider = _setup_provider(profile_id)
    inspection = setup_flow.inspect_profile(profile_id, provider=provider)
    typer.echo(setup_flow.format_profile_status(inspection))
    if inspection.status != setup_flow.LocalProfileStatus.READY:
        raise typer.Exit(code=1)

def doctor(
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
    profile_id: str = typer.Option("default", "--profile-id", help="Local setup profile id to inspect."),
) -> None:
    """Check database, queue, cache, storage, and setup profile readiness."""

    checks = _service(database_url, storage).doctor()
    for check in checks:
        status = "OK" if check.ok else "FAIL"
        typer.echo(f"{status} {check.name}: {check.detail}")
    typer.echo("")
    typer.echo(setup_flow.format_profile_status(setup_flow.inspect_profile(profile_id, provider=_setup_provider(profile_id))))
    if not all(check.ok for check in checks):
        raise typer.Exit(code=1)


def preflight(
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL; defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="External artifact root; defaults to CFDI_STORAGE_ROOT."),
    rabbitmq_url: str | None = typer.Option(None, "--rabbitmq-url", help="RabbitMQ URL; defaults to RABBITMQ_URL."),
    redis_url: str | None = typer.Option(None, "--redis-url", help="Redis URL; defaults to REDIS_URL."),
    commit_ref: str | None = typer.Option(None, "--commit-ref", help="Opaque commit reference; defaults to CFDI_VAULT_COMMIT_REF."),
    profile_id: str = typer.Option("default", "--profile-id", help="Local setup profile id."),
) -> None:
    """Validate local profile, secret reference, storage, and services without SAT I/O."""

    cli_values = {
        key: value
        for key, value in {
            "DATABASE_URL": database_url,
            "CFDI_STORAGE_ROOT": str(storage) if storage is not None else None,
            "RABBITMQ_URL": rabbitmq_url,
            "REDIS_URL": redis_url,
            "CFDI_VAULT_COMMIT_REF": commit_ref,
        }.items()
        if value is not None
    }
    repository_root = find_repo_root(Path.cwd()) or Path.cwd()
    try:
        settings = RuntimeSettings.resolve(
            cli=cli_values,
            dotenv_path=repository_root / ".env",
            repository_root=repository_root,
        )
        profile = load_profile(profile_id)
        provider = _setup_provider(profile_id)
        report = run_local_preflight(
            settings,
            profile,
            provider,
            probes=default_local_probes(settings),
            repository_root=repository_root,
        )
    except (RuntimeSettingsError, SetupError, CredentialProviderError):
        typer.echo("ready=false")
        typer.echo("preflight=failed reason=local-configuration-invalid")
        raise typer.Exit(code=1) from None

    typer.echo(f"ready={str(report.ready).lower()}")
    for check in report.sanitized()["checks"]:
        typer.echo(f"check={check['name']} status={check['status']} reason={check['reason']}")
    if not report.ready:
        raise typer.Exit(code=1)


def register(config_app: typer.Typer, app: typer.Typer) -> None:
    """Register setup commands."""

    config_app.command("validate")(config_validate)

    app.command("onboard")(onboard)

    app.command("setup")(setup_command)

    app.command("status")(setup_status)

    app.command("doctor")(doctor)

    app.command("preflight")(preflight)
