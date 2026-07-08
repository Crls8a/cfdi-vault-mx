"""Live CLI commands."""

from __future__ import annotations

from .common import *


def live_permit_create(
    scope: str = typer.Option(..., "--scope", help="transport_probe, auth_post_probe, verify_post_probe, auth_matrix_probe, auth_live_smoke, metadata_live_smoke, metadata_backfill_submit, or package_download_smoke."),
    profile: str = typer.Option(..., "--profile", help="Local setup profile id."),
    kind: str = typer.Option(..., "--kind", help="metadata only."),
    direction: str = typer.Option(..., "--direction", help="received or issued."),
    from_date: str = typer.Option(..., "--from", help="YYYY-MM-DD."),
    to_date: str = typer.Option(..., "--to", help="YYYY-MM-DD."),
    expires_minutes: int = typer.Option(15, "--expires-minutes", min=1, max=15),
    reason: str = typer.Option(..., "--reason", help="Auditable local reason."),
    auth_envelope_variant: str | None = typer.Option(None, "--auth-envelope-variant", help="auth_live_smoke only: security_only, action_before_security, or security_before_action."),
    wcf_action_header_enabled: bool | None = typer.Option(None, "--wcf-action-header-enabled/--no-wcf-action-header-enabled", help="auth_live_smoke only; defaults to false for security_only and true for Action variants."),
) -> None:
    """Create a one-time local permit outside the repository for one live operation."""

    try:
        permit = create_live_execution_permit(
            LivePermitRequest(
                scope=scope,
                profile_id=profile,
                kind=kind,
                direction=direction,
                date_from=from_date,
                date_to=to_date,
                expires_minutes=expires_minutes,
                reason=reason,
                auth_envelope_variant=auth_envelope_variant if scope == "auth_live_smoke" else None,
                wcf_action_header_enabled=wcf_action_header_enabled if scope == "auth_live_smoke" else None,
            )
        )
    except LivePermitError as exc:
        typer.echo("error=live_permit_denied", err=True)
        typer.echo(f"reason={exc.reason}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo("mode=live-permit")
    typer.echo(f"permit_id={permit.permit_id}")
    typer.echo(f"scope={scope}")
    typer.echo(f"profile={profile}")
    typer.echo(f"kind={kind}")
    typer.echo(f"direction={direction}")
    typer.echo(f"date_from={from_date}")
    typer.echo(f"date_to={to_date}")
    typer.echo(f"max_range_days={permit.max_range_days}")
    typer.echo("max_attempts=1")
    typer.echo(f"expires_at={permit.expires_at.isoformat().replace('+00:00', 'Z')}")
    typer.echo("permit_storage=appdata-local")
    typer.echo("consumed=false")
    typer.echo("redaction_required=true")
    if permit.auth_envelope_variant is not None:
        typer.echo(f"auth_envelope_variant={permit.auth_envelope_variant}")
    if permit.wcf_action_header_enabled is not None:
        typer.echo(f"wcf_action_header_enabled={'true' if permit.wcf_action_header_enabled else 'false'}")


def register(permit_app: typer.Typer) -> None:
    """Register live commands."""

    permit_app.command("create")(live_permit_create)
