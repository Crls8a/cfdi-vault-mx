"""Typer app composition for the CFDI Vault MX CLI."""

from __future__ import annotations

import importlib

import typer

download = importlib.import_module("cfdi_vault.adapters.cli.download")
help_catalog = importlib.import_module("cfdi_vault.adapters.cli.help")
operations = importlib.import_module("cfdi_vault.adapters.cli.operations")
sat = importlib.import_module("cfdi_vault.adapters.cli.sat")
sat_campaign = importlib.import_module("cfdi_vault.adapters.cli.sat_campaign")
custody_commands = importlib.import_module("cfdi_vault.adapters.cli.secrets")
setup = importlib.import_module("cfdi_vault.adapters.cli.setup")
storage_commands = importlib.import_module("cfdi_vault.adapters.cli.storage")

app = typer.Typer(
    name="cfdi-vault",
    help="Recover, reconcile, search, and export CFDI data.",
    no_args_is_help=True,
)
config_app = typer.Typer(help="Validate local RFC profile configuration.", no_args_is_help=True)
queue_app = typer.Typer(help="Inspect queue state.", no_args_is_help=True)
worker_app = typer.Typer(help="Run recovery workers.", no_args_is_help=True)
sync_app = typer.Typer(
    help="Run fake/offline recovery sync jobs; live SAT uses sat campaign.",
    no_args_is_help=True,
)
download_app = typer.Typer(help="Plan and submit fake/offline SAT download requests.", no_args_is_help=True)
sat_app = typer.Typer(help="Manage the productive PostgreSQL-backed SAT campaign.", no_args_is_help=True)
campaign_app = typer.Typer(help="Manage the persistent SAT recovery campaign.", no_args_is_help=True)
custody_app = typer.Typer(help="Manage local secret references without printing values.", no_args_is_help=True)
storage_app = typer.Typer(
    help="Inspect offline filesystem evidence with redacted output.",
    no_args_is_help=True,
)

app.add_typer(config_app, name="config")
app.add_typer(queue_app, name="queue")
app.add_typer(worker_app, name="worker")
app.add_typer(sync_app, name="sync")
app.add_typer(download_app, name="download")
app.add_typer(sat_app, name="sat")
app.add_typer(custody_app, name="secret")
app.add_typer(storage_app, name="storage")
sat_app.add_typer(campaign_app, name="campaign")

help_catalog.register(app)
setup.register(config_app, app)
custody_commands.register(custody_app)
sat.register(sat_app)
sat_campaign.register(campaign_app)
download.register(queue_app, worker_app, sync_app, download_app)
operations.register(app)
storage_commands.register(storage_app)

__all__ = ["app"]
