"""Typer app composition for the CFDI Vault MX CLI."""

from __future__ import annotations

import importlib

import typer

download = importlib.import_module("cfdi_vault.adapters.cli.download")
help_catalog = importlib.import_module("cfdi_vault.adapters.cli.help")
live = importlib.import_module("cfdi_vault.adapters.cli.live")
operations = importlib.import_module("cfdi_vault.adapters.cli.operations")
sat = importlib.import_module("cfdi_vault.adapters.cli.sat")
custody_commands = importlib.import_module("cfdi_vault.adapters.cli.secrets")
setup = importlib.import_module("cfdi_vault.adapters.cli.setup")

app = typer.Typer(
    name="cfdi-vault",
    help="Recover, reconcile, search, and export CFDI data.",
    no_args_is_help=True,
)
config_app = typer.Typer(help="Validate local RFC profile configuration.", no_args_is_help=True)
queue_app = typer.Typer(help="Inspect queue state.", no_args_is_help=True)
worker_app = typer.Typer(help="Run recovery workers.", no_args_is_help=True)
sync_app = typer.Typer(help="Submit SAT recovery sync jobs.", no_args_is_help=True)
download_app = typer.Typer(help="Plan and submit fake/offline SAT download requests.", no_args_is_help=True)
sat_app = typer.Typer(help="Run human-gated SAT live smoke checks.", no_args_is_help=True)
backfill_app = typer.Typer(help="Plan safe SAT metadata historical backfills.", no_args_is_help=True)
custody_app = typer.Typer(help="Manage local secret references without printing values.", no_args_is_help=True)
live_app = typer.Typer(help="Create one-time local live execution permits.", no_args_is_help=True)
permit_app = typer.Typer(help="Create one-time local live execution permits.", no_args_is_help=True)

app.add_typer(config_app, name="config")
app.add_typer(queue_app, name="queue")
app.add_typer(worker_app, name="worker")
app.add_typer(sync_app, name="sync")
app.add_typer(download_app, name="download")
app.add_typer(sat_app, name="sat")
app.add_typer(custody_app, name="secret")
app.add_typer(live_app, name="live")
sat_app.add_typer(backfill_app, name="backfill")
live_app.add_typer(permit_app, name="permit")

help_catalog.register(app)
setup.register(config_app, app)
custody_commands.register(custody_app)
live.register(permit_app)
sat.register(sat_app, backfill_app)
download.register(queue_app, worker_app, sync_app, download_app)
operations.register(app)

__all__ = ["app"]
