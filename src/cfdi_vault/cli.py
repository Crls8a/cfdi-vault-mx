"""Typer CLI for CFDI Vault MX."""

from __future__ import annotations

from pathlib import Path

import typer

from cfdi_vault.service import ImportBatchResult, ImportRecord, SummaryRow, VaultService

app = typer.Typer(
    name="cfdi-vault",
    help="Import, summarize, and export synthetic CFDI/XML data in a local SQLite vault.",
    no_args_is_help=True,
)


def _db_option() -> Path:
    return Path("cfdi-vault.sqlite3")


@app.command("import-xml")
def import_xml(
    xml_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    db: Path = typer.Option(_db_option(), "--db", help="SQLite database path."),
) -> None:
    """Import one synthetic CFDI XML file."""

    record = VaultService(db).import_xml_file(xml_path)
    _print_record(record)
    if record.error:
        raise typer.Exit(code=1)


@app.command("import-zip")
def import_zip(
    zip_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    db: Path = typer.Option(_db_option(), "--db", help="SQLite database path."),
) -> None:
    """Import all XML files from a ZIP archive."""

    result = VaultService(db).import_zip_file(zip_path)
    _print_batch(result)
    if result.failed:
        raise typer.Exit(code=1)


@app.command("summary")
def summary(
    db: Path = typer.Option(_db_option(), "--db", help="SQLite database path."),
) -> None:
    """Print totals grouped by month, issuer, and CFDI comprobante type."""

    vault_summary = VaultService(db).summary()
    _print_section("Totals by month", vault_summary.by_month)
    _print_section("Totals by issuer", vault_summary.by_issuer)
    _print_section("Totals by comprobante type", vault_summary.by_comprobante_type)


@app.command("export-csv")
def export_csv(
    output_path: Path = typer.Argument(..., dir_okay=False, writable=True),
    db: Path = typer.Option(_db_option(), "--db", help="SQLite database path."),
) -> None:
    """Export imported CFDI records to CSV."""

    count = VaultService(db).export_csv(output_path)
    typer.echo(f"Exported {count} invoice(s) to {output_path}")


def _print_record(record: ImportRecord) -> None:
    if record.error:
        typer.echo(f"ERROR {record.source_name}: {record.error}", err=True)
        return
    if record.duplicate:
        typer.echo(f"SKIPPED duplicate UUID {record.uuid} from {record.source_name}")
        return
    typer.echo(f"IMPORTED UUID {record.uuid} from {record.source_name}")
    typer.echo(f"SHA-256 {record.xml_sha256}")


def _print_batch(result: ImportBatchResult) -> None:
    for record in result.records:
        _print_record(record)
    typer.echo(
        f"Processed {result.total_files} XML file(s): "
        f"{result.imported} imported, {result.duplicates} duplicate(s), {result.failed} failed."
    )


def _print_section(title: str, rows: tuple[SummaryRow, ...]) -> None:
    typer.echo(f"\n{title}")
    typer.echo("label,count,subtotal,total")
    if not rows:
        typer.echo("(no rows)")
        return
    for row in rows:
        typer.echo(f"{row.label},{row.count},{row.subtotal:.2f},{row.total:.2f}")
