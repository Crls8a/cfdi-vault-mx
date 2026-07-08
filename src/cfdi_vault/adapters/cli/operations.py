"""Operations CLI commands."""

from __future__ import annotations

from .common import *

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

def init(
    tenant_id: str = typer.Option("default", "--tenant-id", help="Tenant identifier."),
    rfc: str = typer.Option(..., "--rfc", help="Requester RFC."),
    name: str | None = typer.Option(None, "--name", help="Tenant display name."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Initialize the recovery schema, storage folders, and tenant row."""

    service = _service(database_url, storage)
    service.init_tenant(tenant_id, rfc, name)
    typer.echo(f"Initialized tenant {tenant_id} for RFC {rfc.upper()}")

def reconcile(
    tenant_id: str | None = typer.Option(None, "--tenant-id", help="Tenant identifier."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Recompute metadata/XML reconciliation states."""

    count = _service(database_url, storage).reconcile(tenant_id=tenant_id)
    typer.echo(f"Updated {count} reconciliation row(s)")

def search(
    text: str = typer.Argument("", help="Text, UUID, RFC, or party name to search."),
    tenant_id: str | None = typer.Option(None, "--tenant-id", help="Tenant identifier."),
    limit: int = typer.Option(20, "--limit", min=1, max=200, help="Maximum rows."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Search normalized CFDI data."""

    rows = _service(database_url, storage).search(text, tenant_id=tenant_id, limit=limit)
    typer.echo("uuid,issuer_rfc,receiver_rfc,issue_date,total,status,parser_status")
    if not rows:
        typer.echo("(no matches)")
        return
    for row in rows:
        typer.echo(
            f"{row['uuid']},{row['issuer_rfc']},{row['receiver_rfc']},"
            f"{row['issue_date']},{row['total']},{row['status']},{row['parser_status']}"
        )

def show(
    uuid: str = typer.Argument(..., help="CFDI UUID."),
    tenant_id: str | None = typer.Option(None, "--tenant-id", help="Tenant identifier."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Show one CFDI in terminal-friendly form."""

    service = _service(database_url, storage)
    try:
        typer.echo(service.render_text(uuid, tenant_id=tenant_id))
    except LookupError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

def print_invoice(
    uuid: str = typer.Argument(..., help="CFDI UUID."),
    output_path: Path | None = typer.Option(None, "--output", "-o", help="Output file. Required for html/pdf."),
    format: str = typer.Option("text", "--format", help="text, html, or pdf."),
    tenant_id: str | None = typer.Option(None, "--tenant-id", help="Tenant identifier."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Render a CFDI as text, HTML, or a basic PDF."""

    service = _service(database_url, storage)
    try:
        if format == "text":
            text = service.render_text(uuid, tenant_id=tenant_id)
            if output_path:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(text, encoding="utf-8")
            else:
                typer.echo(text)
            return
        if output_path is None:
            output_path = _resolve_storage_root(storage) / "exports" / f"{uuid}.{format}"
        if format == "html":
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(service.render_html(uuid, tenant_id=tenant_id), encoding="utf-8")
        elif format == "pdf":
            write_minimal_pdf(output_path, service.render_text(uuid, tenant_id=tenant_id))
        else:
            raise ValueError("format must be text, html, or pdf")
    except (LookupError, ValueError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Wrote {output_path}")

def export(
    output_path: Path | None = typer.Option(None, "--output", "-o", help="Output CSV path."),
    format: str = typer.Option("csv", "--format", help="Only csv is supported in this slice."),
    tenant_id: str | None = typer.Option(None, "--tenant-id", help="Tenant identifier."),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
    storage: Path | None = typer.Option(None, "--storage", help="Storage root. Defaults to CFDI_STORAGE_ROOT or storage/."),
) -> None:
    """Export normalized CFDI data."""

    if format != "csv":
        typer.echo("Only csv export is supported in this slice.", err=True)
        raise typer.Exit(code=1)
    if output_path is None:
        output_path = _resolve_storage_root(storage) / "exports" / "cfdi.csv"
    count = _service(database_url, storage).export_csv(output_path, tenant_id=tenant_id)
    typer.echo(f"Exported {count} CFDI row(s) to {output_path}")

def import_xml(
    xml_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
) -> None:
    """Import one synthetic CFDI XML file."""

    record = VaultService(database_url).import_xml_file(xml_path)
    _print_record(record)
    if record.error:
        raise typer.Exit(code=1)

def import_zip(
    zip_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
) -> None:
    """Import all XML files from a ZIP archive."""

    result = VaultService(database_url).import_zip_file(zip_path)
    _print_batch(result)
    if result.failed:
        raise typer.Exit(code=1)

def summary(
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
) -> None:
    """Print totals grouped by month, issuer, and CFDI comprobante type."""

    vault_summary = VaultService(database_url).summary()
    _print_section("Totals by month", vault_summary.by_month)
    _print_section("Totals by issuer", vault_summary.by_issuer)
    _print_section("Totals by comprobante type", vault_summary.by_comprobante_type)

def export_csv(
    output_path: Path = typer.Argument(..., dir_okay=False, writable=True),
    database_url: str | None = typer.Option(None, "--database-url", help="PostgreSQL URL. Defaults to DATABASE_URL."),
) -> None:
    """Export imported CFDI records to CSV."""

    count = VaultService(database_url).export_csv(output_path)
    typer.echo(f"Exported {count} invoice(s) to {output_path}")


def register(app: typer.Typer) -> None:
    """Register operations commands."""

    app.command("init")(init)

    app.command("reconcile")(reconcile)

    app.command("search")(search)

    app.command("show")(show)

    app.command("print")(print_invoice)

    app.command("export")(export)

    app.command("import-xml")(import_xml)

    app.command("import-zip")(import_zip)

    app.command("summary")(summary)

    app.command("export-csv")(export_csv)
