# SDD: Initial CFDI Vault MX repository

The initial slice establishes a safe, local-first backend/data foundation for synthetic CFDI/XML import and analysis. The scope is intentionally narrow so the architecture can be reviewed before real integrations or UI work exist.

## Quick path

1. Import synthetic XML or ZIP files through `cfdi-vault`.
2. Persist normalized records in SQLite.
3. Query summaries and export CSV.
4. Keep phase-one data synthetic only.

## Requirements

| Requirement | Implemented by |
|---|---|
| CLI command `cfdi-vault` | `src/cfdi_vault/cli.py` shim, `src/cfdi_vault/adapters/cli/` family modules, and `pyproject.toml` script entry. |
| Import individual XML | `VaultService.import_xml_file`. |
| Import ZIP with multiple XML files | `VaultService.import_zip_file`. |
| Parse CFDI fields | `parse_cfdi_xml`. |
| Store in DB | `Invoice` SQLAlchemy model. |
| Deduplicate by UUID | Existing UUID check before insert. |
| Compute XML SHA-256 hash | `hashlib.sha256(xml_bytes).hexdigest()`. |
| Summary command | `VaultService.summary` and `cfdi-vault summary`. |
| Export CSV | `VaultService.export_csv` and `cfdi-vault export-csv`. |
| Synthetic examples | `examples/synthetic-cfdi/`. |
| Test coverage | `tests/`. |

## Non-goals

- Real SAT integration.
- Certificate or e.firma handling.
- Real taxpayer XML import.
- Web server or dashboard.
- Full CFDI schema validation.

## Acceptance checklist

- [x] Python package structure exists.
- [x] Typer CLI entrypoint exists.
- [x] SQLite persistence exists.
- [x] XML and ZIP import paths exist.
- [x] UUID deduplication exists.
- [x] SHA-256 hash is stored.
- [x] Summary and CSV export exist.
- [x] Required docs exist.
- [x] Synthetic examples avoid real taxpayer data.

## Next step

Run `pytest` after every parser or persistence change; parser regressions become data-quality bugs fast.
