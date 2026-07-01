# CFDI Vault MX

CFDI Vault MX is a local-first backend/data lab for importing, parsing, storing, summarizing, and exporting **synthetic** Mexican CFDI/XML files. It is built as a public case study for architecture, data modeling, CLI design, testing, and secure handling boundaries.

## Quick path

1. Create a local Python 3.12 environment.
2. Install the project:

   ```bash
   python -m pip install -e ".[dev]"
   ```

3. Import sample XML:

   ```bash
   cfdi-vault import-xml examples/synthetic-cfdi/invoice-income.xml --db local.sqlite3
   ```

4. Review summaries and export:

   ```bash
   cfdi-vault summary --db local.sqlite3
   cfdi-vault export-csv export.csv --db local.sqlite3
   ```

5. Verify:

   ```bash
   python -m pytest
   ```

   On Windows, if you created the local `.venv`, you can also run:

   ```powershell
   .\.venv\Scripts\python.exe -m pytest
   ```

## What this lab does

| Capability | Phase-one behavior |
|---|---|
| Import XML | Parses one CFDI-like XML file. |
| Import ZIP | Imports every `.xml` member in a ZIP archive. |
| Parse fields | UUID, issuer, receiver, date, amounts, currency, type, payment method/form. |
| Store locally | Uses SQLite through SQLAlchemy. |
| Deduplicate | Skips records with an existing UUID. |
| Hash | Computes SHA-256 for the imported XML bytes. |
| Summarize | Groups totals by month, issuer, and comprobante type. |
| Export | Writes normalized records to CSV. |

## Safety rules

- Use only `examples/synthetic-cfdi/` or your own fake data.
- Do not import real taxpayer XMLs.
- Do not store `.cer`, `.key`, passwords, SAT credentials, or secrets.
- Do not add SAT integration, e.firma upload, or dashboard code in phase one.

## Project map

| Path | Purpose |
|---|---|
| `src/cfdi_vault/parser.py` | Namespace-tolerant CFDI field extraction. |
| `src/cfdi_vault/db.py` | SQLAlchemy model and SQLite setup. |
| `src/cfdi_vault/service.py` | Import, dedupe, summary, and CSV export use cases. |
| `src/cfdi_vault/cli.py` | Typer CLI entrypoint. |
| `examples/synthetic-cfdi/` | Fake XML examples only. |
| `tests/` | Parser, import, dedupe, summary, and export tests. |
| `docs/` | Architecture, SDD, security model, ADRs, and learning log. |

## Next step

Read `docs/security-model.md` before adding any feature that touches real CFDI data or external services.
