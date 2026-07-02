# CFDI Vault MX

CFDI Vault MX is evolving from a local CFDI/XML lab into an open-source **CFDI recovery and reconciliation library**. The current code supports two safe paths:

- local synthetic XML import with SQLite;
- a fake SAT recovery workflow with CLI, queue/cache/storage ports, PostgreSQL-ready schema, and Docker Compose scaffolding.

Live SAT SOAP access is still intentionally disabled until signing, credential custody, and compliance work are implemented.

## Quick path

1. Create a local Python 3.12 environment.
2. Install the project:

   ```bash
   python -m pip install -e ".[dev]"
   ```

3. Create or validate a local profile:

   ```bash
   cfdi-vault setup --source-folder <external-folder>
   cfdi-vault status
   cfdi-vault config validate examples/config/local-dev-dummy.json
   ```

   For the full AppData credential intake runbook, read `docs/setup.md`.

4. Import sample XML with the local-first path:

   ```bash
   cfdi-vault help
   cfdi-vault import-xml examples/synthetic-cfdi/invoice-income.xml --db local.sqlite3
   ```

5. Review summaries and export:

   ```bash
   cfdi-vault summary --db local.sqlite3
   cfdi-vault export-csv export.csv --db local.sqlite3
   ```

6. Run the fake SAT recovery path:

   ```bash
   cfdi-vault doctor
   cfdi-vault sync metadata --rfc XAXX010101000 --start 2024-01-01 --end 2024-01-31
   cfdi-vault search fake
   cfdi-vault queue status
   ```

7. Verify:

   ```bash
   python -m pytest
   ```

   On Windows, if you created the local `.venv`, you can also run:

   ```powershell
   .\.venv\Scripts\python.exe -m pytest
   ```

## Docker Compose path

```powershell
Copy-Item .env.example .env
docker compose up -d --build postgres rabbitmq redis
docker compose run --rm app doctor
```

Windows local setup can also use:

```powershell
.\scripts\install.ps1
```

## SAT download library documentation

The repository includes design documentation for the SAT Web Service download library. Start at `docs/foundation/README.md`, then `docs/planning/README.md`, `docs/sat-download/README.md`, and `docs/recovery-v2.md`.

Important boundary: this implementation includes fake SAT only. It does not authenticate with SAT, upload e.firma files, or download real CFDI.

## What this lab does

| Capability | Phase-one behavior |
|---|---|
| Import XML | Parses one CFDI-like XML file. |
| Import ZIP | Imports every `.xml` member in a ZIP archive. |
| Help | Explains the recommended recovery flow and what each command does. |
| Setup | Creates a local AppData RFC profile, imports credential files outside the repo, and stores the private-key phrase through a secret provider. |
| Onboarding | Creates a safe local profile config with storage, RFC, schedule, certificate fingerprint, and credential references only. |
| Fake SAT sync | Creates deterministic metadata/package rows without network access. |
| Queue events | Records RabbitMQ-style queue events; RabbitMQ adapter is available through `.[infra]`. |
| Cache/progress | Uses a cache port; Redis adapter is available through `.[infra]`. |
| Recovery database | Adds PostgreSQL-ready tables with JSON-compatible payloads. |
| Parse fields | UUID, issuer, receiver, date, amounts, currency, type, payment method/form. |
| Store locally | Uses SQLite through SQLAlchemy. |
| Deduplicate | Skips records with an existing UUID. |
| Hash | Computes SHA-256 for the imported XML bytes. |
| Summarize | Groups totals by month, issuer, and comprobante type. |
| Export | Writes normalized records to CSV. |

## Safety rules

- Use only `examples/synthetic-cfdi/` or your own fake data.
- Do not import real taxpayer XMLs.
- Do not store `.cer`, `.key`, passwords, SAT credentials, or secrets in the repository or unsafe locations.
- Do not use `--live` until the real SAT SOAP/signing slice is implemented and reviewed.

## Project map

| Path | Purpose |
|---|---|
| `src/cfdi_vault/parser.py` | Namespace-tolerant CFDI field extraction. |
| `src/cfdi_vault/db.py` | SQLAlchemy model and SQLite setup. |
| `src/cfdi_vault/service.py` | Import, dedupe, summary, and CSV export use cases. |
| `src/cfdi_vault/cli.py` | Typer CLI entrypoint. |
| `src/cfdi_vault/config.py` | Safe local RFC profile configuration schema and validation. |
| `src/cfdi_vault/setup.py` | AppData profile setup, credential intake guards, redacted status, and dummy smoke boundary. |
| `src/cfdi_vault/recovery_service.py` | Fake SAT recovery, search, print, export, and reconciliation use cases. |
| `src/cfdi_vault/recovery_db.py` | PostgreSQL-ready recovery/accounting schema. |
| `src/cfdi_vault/queueing.py` | In-memory and RabbitMQ queue adapters. |
| `src/cfdi_vault/cache.py` | In-memory and Redis cache adapters. |
| `docker-compose.yml` | Local PostgreSQL/RabbitMQ/Redis stack. |
| `examples/config/` | Dummy safe profile config examples. |
| `examples/synthetic-cfdi/` | Fake XML examples only. |
| `tests/` | Parser, import, dedupe, summary, and export tests. |
| `docs/` | Architecture, SDD, security model, ADRs, and learning log. |
| `docs/planning/` | Agile planning workspace with sprint roadmap, backlog, and team board. |

## Next step

Read `docs/security-model.md` before adding any feature that touches real CFDI data or external services.
