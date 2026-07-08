# CFDI Vault MX

CFDI Vault MX separates two related goals: a reusable Python library for SAT CFDI recovery, and a reference system that shows how that library can power a personal/local CFDI vault. They live together while the architecture matures, but they must be documented as different products.

## What problem this solves

SAT CFDI recovery is not just "download invoices." The hard part is building a repeatable, auditable flow around scarce v1.5 documentation, asynchronous SAT requests, expiring packages, credential custody, partial parser support, retries, and operator-friendly errors.

This repository has two tracks:

| Track | What it is | What it is not |
|---|---|---|
| **Library / package** | The future `cfdi-vault-mx` Python package: importable domain models, ports, fake/offline SAT adapters, parsers, and recovery building blocks. | A guarantee that the full personal vault system is installed, configured, or production-ready. |
| **Reference system / case study** | This repository's CLI, Docker/local runtime, docs, and examples showing how someone could manage and inspect their own CFDI recovery workflow. | A certified tax product, SaaS, accounting system, or promise of live SAT automation. |

The relationship is intentional: the system explains why the library exists, and the library should eventually be reusable without copying the whole system.

## Current status and claims

CFDI Vault MX is a development-stage case study and reference implementation. It is meant to contribute a clear programming example for SAT CFDI recovery architecture, not to promise a certified tax product.

| Topic | Current claim |
|---|---|
| PyPI availability | Not published yet. `pip install cfdi-vault-mx` is the library/package release target, not a current guarantee. |
| SAT live automation | Not production-ready. Live SAT access remains gated behind signing, credential custody, compliance, and manual approval. |
| Supported demo mode | Fake/offline SAT flows with synthetic data. |
| Intended use today | Learning, architecture review, local development, and contribution discussion. |
| Contact | Open a GitHub issue for questions, collaboration, or responsible disclosure before depending on unsupported behavior. |

The current code uses one durable data direction: PostgreSQL. RabbitMQ handles jobs, Redis handles transient state, and Docker Compose scaffolds the local runtime.

Important database boundary: synthetic import checks, recovery jobs, package/XML evidence, reconciliation, accounting search, and queue audit all belong in PostgreSQL.

Live SAT SOAP access is still intentionally disabled until signing, credential custody, and compliance work are implemented.

## Quick path

1. Create a local Python 3.12 environment.
2. Install the project:

   ```bash
   python -m pip install -e ".[dev]"
   ```

   This is the recommended developer path. `PYTHONPATH=src` is only a temporary source-tree debugging fallback; see `docs/devx.md`.

3. Create or validate a local profile:

   ```bash
   cfdi-vault setup --source-folder <external-folder>
   cfdi-vault status
   cfdi-vault config validate examples/config/local-dev-dummy.json
   ```

   For the full AppData credential intake runbook, read `docs/setup.md`.

4. Import sample XML into PostgreSQL:

   ```bash
   cfdi-vault help
   cfdi-vault import-xml examples/synthetic-cfdi/invoice-income.xml
   ```

5. Review summaries and export:

   ```bash
   cfdi-vault summary
   cfdi-vault export-csv export.csv
   ```

6. Run the fake SAT recovery path through Docker Compose so recovery uses PostgreSQL/RabbitMQ/Redis:

   ```powershell
   Copy-Item .env.example .env
   docker compose up -d --build postgres rabbitmq redis
   docker compose run --rm app doctor
   docker compose run --rm app sync metadata --rfc XAXX010101000 --start 2024-01-01 --end 2024-01-31
   docker compose run --rm app search fake
   docker compose run --rm app queue status
   ```

   The local CLI can still run fake flows for tests and demos, but it must use `DATABASE_URL` and PostgreSQL:

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

For the no-Docker local installer alpha, run:

```powershell
.\scripts\bootstrap_local.ps1
```

See `docs/installer/local-installer-alpha.md` for the editable install and fake/offline first-use flow.

## SAT download library documentation

The repository includes design documentation for the SAT Web Service download library. Start at `docs/foundation/README.md`, then `docs/planning/README.md`, `docs/sat-download/README.md`, and `docs/recovery-v2.md`.

Important boundary: this implementation includes fake SAT only. It does not authenticate with SAT, upload e.firma files, or download real CFDI.

## Python package direction

The package metadata already exposes the distribution name `cfdi-vault-mx`, import package `cfdi_vault`, and CLI command `cfdi-vault`. That package is the library track. The reference system remains the repository-level case study, docs, Docker/local runtime, and examples.

The release target is:

```bash
pip install cfdi-vault-mx
cfdi-vault help
```

Do not treat the package as published until the release gates in `docs/release/python-package-plan.md` are complete. The first public release should be an alpha reference implementation with fake/offline SAT support, not a claim that live SAT automation is production-ready.

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
| Recovery database | Uses PostgreSQL as the durable target for jobs, evidence, reconciliation, and accounting search. |
| Parse fields | UUID, issuer, receiver, date, amounts, currency, type, payment method/form. |
| Local import | Uses PostgreSQL through SQLAlchemy. |
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
| `src/cfdi_vault/db.py` | PostgreSQL SQLAlchemy engine and import model setup. |
| `src/cfdi_vault/service.py` | Import, dedupe, summary, and CSV export use cases. |
| `src/cfdi_vault/cli.py` | Compatibility shim for the public Typer entrypoint. |
| `src/cfdi_vault/adapters/cli/` | Typer CLI app composition and command families. |
| `src/cfdi_vault/config.py` | Safe local RFC profile configuration schema and validation. |
| `src/cfdi_vault/setup.py` | AppData profile setup, credential intake guards, redacted status, and dummy smoke boundary. |
| `src/cfdi_vault/recovery_service.py` | Fake SAT recovery, search, print, export, and reconciliation use cases. |
| `src/cfdi_vault/recovery_db.py` | PostgreSQL-targeted recovery/accounting schema. |
| `src/cfdi_vault/queueing.py` | In-memory and RabbitMQ queue adapters. |
| `src/cfdi_vault/cache.py` | In-memory and Redis cache adapters. |
| `docker-compose.yml` | Local PostgreSQL/RabbitMQ/Redis stack. |
| `examples/config/` | Dummy safe profile config examples. |
| `examples/synthetic-cfdi/` | Fake XML examples only. |
| `tests/` | Parser, import, dedupe, summary, and export tests. |
| `docs/` | Architecture, SDD, security model, ADRs, and learning log. |
| `docs/planning/` | Agile planning workspace with sprint roadmap, backlog, and team board. |

## Next step

Read `docs/foundation/infrastructure-boundary.md` before changing database, queue, worker, Redis, Docker, or API behavior.
