# Local Installer Alpha

This alpha path gives a technical Windows user a repeatable local install without `PYTHONPATH=src`. It creates a normal Python virtual environment, installs the package in editable mode, validates the installed package imports, and runs an offline profile/dependency smoke check only.

There is no `cfdi-vault` CLI anymore — it was retired in favor of the local
control-panel API (`cfdi-vault-webapi`) and its Next.js frontend under `web/`.
See `docs/adr/0004-local-control-panel.md`.

## Quick path

From the repository root:

```powershell
.\scripts\bootstrap_local.ps1 `
  -DatabaseUrl "postgresql+psycopg://cfdi_vault:cfdi_vault@localhost:5432/cfdi_vault" `
  -TestDatabaseUrl "postgresql+psycopg://cfdi_vault:cfdi_vault@localhost:5432/cfdi_vault_test"
```

Expected result:

- `.venv` exists locally and remains untracked;
- `pip install -e ".[dev,webapi]"` succeeds;
- `cfdi_vault.adapters.webapi.app`, `cfdi_vault.doctor_runner`, `cfdi_vault.worker_runner`, and `cfdi_vault.sat_campaign_run_service` import cleanly as the installed package;
- scanner and pytest pass;
- offline profile/doctor smoke passes with a temporary synthetic profile outside the repo;
- SAT real is not executed.

## Manual editable install

Use this when you want to control each step yourself:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev,webapi]"
.\.venv\Scripts\python.exe -c "import cfdi_vault.adapters.webapi.app"
```

Do not set `PYTHONPATH=src` for normal local use. Editable install is the supported alpha path.

## First-use workflow

Use a real operator profile only on the operator machine and never commit local profile files. For docs or PR evidence, use placeholders and redacted summaries.

Start the panel API (`cfdi-vault-webapi`, loopback-only, ADR 0004) and drive
these from the web frontend, or call the same endpoints directly:

| Step | Endpoint | Purpose |
|---|---|---|
| Setup | `POST /api/setup` | Create the local AppData profile and import credential file references safely. |
| Status | `GET /api/profile/{profile_id}/status` | Show redacted profile readiness. |
| Doctor | `GET /api/system/doctor` | Check local recovery dependencies, queue/cache fallback, storage, and profile readiness. Docker recovery uses PostgreSQL/RabbitMQ/Redis. |

The fake/offline SAT download pipeline (`download plan/request/sync/status`)
that used to appear here was retired along with the CLI: it was already a
parallel harness disconnected from the real PostgreSQL-backed campaign path
(see `docs/runbooks/sat-campaign.md`), and nothing replaced it.

## Bootstrap options

| Option | Use when |
|---|---|
| `-VenvPath <path>` | You want a virtual environment somewhere other than `.venv`. |
| `-ProfileId <profile>` | You want the temporary smoke profile to use a different id. |
| `-DatabaseUrl <url>` | Runtime PostgreSQL database for the offline smoke. |
| `-TestDatabaseUrl <url>` | Disposable PostgreSQL test database. The database name should contain `test` because pytest resets its schema from the Flyway baseline. |
| `-SkipScanner` | You are only checking install mechanics locally. Do not use before PR. |
| `-SkipTests` | You are only checking install mechanics locally. Do not use before PR. |
| `-SkipOfflineSmoke` | You cannot run the offline smoke, but still want install/import validation. |

## Safety boundaries

The alpha installer does not:

- execute SAT real;
- use real e.firma against SAT;
- require real credentials for the bootstrap smoke;
- run destructive test resets against the runtime database;
- commit or copy certificates, keys, passwords, SAT metadata, SAT ZIPs, or CFDI files;
- approve or close issue #50;
- build a desktop installer;
- build PyInstaller or Nuitka artifacts.

The temporary smoke profile lives under the OS temp directory and is removed by the script. If cleanup is interrupted, delete the `cfdi-vault-local-alpha-*` temp folder manually.

## Release checks

Before merging packaging changes, run:

```powershell
py scripts\scan_sensitive_fixtures.py --root .
py -m pytest -q
git diff --check
```

CI must be green before merge.

## Next step

After this alpha, future packaging final work can decide whether to add a signed desktop installer, wheel publishing, or PyInstaller/Nuitka. That is intentionally outside this milestone.
