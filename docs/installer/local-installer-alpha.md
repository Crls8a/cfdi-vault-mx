# Local Installer Alpha

This alpha path gives a technical Windows user a repeatable local install without `PYTHONPATH=src`. It creates a normal Python virtual environment, installs the package in editable mode, validates the installed CLI, and runs fake/offline checks only.

## Quick path

From the repository root:

```powershell
.\scripts\bootstrap_local.ps1 `
  -DatabaseUrl "postgresql+psycopg://cfdi_vault:cfdi_vault@localhost:5432/cfdi_vault" `
  -TestDatabaseUrl "postgresql+psycopg://cfdi_vault:cfdi_vault@localhost:5432/cfdi_vault_test"
```

Expected result:

- `.venv` exists locally and remains untracked;
- `pip install -e ".[dev]"` succeeds;
- `cfdi-vault --help` works as an installed command;
- `cfdi-vault setup --help` works;
- `cfdi-vault doctor --help` works;
- scanner and pytest pass;
- fake/offline download smoke passes with a temporary synthetic profile outside the repo;
- SAT real is not executed.

## Manual editable install

Use this when you want to control each step yourself:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\cfdi-vault.exe --help
.\.venv\Scripts\cfdi-vault.exe setup --help
.\.venv\Scripts\cfdi-vault.exe doctor --help
```

Do not set `PYTHONPATH=src` for normal local use. Editable install is the supported alpha path.

## First-use workflow

Use a real operator profile only on the operator machine and never commit local profile files. For docs or PR evidence, use placeholders and redacted summaries.

| Step | Command | Purpose |
|---|---|---|
| Setup | `cfdi-vault setup --source-folder <external-folder>` | Create the local AppData profile and import credential file references safely. |
| Status | `cfdi-vault status --profile-id <profile>` | Show redacted profile readiness. |
| Doctor | `cfdi-vault doctor --profile-id <profile>` | Check local recovery dependencies, queue/cache fallback, storage, and profile readiness. Docker recovery uses PostgreSQL/RabbitMQ/Redis. |
| Plan | `cfdi-vault download plan --profile <profile> --from 2024-01-01 --to 2024-01-31 --kind metadata --direction received` | Validate a fake/offline query without submission. |
| Request | `cfdi-vault download request --profile <profile> --from 2024-01-01 --to 2024-01-31 --kind metadata --direction received` | Submit a synthetic request to the fake SAT simulator only. |
| Sync | `cfdi-vault download sync --profile <profile> --from 2024-01-01 --to 2024-01-31 --kind metadata --direction received` | Run the fake/offline pipeline and persist local recovery state. |
| Status readback | `cfdi-vault download status --profile <profile> --job-id <job-id>` | Read safe aggregate status for the local fake job. |

For package/XML fake evidence, use `--kind cfdi` only with synthetic/local data and keep output redacted.

## Bootstrap options

| Option | Use when |
|---|---|
| `-VenvPath <path>` | You want a virtual environment somewhere other than `.venv`. |
| `-ProfileId <profile>` | You want the temporary smoke profile to use a different id. |
| `-From YYYY-MM-DD -To YYYY-MM-DD` | You want a different synthetic smoke range. Keep it small. |
| `-DatabaseUrl <url>` | Runtime PostgreSQL database for the fake/offline smoke. |
| `-TestDatabaseUrl <url>` | Disposable PostgreSQL test database. The database name should contain `test` because pytest resets its schema from the Flyway baseline. |
| `-SkipScanner` | You are only checking install mechanics locally. Do not use before PR. |
| `-SkipTests` | You are only checking install mechanics locally. Do not use before PR. |
| `-SkipOfflineSmoke` | You cannot run the fake smoke, but still want install/help validation. |

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
