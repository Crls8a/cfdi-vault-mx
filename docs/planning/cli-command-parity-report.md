# CLI command parity report

This report verifies that the CLI family split keeps the public `cfdi-vault` command tree registered through the compatibility shim and the adapter family modules. Evidence was collected from Typer app introspection, help smoke checks, and focused CLI/SAT tests.

## Verdict

- **Parity status:** PASS for command registration and help coverage.
- **Entrypoint:** `src/cfdi_vault/cli.py` remains a tiny shim that imports `app` from `cfdi_vault.adapters.cli.app`.
- **Source of truth:** command behavior lives under `src/cfdi_vault/adapters/cli/`.
- **No live SAT/e.firma/secret/RFC data was used.** Checks were help/introspection/test-only.

## Registered command tree by family

| Family | Registration owner | Public commands/groups |
|---|---|---|
| Root composition | `src/cfdi_vault/adapters/cli/app.py` | Registers `config`, `queue`, `worker`, `sync`, `download`, `sat`, `secret`, and `live`; nests `sat backfill` and `live permit`. |
| Help catalog | `src/cfdi_vault/adapters/cli/help.py` | `help`. |
| Setup/config | `src/cfdi_vault/adapters/cli/setup.py` | `onboard`, `setup`, `status`, `doctor`, `config validate`. |
| Local operations | `src/cfdi_vault/adapters/cli/operations.py` | `init`, `reconcile`, `search`, `show`, `print`, `export`, `import-xml`, `import-zip`, `summary`, `export-csv`. |
| Queue/worker/sync/download | `src/cfdi_vault/adapters/cli/download.py` | `queue status`, `worker run`, `sync metadata`, `sync xml`, `download plan`, `download request`, `download sync`, `download live-smoke`, `download status`. |
| SAT/backfill/probes | `src/cfdi_vault/adapters/cli/sat.py` | `sat auth-smoke`, `sat metadata-request-smoke`, `sat metadata-request-state`, `sat verify-due`, `sat package-download-smoke`, `sat metadata-verify-smoke`, `sat inspect-auth-contract`, `sat lint-auth-envelope`, `sat oracle-auth-fingerprint`, `sat diff-auth-oracle`, `sat diagnose-live`, `sat probe-transport`, `sat probe-auth-post`, `sat probe-verify-post`, `sat probe-auth-matrix`, `sat backfill plan`, `sat backfill submit`. |
| Secret custody | `src/cfdi_vault/adapters/cli/secrets.py` | `secret register`, `secret verify`, `secret delete`. |
| Live permit | `src/cfdi_vault/adapters/cli/live.py` | `live permit create`. |

## Help smoke coverage

Typer `CliRunner` help smoke checks passed for **57/57** commands/groups, including:

- root and setup/config: `--help`, `help --help`, `setup --help`, `status --help`, `doctor --help`, `config validate --help`;
- local operations: `init`, `reconcile`, `search`, `show`, `print`, `export`, `import-xml`, `import-zip`, `summary`, `export-csv` help;
- queue/download: `queue status`, `worker run`, `sync metadata`, `sync xml`, and all `download` subcommands help;
- SAT/backfill/probes: all `sat` smoke/probe/oracle/diagnose commands plus `sat backfill plan/submit` help;
- custody/live: `secret register/verify/delete`, `live permit`, and `live permit create` help.

## Test-target parity

Focused tests still exercise the public shim while monkeypatching the family modules that now own behavior:

| Area | Evidence |
|---|---|
| Public compatibility | CLI tests import `app` from `cfdi_vault.cli`, proving the shim path still works. |
| Setup family | `tests/test_cli_setup.py` imports `cfdi_vault.adapters.cli.setup` for monkeypatch targets. |
| Secret custody family | `tests/test_cli_secret_commands.py` imports `cfdi_vault.adapters.cli.secrets` for monkeypatch targets. |
| Download/SAT split | `tests/test_cli_download.py` imports `cfdi_vault.adapters.cli.download`, `cfdi_vault.adapters.cli.sat`, and `cfdi_vault.adapters.cli.common` for family-owned monkeypatch targets. |
| SAT probe/backfill family | `tests/test_cli_transport_probe.py`, `tests/test_sat_backfill.py`, `tests/test_sat_auth_contract.py`, and `tests/test_sat_auth_envelope_lint.py` patch `cfdi_vault.adapters.cli.sat`, not the shim. |

Focused parity test run passed: **109 passed** for CLI help/setup/secret/storage/transport/download plus SAT backfill/auth/oracle/envelope tests.

## Commands run

```powershell
$env:PYTHONPATH = "src"
@'
# Typer CliRunner introspection/help matrix for 57 commands/groups.
'@ | python -
python -m pytest tests/test_cli_help.py tests/test_cli_setup.py tests/test_cli_secret_commands.py tests/test_cli_storage.py tests/test_cli_transport_probe.py tests/test_cli_download.py tests/test_sat_backfill.py tests/test_sat_auth_contract.py tests/test_sat_auth_envelope_lint.py tests/test_sat_auth_oracle.py -q
python scripts/scan_sensitive_fixtures.py --root .
git diff --check
```

Full pytest was not rerun for this docs-only report slice. The focused CLI/SAT parity subset and full help matrix are the relevant evidence for this review-facing guard; the full suite remains required before PR merge per `docs/planning/cli-family-refactor-plan.md`.

## Merge-conflict guard

If a merge or rebase conflicts with CLI files, **do not resurrect the old monolithic `src/cfdi_vault/cli.py`**. Keep `src/cfdi_vault/cli.py` as the shim and move any incoming command logic into the correct `src/cfdi_vault/adapters/cli/` family module before committing the conflict resolution.
