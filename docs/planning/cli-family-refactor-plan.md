# CLI family refactor plan

This is the living plan for keeping the `cfdi-vault` Typer CLI split by responsibility instead of rebuilding a monolithic `cli.py`.

## Decision

`src/cfdi_vault/cli.py` is only a compatibility shim. The source of truth for command behavior is `src/cfdi_vault/adapters/cli/`.

## Current status

| Area | Status | Notes |
|---|---:|---|
| Public entrypoint | Done | `cfdi_vault.cli:app` still works through the shim. |
| Family modules | Done | Commands are split under `adapters/cli/`. |
| Merge-conflict policy | Done | `AGENTS.md` says not to restore the 3,400+ line file. |
| Architecture docs | In progress | Keep this plan, README, architecture, and SDD aligned with the split. |
| SAT sub-splitting | Deferred | `sat.py` is the largest family and can be split later by SAT operation. |

## Family ownership

| Family module | Owns | Must not own |
|---|---|---|
| `app.py` | Typer app composition and subcommand registration. | Command logic or business rules. |
| `help.py` | Custom help catalog and help command. | SAT/download/setup execution. |
| `setup.py` | `config validate`, `onboard`, `setup`, `status`, `doctor`. | Credential backend internals or SAT calls. |
| `secrets.py` | Local credential-reference register/verify/delete commands. | Real secret values in output, config, docs, or fixtures. |
| `live.py` | Local live execution permit commands. | Real SAT execution. |
| `download.py` | Fake/offline download, sync, queue, worker, and download status commands. | SAT live probes or signing rules. |
| `operations.py` | Local import/search/show/print/export/reconcile operations. | SAT transport or credential custody. |
| `sat.py` | SAT-gated smoke/probe/backfill/verify commands. | Generic local import/export commands. |
| `common.py` | Shared CLI DTOs, parsing, guard helpers, and output helpers used by multiple families. | Family-specific command bodies. |

## Work plan

- [x] Split CLI code into adapter family modules.
- [x] Keep `src/cfdi_vault/cli.py` as the public import shim.
- [x] Update tests to monkeypatch family modules instead of the shim.
- [x] Document SOLID/thin-adapter rules in `AGENTS.md`.
- [x] Document merge-conflict policy in `AGENTS.md`.
- [x] Add this living plan.
- [x] Update high-level docs that still pointed at monolithic `cli.py`.
- [ ] If SAT keeps growing, split `sat.py` into SAT subfamilies:
  - `sat_auth.py`
  - `sat_metadata.py`
  - `sat_backfill.py`
  - `sat_probes.py`
  - `sat_verify.py`
- [ ] Before PR merge, decide review strategy: `size:exception` or chained review slices.

## Agent task slices

| Slice | Suggested owner | Files |
|---|---|---|
| Setup/custody/live | Worker | `setup.py`, `secrets.py`, `live.py`, related tests. |
| Download/operations | Worker | `download.py`, `operations.py`, related tests. |
| SAT commands | Worker | `sat.py`, SAT/backfill/probe tests. |
| Docs and governance | Worker/reviewer | `AGENTS.md`, `README.md`, `docs/architecture.md`, this plan. |
| Fresh review | Reviewer | Diff behavior, command tree, monkeypatch targets, merge-conflict risk. |

## Merge and rebase protocol

When a branch conflicts with the CLI refactor:

1. Treat `src/cfdi_vault/adapters/cli/` as the source of truth.
2. Keep `src/cfdi_vault/cli.py` as a shim only.
3. If the other branch added command logic to `cli.py`, move it into the correct family module.
4. Do not restore the old 3,400+ line `cli.py` to make conflict resolution easier.
5. Run the validation gate before committing the conflict resolution.

## Validation gate

Run this after any CLI-family change or CLI merge conflict:

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m pytest tests/test_cli_help.py tests/test_cli_secret_commands.py tests/test_cli_setup.py tests/test_cli_storage.py tests/test_cli_transport_probe.py tests/test_cli_download.py
.\.venv\Scripts\python.exe scripts\scan_sensitive_fixtures.py --root .
git diff --check
```

Run the full suite before PR merge:

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m pytest -q
```

## Update rule

When a task above changes state, update this file in the same PR as the code or documentation change. Do not keep the plan in chat only.
