# CLI refactor merge synchronization plan

This plan defines how to land the CLI family refactor without changing user-visible CLI behavior, losing SAT live-gate work, or restoring the old monolithic `src/cfdi_vault/cli.py`.

## Decision

`codex/cli-refactor-base` is the source of truth for the split CLI architecture. Any branch that still edits command logic in `src/cfdi_vault/cli.py` must be synchronized by moving that logic into the correct module under `src/cfdi_vault/adapters/cli/`.

Do not merge the refactor into a dirty worktree. Stabilize the target branch first, then merge through a dedicated synchronization branch.

## Current branch inventory

| Branch or ref | Role | Current evidence | Merge implication |
|---|---|---|---|
| `origin/main` | Common base for the CLI refactor. | Refactor branch is ahead by 6 commits. | Use as comparison base for review budget and regression checks. |
| `codex/cli-refactor-base` | Integrated CLI split. | `src/cfdi_vault/cli.py` is a 7-line shim; full suite passed with `373 passed`. | Land this before future CLI work, or use it as the source branch for a sync branch. |
| `test/sat-v15-verify-live-gate` | Active SAT/live-gate and broader docs/runtime WIP. | Dirty worktree; `src/cfdi_vault/cli.py` is still thousands of lines. | Must be cleaned or committed before synchronization. Do not merge into it while dirty. |
| `codex/cli-refactor-parity-review` | Source audit branch. | Content cherry-picked into `codex/cli-refactor-base` as `d147619`. | Keep for audit unless explicitly pruning cherry-picked branches. |
| `codex/cli-refactor-pr-governance` | Source governance branch. | Content cherry-picked into `codex/cli-refactor-base` as `7d21362`. | Keep for audit unless explicitly pruning cherry-picked branches. |

## Safe merge topology

```text
origin/main
  ├─ codex/cli-refactor-base
  │    ├─ b619c40 refactor(cli): split Typer adapter by command family
  │    ├─ 226854c refactor(cli): split SAT command subfamilies
  │    └─ 7d21362 docs: add CLI refactor review strategy
  │
  └─ test/sat-v15-verify-live-gate
       └─ codex/cli-refactor-sync-sat-live-gate
            └─ merge codex/cli-refactor-base and port CLI logic into families
```

The synchronization branch should be created only after `test/sat-v15-verify-live-gate` has a clean status.

## Synchronization steps

1. Stabilize `test/sat-v15-verify-live-gate`.
   - Commit or intentionally split its current WIP into reviewable work units.
   - Run its own targeted tests before mixing in the CLI refactor.
   - Create a safety tag or backup branch if the WIP contains important unpushed work.
2. Create an integration branch from the clean SAT branch:

   ```powershell
   git switch test/sat-v15-verify-live-gate
   git status --short --branch
   git switch -c codex/cli-refactor-sync-sat-live-gate
   git merge --no-ff codex/cli-refactor-base
   ```

3. Resolve conflicts by family ownership, not by file convenience.
   - `src/cfdi_vault/cli.py`: keep the 7-line shim from `codex/cli-refactor-base`.
   - CLI help catalog changes: move to `src/cfdi_vault/adapters/cli/help.py`.
   - Import/search/show/summary/export/import changes: move to `src/cfdi_vault/adapters/cli/operations.py`.
   - Setup/config/status/doctor changes: move to `src/cfdi_vault/adapters/cli/setup.py`.
   - Download/sync/queue/worker changes: move to `src/cfdi_vault/adapters/cli/download.py`.
   - Secret custody changes: move to `src/cfdi_vault/adapters/cli/secrets.py`.
   - Live permit changes: move to `src/cfdi_vault/adapters/cli/live.py`.
   - SAT auth/WSDL/oracle/lint changes: move to `src/cfdi_vault/adapters/cli/sat_auth.py`.
   - SAT metadata/backfill changes: move to `src/cfdi_vault/adapters/cli/sat_metadata.py` or `sat_backfill.py`.
   - SAT transport/probe/guard changes: move to `src/cfdi_vault/adapters/cli/sat_probes.py`.
   - SAT verify/package smoke changes: move to `src/cfdi_vault/adapters/cli/sat_verify.py`.
   - If the SAT live gate remains large enough to blur ownership, create `src/cfdi_vault/adapters/cli/sat_live_gate.py` and register it from `sat.py`.
4. Keep compatibility transparent.
   - Public import remains `cfdi_vault.cli:app`.
   - Existing command names, options, exit codes, and output contracts must stay unchanged unless the SAT WIP intentionally changed them and tests document it.
   - Tests may import `cfdi_vault.cli` as the public entrypoint, but monkeypatches should target the real family module.
5. Run the merge gate before committing the synchronization branch.

## Merge gate

Run these after resolving conflicts:

```powershell
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe scripts\scan_sensitive_fixtures.py --root .
git diff --check
.\.venv\Scripts\python.exe -m pytest tests/test_cli_help.py tests/test_cli_secret_commands.py tests/test_cli_setup.py tests/test_cli_storage.py tests/test_cli_transport_probe.py tests/test_cli_download.py tests/test_sat_backfill.py tests/test_sat_auth_contract.py tests/test_sat_auth_envelope_lint.py tests/test_sat_auth_oracle.py -q
.\.venv\Scripts\python.exe -m pytest -q
```

If PostgreSQL-only work is included in the same target branch, also run the database-specific test gate documented by that workstream before declaring the sync transparent.

## Review strategy

Prefer chained PRs because the integrated refactor exceeds the 400 changed-line review budget.

| PR | Target | Content | Review focus |
|---:|---|---|---|
| 1 | `main` | Base CLI split and SOLID/merge policy. | Public shim, adapter registration, existing command compatibility. |
| 2 | After PR 1 | SAT subfamilies. | SAT command registration and monkeypatch target movement. |
| 3 | After PR 2 | Parity report and governance docs. | Evidence, merge checklist, review policy. |
| 4 | After SAT WIP is clean | `codex/cli-refactor-sync-sat-live-gate`. | Port SAT live-gate CLI logic into family modules without behavior drift. |

Use a single PR only if Carlos explicitly accepts `size:exception`. The exception should say why review safety is better than slicing for that specific PR.

## Acceptance checklist

- [ ] Target branch is clean before synchronization starts.
- [ ] `src/cfdi_vault/cli.py` remains a shim after conflict resolution.
- [ ] Every moved command keeps its public Typer name and options.
- [ ] SAT live-gate behavior is covered by existing or updated tests.
- [ ] Sensitive fixture scanner passes.
- [ ] `git diff --check` passes.
- [ ] Targeted CLI/SAT tests pass.
- [ ] Full pytest passes when production code changed.
- [ ] Worktrees and temporary branches are cleaned only after Git confirms they are merged or intentionally retained for audit.
