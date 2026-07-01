# CLI help design

The CLI help is a user-facing guide, not just auto-generated option text. It should explain the recovery flow and what each command is responsible for.

## Decision

`cfdi-vault help` should provide:

1. the recommended recovery flow;
2. a command catalog;
3. per-command explanations;
4. examples;
5. a pointer to Typer's built-in `--help` for flags/options.

## Help command contract

```bash
cfdi-vault help
cfdi-vault help "sync metadata"
cfdi-vault help "sync xml"
cfdi-vault sync metadata --help
```

## Command responsibilities

| Command | Responsibility |
|---|---|
| `doctor` | Verify database, queue, cache, and storage connectivity. |
| `init` | Initialize tenant/RFC scope. |
| `sync metadata` | Recover metadata and load the metadata ledger. |
| `sync xml` | Recover packages/XML, register local paths, parse, load DB, and reconcile. |
| `queue status` | Inspect durable queue/job event counts. |
| `worker run` | Process queued recovery work. |
| `reconcile` | Recompute UUID-level reconciliation state. |
| `search` | Find normalized CFDI records. |
| `show` | Display one CFDI detail view. |
| `print` | Render one CFDI as text/HTML/PDF. |
| `export` | Export normalized recovery data. |
| `import-xml`, `import-zip`, `summary`, `export-csv` | Legacy local synthetic lab commands. |

## Help output target

```text
CFDI Vault MX help

Recommended recovery flow:
  1. cfdi-vault doctor
  2. cfdi-vault init --tenant-id <tenant> --rfc <RFC>
  3. cfdi-vault sync metadata ...
  4. cfdi-vault sync xml ...
  5. cfdi-vault search <text-or-rfc>
  6. cfdi-vault show <UUID>
  7. cfdi-vault print <UUID> --format pdf

Command catalog:
  doctor         Check whether database, queue, cache, and storage are reachable.
  sync xml       Recover SAT packages/XML evidence, register local file paths, parse known fields, and load data.
```

## Acceptance criteria

- [ ] `cfdi-vault help` shows the recommended flow.
- [ ] `cfdi-vault help "sync xml"` explains download, extraction, local path registration, parsing, DB load, and reconciliation.
- [ ] Unknown help topics exit non-zero and point back to `cfdi-vault help`.
- [ ] Built-in `--help` still works for options.
