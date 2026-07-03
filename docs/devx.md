# Developer CLI invocation

Use an editable install for local development so the CLI behaves like an installed user command. `PYTHONPATH=src` is a development fallback only; do not document it as the normal operator path.

## Quick path

1. Create or activate a Python 3.12 environment.
2. Install the project in editable mode:

   ```bash
   python -m pip install -e ".[dev]"
   ```

3. Run the CLI as an installed command:

   ```bash
   cfdi-vault setup --source-folder <external-folder>
   cfdi-vault status
   cfdi-vault doctor
   ```

4. Run the test suite before opening a PR:

   ```bash
   python -m pytest
   python scripts/scan_sensitive_fixtures.py --root .
   ```

## Invocation rules

| Situation | Command style | Rule |
|---|---|---|
| Normal local development | `cfdi-vault <command>` | Preferred path after editable install. |
| CI | `python -m pytest` and scanner scripts | CI installs the package before running tests. |
| Temporary source-tree debugging | `PYTHONPATH=src python -m cfdi_vault.cli ...` | Dev-only fallback. Do not present this as end-user UX. |

## Safety checklist

- [ ] Do not commit local profile files, runtime databases, certificates, keys, passwords, SAT ZIPs, or real CFDI/XML files.
- [ ] Keep `PYTHONPATH=src` examples out of user-facing setup instructions.
- [ ] Use placeholders such as `<external-folder>` instead of personal machine paths.
- [ ] Keep live SAT and e.firma usage behind the documented human gate.

## Next step

Use `docs/setup.md` for the local profile setup runbook and `docs/security-model.md` before changing any credential, certificate, or live SAT boundary.
