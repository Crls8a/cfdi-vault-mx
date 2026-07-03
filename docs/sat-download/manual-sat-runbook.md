# MANUAL-SAT-001: human-gated live SAT smoke runbook

This runbook defines the approval and evidence rules for any future real SAT smoke. It does not authorize live SAT execution by itself, and it must never run in CI.

## Current status

Live SAT remains blocked in this repository.

Before any real SAT/e.firma action, all of these must be true:

1. Carlos explicitly approves the one-time smoke in issue #50 or in the exact PR for that run.
2. The live SAT smoke issue is approved for that exact run.
3. The command is run only on the operator machine in an interactive terminal.
4. No real certificate, key, password, token, SAT ZIP, metadata, XML, RFC, or local path is copied into git, logs, screenshots, fixtures, or PR text.
5. The local working tree is clean before and after the smoke.

If any item is false, stop.

## Required live execution gates

Any future live command must require all three explicit operator choices:

| Gate | Required value |
|---|---|
| Real SAT opt-in | `CFDI_VAULT_ALLOW_REAL_SAT=1` |
| Real credential opt-in | `CFDI_VAULT_ALLOW_REAL_CREDENTIALS=1` |
| Manual command flag | `--manual-real-sat` |

These gates are not permission by themselves. They only make the future command eligible to continue after issue #50 is explicitly approved.

## Enablement commands

The safe CLI surface is:

```powershell
cfdi-vault sat auth-smoke `
  --profile <PROFILE_ID> `
  --manual-real-sat

cfdi-vault download live-smoke `
  --profile <PROFILE_ID> `
  --from <YYYY-MM-DD> `
  --to <YYYY-MM-DD> `
  --kind metadata `
  --direction received `
  --manual-real-sat
```

Use `--direction issued` only when that exact direction is approved for the manual run.

If the command returns `error=live_adapter_unavailable`, stop. That means the safety gates passed, but the real SAT adapter is not wired for execution yet. Do not fall back to `sync metadata --live`.

## Safe preflight

Run only repository-safe checks first:

```bash
git status --short
cfdi-vault status
cfdi-vault doctor
py scripts/scan_sensitive_fixtures.py --root .
py -m pytest
```

On non-Windows environments, use the project Python interpreter if `py` is unavailable.

Expected result:

- the working tree is clean;
- status and doctor output are redacted;
- the profile is ready in the operator AppData location;
- `passwordRef` exists and points to the approved local `SecretProvider`;
- scanner passes;
- tests pass;
- no live SAT command has been executed.

## First live smoke scope

The first authorized smoke must be intentionally small:

- metadata-only first;
- one calendar day only for the first attempt;
- one local manual profile and its configured storage root;
- no XML/package download until metadata-only evidence is reviewed;
- no recurrent job, scheduler, CI run, or shared agent environment.

## Required confirmation

Before any future command performs network I/O, the operator must see a visible warning and confirm the exact run interactively by typing:

```text
SAT REAL METADATA SMOKE
```

There is no `--yes` bypass for the first live smoke.

The warning must include:

- live SAT access is about to be attempted;
- real e.firma custody is involved;
- output and artifacts must remain redacted;
- the run must stop if the terminal is not interactive.

## Live smoke gate

| Gate | Required evidence |
|---|---|
| Human approval | Issue or PR comment from Carlos approving this specific run. |
| Local-only execution | Confirmation that the command ran outside CI and outside any shared agent environment. |
| Secret custody | Confirmation that e.firma material stayed outside the repository and was handled through local approved custody only. |
| Output redaction | Confirmation that copied output contains no RFC, token, certificate path, key path, SAT package id, XML path, or downloaded content. |
| Cleanup | Final `git status --short`, scanner result, and cleared live env vars. |

Do not attach raw terminal logs. Summarize the result with redacted fields only.

## Allowed evidence template

Use this template in the issue or PR after a manually approved smoke:

```markdown
## MANUAL-SAT-001 result

- Approval: <issue-or-comment-link>
- Date: <YYYY-MM-DD>
- Operator: Carlos
- Environment: local operator machine, not CI
- Scope: metadata-only, smallest approved date range
- Result: passed / failed / blocked
- Request outcome: redacted
- Package/XML persistence: none for metadata-only smoke, or redacted counts only if separately approved later
- Live env vars cleared after run: yes
- Scanner after run: passed
- Tests after run: passed
- Working tree after run: clean
- Sensitive data committed: no

Notes:
- <redacted operational note, no paths or identifiers>
```

## Forbidden evidence

Never paste or commit:

- e.firma certificate/key files or filenames from the operator machine;
- passwords, tokens, secret values, or secret references;
- authorization headers, SOAP bodies, or raw response payloads;
- real RFCs, taxpayer names, UUIDs, SAT request ids, package ids, metadata rows, XML, ZIPs, or extracted files;
- absolute local paths;
- screenshots that reveal local profile details or fiscal data.

## Abort conditions

Stop the smoke and do not retry automatically if:

- approval is missing or ambiguous;
- a command would run in CI or a non-interactive terminal;
- the working tree is dirty;
- scanner fails;
- `cfdi-vault status` or `cfdi-vault doctor` fails readiness checks;
- the profile is not ready, `passwordRef` is missing, or the approved `SecretProvider` cannot resolve locally;
- `CFDI_VAULT_ALLOW_REAL_SAT=1`, `CFDI_VAULT_ALLOW_REAL_CREDENTIALS=1`, or `--manual-real-sat` is missing;
- the command is non-interactive or the typed confirmation is missing;
- `--kind` is anything other than `metadata`;
- the requested range is more than one calendar day;
- `cfdi-vault doctor` does not pass for the selected profile;
- a command attempts to read real SAT material from the repository;
- output would print tokens, passwords, private keys, certificates, headers, RFCs, paths, XML, ZIPs, or raw SAT payloads;
- real fiscal data appears in any repository path;
- the live command is unavailable or still blocked by product code.

## Rollback and cleanup

After any approved manual attempt:

1. Clear `CFDI_VAULT_ALLOW_REAL_SAT` and `CFDI_VAULT_ALLOW_REAL_CREDENTIALS` from the shell.
2. Inspect generated artifacts and logs before copying any evidence.
3. Run the sensitive fixture scanner again.
4. Confirm `git status --short` is clean.
5. Record only the redacted evidence template above.

## Next step

Keep issue #50 as the approval gate for the actual live smoke. This document only defines the manual process; it does not approve, implement, or execute live SAT access.
