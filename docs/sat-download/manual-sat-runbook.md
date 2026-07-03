# MANUAL-SAT-001: human-gated live SAT smoke runbook

This runbook defines the approval and evidence rules for any future real SAT smoke. It does not authorize live SAT execution by itself, and it must never run in CI.

## Current status

Live SAT remains blocked in this repository.

Before any real SAT/e.firma action, all of these must be true:

1. Carlos explicitly approves the one-time smoke in the issue or PR.
2. The live SAT smoke issue is approved for that exact run.
3. The command is run only on the operator machine.
4. No real certificate, key, password, token, SAT ZIP, metadata, XML, RFC, or local path is copied into git, logs, screenshots, fixtures, or PR text.
5. The local working tree is clean before and after the smoke.

If any item is false, stop.

## Safe preflight

Run only repository-safe checks first:

```bash
git status --short
cfdi-vault status
cfdi-vault doctor
python scripts/scan_sensitive_fixtures.py --root .
python -m pytest
```

Expected result:

- the working tree is clean;
- status and doctor output are redacted;
- scanner passes;
- tests pass;
- no live SAT command has been executed.

## Live smoke gate

| Gate | Required evidence |
|---|---|
| Human approval | Issue or PR comment from Carlos approving this specific run. |
| Local-only execution | Confirmation that the command ran outside CI and outside any shared agent environment. |
| Secret custody | Confirmation that e.firma material stayed outside the repository and was handled through local approved custody only. |
| Output redaction | Confirmation that copied output contains no RFC, token, certificate path, key path, SAT package id, XML path, or downloaded content. |
| Cleanup | Final `git status --short` and scanner result. |

Do not attach raw terminal logs. Summarize the result with redacted fields only.

## Allowed evidence template

Use this template in the issue or PR after a manually approved smoke:

```markdown
## MANUAL-SAT-001 result

- Approval: <issue-or-comment-link>
- Date: <YYYY-MM-DD>
- Operator: Carlos
- Environment: local operator machine, not CI
- Scope: one live SAT smoke for the approved RFC profile
- Result: passed / failed / blocked
- Request outcome: redacted
- Package/XML persistence: redacted counts only
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
- passwords, tokens, or secret references;
- real RFCs, taxpayer names, UUIDs, SAT request ids, package ids, metadata rows, XML, ZIPs, or extracted files;
- absolute local paths;
- screenshots that reveal local profile details or fiscal data.

## Abort conditions

Stop the smoke and do not retry automatically if:

- approval is missing or ambiguous;
- a command would run in CI;
- output is not redacted;
- the working tree is dirty;
- scanner fails;
- real fiscal data appears in any repository path;
- the live command is unavailable or still blocked by product code.

## Next step

Keep issue #50 as the approval gate for the actual live smoke. This document only defines the manual process; it does not implement or execute live SAT access.
