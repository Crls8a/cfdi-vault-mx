# MANUAL-SAT-001: human-gated live SAT smoke runbook

Target contract:
SAT Descarga Masiva CFDI y CFDI de Retenciones v1.5, mayo 2025.

Allowed sources:
- V1_5_CONTRACT
- RUNTIME_WSDL
- COMMUNITY_ORACLE as implementation oracle only

Forbidden as operational contract:
- v1.2
- 2023 manuals
- legacy endpoints
- forums/blogs/snippets
- old prompts


This runbook defines the approval and evidence rules for any future real SAT smoke. It does not authorize live SAT execution by itself, and it must never run in CI.

## Current status

Live SAT access is available only behind the human-gated smoke/diagnostic commands below. This runbook does not approve a run by itself.

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

The verify-only v1.5 live gate adds two explicit opt-ins before any network I/O:

| Gate | Required value |
|---|---|
| Verify live gate opt-in | `CFDI_VAULT_SAT_LIVE=1` |
| Production-signed verify opt-in | `CFDI_VAULT_SAT_PRODUCTION_SIGNED=1` |

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

cfdi-vault sat diagnose-live `
  --profile <PROFILE_ID> `
  --from <YYYY-MM-DD> `
  --to <YYYY-MM-DD> `
  --kind metadata `
  --direction received `
  --manual-real-sat

cfdi-vault sat verify-live-gate `
  --profile <PROFILE_ID> `
  --request-ref <REQUEST_REF> `
  --manual-real-sat `
  --permit <PERMIT_ID> `
  --connect-timeout-seconds 15 `
  --read-timeout-seconds 60
```

Use `--direction issued` only when that exact direction is approved for the manual run.

If `download live-smoke` fails with `error=live_adapter_failed`, run `sat diagnose-live` once only if the same approval still covers diagnostics. Do not retry automatically.

If any command returns `error=live_adapter_unavailable`, stop. That means the safety gates passed, but the real SAT adapter is not wired for execution. Do not fall back to `sync metadata --live`.

## Diagnostic path after a failed smoke

Use `sat diagnose-live` to identify the failed stage without copying raw SOAP:

```powershell
cfdi-vault sat diagnose-live `
  --profile <PROFILE_ID> `
  --from <YYYY-MM-DD> `
  --to <YYYY-MM-DD> `
  --kind metadata `
  --direction received `
  --manual-real-sat
```

Allowed diagnostic fields to copy into #50:

- `diagnostic_status`
- `stages`
- `failed_stage`
- `error_kind`
- `safe_hint`
- `endpoint`
- `http_status`
- `soap_fault_code`
- `sat_code`
- `payload_size`
- `envelope_sha256`
- `duration_ms`
- `correlation_id`

Do not copy raw SOAP, headers, terminal transcript, RFCs, request ids, package ids, UUIDs, file paths, or credential details.

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

## Verify v1.5 live gate

Use `sat verify-live-gate` only after one metadata request has already been accepted and persisted locally as a redacted `request-ref`.

This command performs, in order:

1. redacted preflight only;
2. local production-signed `VerificaSolicitudDescarga` oracle parity;
3. public read-only verify WSDL/endpoint reachability check without e.firma material;
4. at most one live auth + verify attempt with the configured gate timeouts.

It does not create a new request, download packages, persist XML/PDF, or store raw SOAP/SAT responses.

Gate timeout controls:

- `--connect-timeout-seconds` defaults to 15 seconds and applies to the gate's public WSDL/endpoint check and guarded SOAP connect phase when separate gate timeouts are enabled.
- `--read-timeout-seconds` defaults to 60 seconds and may be explicitly raised up to 180 seconds for this gate only.
- `CFDI_VAULT_VERIFY_GATE_CONNECT_TIMEOUT_SECONDS` and `CFDI_VAULT_VERIFY_GATE_READ_TIMEOUT_SECONDS` are local fallback overrides when the flags are omitted.
- The normal SAT runtime path is not changed by these gate-only diagnostics.

Required extra evidence:

- `production_signed=yes`;
- `oracle_parity=passed`;
- `wsdl_check=passed`;
- `connect_timeout_seconds=15` or the approved timeout;
- `read_timeout_seconds=60` or the approved timeout;
- `raw_wsdl_persisted=no`;
- `download_executed=no`;
- `raw_soap_persisted=no`;
- `raw_response_persisted=no`.

Local gate result on 2026-07-08:

First preflight-only attempt:

- live SAT executed: no;
- production-signed: no;
- oracle parity: not run;
- read timeout: 60 seconds;
- reason: preflight blocked by missing `CFDI_VAULT_SAT_LIVE`, missing `CFDI_VAULT_SAT_PRODUCTION_SIGNED`, missing `--manual-real-sat`, missing `--permit`, and missing `--request-ref`.

Controlled rerun after resolving the missing preflight inputs:

- live SAT executed: yes;
- production-signed: yes;
- oracle parity: passed;
- read timeout: 60 seconds;
- preflight: ready;
- `EstadoSolicitud`: not run;
- `CodigoEstado`: not reported;
- `NumeroCFDIs`: not reported;
- `IdsPaquetes`: not run;
- download executed: no;
- raw SOAP persisted: no;
- raw SAT response persisted: no;
- result: not completed because the single live verify attempt reached the approved read timeout (`error_kind=verify_read_timeout`).

The controlled rerun used a clean detached worktree at the same gate commit to avoid stashing, deleting, or mixing unrelated local documentation edits present in the main worktree.

Controlled timeout-diagnostics rerun after adding gate-only connect/read timeout controls:

- live SAT executed: yes;
- production-signed: yes;
- oracle parity: passed;
- WSDL/endpoint check: passed;
- WSDL HTTP status: 200;
- WSDL elapsed: 392 ms;
- connect timeout: 15 seconds;
- read timeout: 180 seconds;
- verify elapsed: not reported by this run;
- preflight: ready;
- `EstadoSolicitud`: accepted;
- `CodigoEstado`: not reported;
- `NumeroCFDIs`: not reported;
- `IdsPaquetes`: none;
- download executed: no;
- raw WSDL persisted: no;
- raw SOAP persisted: no;
- raw SAT response persisted: no;
- result: completed; the verify response was received without packages and no download was attempted.

## Package/download offline gate

The package/download contract is prepared offline only. It does not authorize or execute a real package download.

Current offline scope:

1. Build the `Descargar` SOAP envelope with `peticionDescarga`.
2. Keep the WRAP token in the HTTP `Authorization` header, never in XML.
3. Sign the v1.5 operation wrapper with exclusive c14n and `X509IssuerSerial` + `X509Certificate`.
4. Parse a synthetic `Paquete` base64 response as ZIP bytes.
5. Block download unless verify has `EstadoSolicitud=3` and at least one package id.

Next live step is allowed only after a future verify result returns packages:

- `EstadoSolicitud=3`;
- `IdsPaquetes` present;
- Carlos approves that exact live package/download gate;
- no XML/PDF parsing is enabled in the same run;
- copied evidence remains redacted and contains no package id, raw SOAP, raw SAT response, token, RFC, or ZIP bytes.

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
- Diagnostic command: not run / `sat diagnose-live`
- Diagnostic status: redacted
- Failed stage: redacted or n/a
- Error kind: redacted or n/a
- Safe hint: redacted or n/a
- HTTP status: redacted or n/a
- SAT code: redacted or n/a
- Correlation id: synthetic local id or n/a
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
- `CFDI_VAULT_SAT_LIVE=1`, `CFDI_VAULT_SAT_PRODUCTION_SIGNED=1`, `--permit`, or `--request-ref` is missing for `sat verify-live-gate`;
- the command is non-interactive or the typed confirmation is missing;
- `--kind` is anything other than `metadata`;
- the requested range is more than one calendar day;
- `cfdi-vault doctor` does not pass for the selected profile;
- a command attempts to read real SAT material from the repository;
- output would print tokens, passwords, private keys, certificates, headers, RFCs, paths, XML, ZIPs, or raw SAT payloads;
- real fiscal data appears in any repository path;
- the live command is unavailable or still blocked by product code;
- a second diagnostic retry would be needed without a new explicit approval.

## Rollback and cleanup

After any approved manual attempt:

1. Clear live SAT opt-in environment variables from the shell.
2. Inspect generated artifacts and logs before copying any evidence.
3. Run the sensitive fixture scanner again.
4. Confirm `git status --short` is clean.
5. Record only the redacted evidence template above.

PowerShell cleanup:

```powershell
Remove-Item Env:CFDI_VAULT_ALLOW_REAL_SAT -ErrorAction SilentlyContinue
Remove-Item Env:CFDI_VAULT_ALLOW_REAL_CREDENTIALS -ErrorAction SilentlyContinue
Remove-Item Env:CFDI_VAULT_SAT_LIVE -ErrorAction SilentlyContinue
Remove-Item Env:CFDI_VAULT_SAT_PRODUCTION_SIGNED -ErrorAction SilentlyContinue
git status --short
py scripts/scan_sensitive_fixtures.py --root .
```

## Next step

Keep issue #50 as the approval gate for the actual live smoke. This document only defines the manual process; it does not approve, implement, or execute live SAT access.
