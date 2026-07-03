# Offline/local SAT download operations

This runbook is the docs-only FASE 12 path for issue #51. It proves the current fake/offline download workflow without real SAT access, real e.firma use, fiscal data, secrets, certificates, SAT ZIPs, or live smoke execution.

> Scope boundary: issue #50 remains the human-gated live SAT smoke. This document does not authorize, execute, or close that gate.

## Quick offline demo

Use an already configured synthetic/local profile. Keep the output redacted in issues and PRs.

```powershell
cfdi-vault status --profile-id <profile>
cfdi-vault doctor

cfdi-vault download plan `
  --profile <profile> `
  --from 2024-01-01 `
  --to 2024-01-31 `
  --kind cfdi `
  --direction received

cfdi-vault download request `
  --profile <profile> `
  --from 2024-01-01 `
  --to 2024-01-31 `
  --kind cfdi `
  --direction received

cfdi-vault download sync `
  --profile <profile> `
  --from 2024-01-01 `
  --to 2024-01-31 `
  --kind cfdi `
  --direction received

cfdi-vault download status --profile <profile> --job-id <job-id-from-sync>
```

Expected safe shape:

| Step | Expected evidence | Do not paste |
|---|---|---|
| `status` / `doctor` | Redacted profile readiness and dependency health. | Profile JSON, secret references, certificates, real local paths. |
| `download plan` | `mode=fake`, criteria hash, range, kind, direction, `will_submit=false`. | Real RFCs or personal storage roots. |
| `download request` | Synthetic request accepted proof; this is not the persisted job. | Raw SOAP, real SAT ids, credentials. |
| `download sync` | `mode=fake`, `job_id`, synthetic `request_id`, `status=succeeded`, metadata count. | Package ids, storage keys, XML/ZIP content. |
| Internal package/XML behavior | For `--kind cfdi`, the sync stores metadata, package ZIP bytes, extracted XML evidence, hashes, and SQLite rows under the profile storage root. | Treat this as internal behavior; there is no separate package extraction CLI command yet. |
| `download status` | Safe aggregate readback: job/request ids, status, SAT state, kind, direction, criteria hash, metadata/package/XML counts. | Queue payloads or event messages, because they may include package ids and storage keys. |

## Active and cancelled fake evidence

The full CLI demo proves the active path: synthetic metadata rows are `vigente`, packages are stored, XML evidence is extracted for `--kind cfdi`, and `download status` should show `status=succeeded` with non-zero counts.

Cancelled reconciliation is an offline/internal evidence path, not a live command. Existing metadata/reconciliation docs and tests define this behavior:

| Synthetic signal | Expected local decision |
|---|---|
| Metadata status `Vigente` / `active`, no XML yet | `DISCOVERED_IN_METADATA` or `XML_PENDING`; XML download is allowed. |
| Metadata status `Cancelado` / `cancelled` | `CANCELLED_METADATA`; do not blindly retry XML; status confirmation is required. |
| XML evidence already exists | `XML_DOWNLOADED`; no retry unless metadata status changed. |

If an issue needs cancelled evidence, summarize the state transition only. Do not attach raw metadata rows, UUIDs, DB dumps, or files.

## Troubleshooting outcomes

Use this table with [Statuses, limits, and errors](statuses-limits-errors.md), [Metadata-first reconciliation](metadata-first-reconciliation.md), and [User-facing errors](user-facing-errors.md).

| Outcome | Meaning | Local action |
|---|---|---|
| `active` | SAT/status says the CFDI is active (`Vigente`). | Continue with XML recovery unless XML evidence already exists. |
| `cancelled` | SAT/status or metadata says the CFDI is cancelled. | Stop blind XML retries; classify as cancellation/state-check work. |
| `not_found` | SAT/status says the CFDI is not available. | Treat as terminal unless the query criteria are clearly wrong. |
| `unauthorized` | Requester cannot consult the RFC/CFDI. | Stop; check profile/RFC authorization. Live follow-up belongs to #50. |
| `retryable` | Timeout, rate limit, temporary unavailable, or transient SAT error. | Retry later with backoff; do not loop immediately. |
| `permanent` | Invalid request, rejected state, threshold, or terminal validation failure. | Mark failed/manual-review; fix criteria before a new request. |
| `unknown` | Code/status is not mapped. | Retry once only if safe, then manual review with redacted evidence. |

## Backup and restore

Back up only local runtime state outside the repository. Use encrypted local backup tooling controlled by the operator.

| Item | Default shape | Guidance |
|---|---|---|
| App profile root | `%LOCALAPPDATA%\cfdi-vault-mx\profiles\<profile>\` | Contains profile configuration and local references. Do not commit it. |
| Profile storage root | `%LOCALAPPDATA%\cfdi-vault-mx\storage\<profile>\` or configured `storage_root` | Contains metadata, packages, XML, logs, exports, and DB folders. Treat as sensitive runtime data. |
| Recovery SQLite DB | `<storage_root>\db\recovery.sqlite3` | Back up with the storage root while the CLI/workers are stopped. |

Restore checklist:

1. Stop CLI workers or background processes using the profile.
2. Restore the profile folder and storage root to the same logical layout.
3. Recreate local secret-provider entries if the machine changed; do not move secrets through git or chat.
4. Run `cfdi-vault status --profile-id <profile>` and `cfdi-vault doctor`.
5. Run `cfdi-vault download status --profile <profile> --job-id <job-id>` for known synthetic jobs.

Never place backups, SQLite files, profile JSON, logs, ZIPs, XML, certificates, keys, or passwords inside the repo.

## Local observability

Prefer aggregate evidence over raw logs.

Safe to summarize:

- command name and fake/offline mode;
- status/action (`succeeded`, `retryable`, `permanent_failure`, etc.);
- counts for metadata, packages, downloaded packages, and XML evidence;
- redacted job/request references such as `<job-id>` and `<request-id>`.

Do not paste:

- real RFCs, UUIDs, SAT request ids, package ids, taxpayer names, or fiscal amounts;
- raw XML, metadata rows, SAT ZIP content, SOAP envelopes, DB dumps, or queue payloads;
- certificate/key filenames, fingerprints, passwords, tokens, secret references, or profile JSON;
- absolute local paths or screenshots that reveal operator machine details.

## Live SAT boundary

FASE 12 is offline/local release hardening for issue #51 only. The live SAT smoke remains issue #50 and must follow [MANUAL-SAT-001](manual-sat-runbook.md): explicit Carlos approval, local operator machine, redacted evidence, clean working tree, scanner, and tests.

If the live command is unavailable, still blocked, or requires real e.firma/SAT access, stop. Do not convert this runbook into a live smoke.

## Follow-up proposal

Future work may add a small package/status CLI or desktop view for local operators, for example:

- package list by redacted job id;
- package/download/XML counts without raw paths;
- desktop read-only status cards for active, cancelled, retryable, permanent, and unknown outcomes.

That is a proposal only. It needs its own approved issue before implementation.
