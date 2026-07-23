# SAT campaign monitor design

SAT verification is persisted one-shot work, not an in-process polling loop.
The public operation is:

```text
cfdi-vault sat campaign run --profile <profile> --campaign-ref <campaign-ref> --grant <grant-ref>
```

The command wakes, acquires the PostgreSQL-backed monitor lease, processes only
due operations, and exits. A future Windows Task Scheduler or POSIX cron entry
may invoke this same command every five minutes after a separate operational
review; the application does not install or activate either task.

## Due-time contract

| Field | Contract |
|---|---|
| `next_check_at` | Earliest permitted VERIFY contact; no due work means no SAT contact. |
| `verify_history` | Private append-only attempt history; public status exposes aggregates only. |
| `service_window_expires_at` | New requests use a 48-hour local window; legacy requests retain their stored deadline. |
| `package_refs_redacted` | Private non-reversible package references when SAT reports readiness. |

The deterministic minimum schedule is 5m, 15m, 30m, 1h, 2h, 4h, and then 8h
between contacts. A later SAT-provided time always wins. No request is
contacted after its service window expires, and no timeout creates a
replacement request.

`next_check_at` being due is not an expiration. It means the request is now
eligible for one VERIFY attempt. `service_window_expires_at` is the independent
48-hour deadline; only that deadline produces `service_window_exceeded`.

## Worker behavior

The runner claims VERIFY before contacting SAT and appends one sanitized result
for each claim. `5004` closes the window as no data; pending, expired,
service-window, and uncertain outcomes remain categorized in PostgreSQL. A
download timeout is uncertain and is not automatically retried. RabbitMQ jobs
carry opaque references only; ZIP/TXT/XML remain in external storage.

## Review-only scheduling shape

An operator may review a platform-specific task that invokes the public
`campaign run` command. It must use the same profile, campaign, grant, and
private storage as the interactive run, enforce one process at a time, and
never add a sleep loop or a second SAT request. The scheduler is an operational
convenience; `next_check_at` remains the sole authority for SAT contact.

## Safe configuration

The adaptive process is disabled unless all gates are explicit. Compose supplies
these non-secret defaults to `sat-monitor`:

| Setting | Default | Purpose |
|---|---:|---|
| `SAT_MONITOR_ENABLED` | `0` | Starts or suppresses the monitor container loop. |
| `CFDI_VAULT_LIVE_WORKER_ENABLED` | `0` | Keeps SAT factories disabled. |
| `SAT_MONITOR_ADAPTIVE_ENABLED` | `0` | Chooses the adaptive listener path; `0` preserves the one-shot/fixed fallback. |
| `SAT_MONITOR_WATCHDOG_SECONDS` | `300` | Upper bound for a missed `NOTIFY` wake; minimum is 60 seconds. |
| `SAT_MONITOR_NOTIFY_CHANNEL` | `sat_schedule_changed` | Fixed PostgreSQL channel required by the V8 trigger; other values are rejected. Payloads remain empty. |
| `SAT_TRANSPORT_TIMEOUT_SECONDS` | `90` | Total limit for one guarded SOAP call; maximum 300 seconds. |
| `SAT_TRANSPORT_CONNECT_TIMEOUT_SECONDS` | `15` | Connection limit; maximum 120 seconds and never above the total limit. |
| `SAT_TRANSPORT_READ_TIMEOUT_SECONDS` | `60` | Read limit; maximum 300 seconds and never above the total limit. |

Safe baseline for a local stack:

```text
SAT_MONITOR_ENABLED=0
CFDI_VAULT_LIVE_WORKER_ENABLED=0
SAT_MONITOR_ADAPTIVE_ENABLED=0
SAT_MONITOR_WATCHDOG_SECONDS=300
SAT_MONITOR_NOTIFY_CHANNEL=sat_schedule_changed
SAT_TRANSPORT_TIMEOUT_SECONDS=90
SAT_TRANSPORT_CONNECT_TIMEOUT_SECONDS=15
SAT_TRANSPORT_READ_TIMEOUT_SECONDS=60
```

`SAT_MONITOR_NOTIFY_CHANNEL` is intentionally fixed. The V8 trigger emits only
`sat_schedule_changed`, so a custom value is rejected rather than silently
falling back to watchdog-only wakes.

`DATABASE_URL`, broker URLs, campaign references, and the external artifact
mount are ordinary runtime settings. e.firma files are deliberately absent
from the Compose service: Windows profile material is never mounted into the
Linux container. Do not put passwords, certificates, keys, RFCs, SAT IDs, or
local machine paths in a scheduler definition.

## Human-reviewed activation

1. Keep `SAT_MONITOR_ENABLED=0` and `CFDI_VAULT_LIVE_WORKER_ENABLED=0` while
   reviewing the commit, grant, PostgreSQL/Flyway state, and storage boundary.
2. Run the one-shot `campaign run` command manually first. It exits when no
   durable operation is due and remains the rollback path if adaptive waiting
   is disabled.
3. Only after explicit approval set `SAT_MONITOR_ENABLED=1`,
   `CFDI_VAULT_LIVE_WORKER_ENABLED=1`, and
   `SAT_MONITOR_ADAPTIVE_ENABLED=1` in the operator environment. The process
   still never waits through SAT I/O; every wake is one bounded runner call.
4. Disable the three flags before rollback or credential/profile maintenance.

## Windows Task Scheduler template

Review the action with `-WhatIf` first. Register it only as the same Windows
user that owns the local profile; do not use a system account or copy the
certificate/key into the task definition.

```powershell
$action = New-ScheduledTaskAction `
  -Execute 'cfdi-vault' `
  -Argument 'sat campaign run --profile <profile> --campaign-ref <campaign-ref> --grant <grant-ref>'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
  -RepetitionInterval (New-TimeSpan -Minutes 5) `
  -RepetitionDuration (New-TimeSpan -Days 2)
Register-ScheduledTask -TaskName 'cfdi-vault-sat-campaign' `
  -Action $action -Trigger $trigger -Description 'Human-reviewed one-shot SAT wake'
```

The task wakes every five minutes, but the command contacts SAT only when the
persisted due gate has passed. Remove or disable the task to roll back; no
request is cancelled or replaced by that action.

## POSIX cron template

Use a private, permission-restricted environment file containing only the
approved non-secret settings and opaque campaign references. The command is
one-shot; cron is only the wake mechanism.

```cron
*/5 * * * * cd <checkout> && umask 077 && . <private-env-file> && \
  cfdi-vault sat campaign run --profile <profile> --campaign-ref <campaign-ref> --grant <grant-ref> \
  >> <private-log-file> 2>&1
```

Review the command and log destination before installing the crontab. Never
mount Windows credential paths on Linux. Remove the line to roll back; the
durable request and its `verify_history` remain in PostgreSQL.

## Operator output contract

Review output is limited to fixed statuses, counts, `next_check_at`, and the
opaque campaign reference needed to resume the operation. It must not contain
RFCs, UUIDs, SAT request/package identifiers, XML/TXT rows, storage paths,
hashes, SOAP, raw exceptions, or secrets. A malformed setting returns a fixed
reason such as `sat-monitor-settings-invalid`; the underlying exception is
never printed.
