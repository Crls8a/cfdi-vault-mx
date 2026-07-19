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
