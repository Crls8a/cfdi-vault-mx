# SAT async verify scheduler

`cfdi-vault` treats SAT verification as persisted one-shot work, not as a long-running polling loop. SAT does not send webhooks, so the local state file stores when the next `VerificaSolicitudDescarga` check is allowed to run.

## Quick path

```powershell
cfdi-vault sat verify-due --profile default --dry-run
cfdi-vault sat verify-due --profile default --limit 1
cfdi-vault download status --profile default
```

This slice uses the non-live fake verifier. It does not execute real SAT access, download packages, print full `IdSolicitud`, print raw SOAP, or create new SAT requests.

## Scheduler contract

| Field | Decision |
|---|---|
| `next_check_at` | The next allowed verification time. A worker exits if nothing is due. |
| `attempt_count` | Incremented once per verify attempt. It prevents endless retries. |
| `expires_at` | Defaults to 72 hours after the accepted request. Expired work becomes terminal. |
| `package_refs_redacted` | Stores non-reversible package fingerprints when SAT says the request is ready. |

Initial backoff policy:

| Completed attempts | Next delay |
|---:|---|
| 0 | 5 minutes after request acceptance |
| 1 | 15 minutes |
| 2 | 30 minutes |
| 3 | 1 hour |
| 4+ | 2-4 hours with deterministic jitter |

`max_attempts` defaults to 12 and is configurable in code through `VerifyBackoffPolicy`.

## Worker behavior

`cfdi-vault sat verify-due --profile <PROFILE_ID> --limit 1`:

1. Loads persisted live metadata request state from the profile storage root.
2. Selects requests where `next_check_at <= now`.
3. Verifies at most `--limit` requests once each.
4. Updates state and schedules the next check when the outcome is retryable.
5. Exits.

The command intentionally does not sleep, loop, create a new SAT request, or download packages.

## Terminal states

The scheduler stops retrying on:

- `VERIFY_NO_DATA`
- `VERIFY_REJECTED`
- `VERIFY_EXPIRED`
- `VERIFY_MANUAL_REVIEW`
- `VERIFY_FAILED_PERMANENT`
- `PACKAGE_READY`

`VERIFY_MANUAL_REVIEW` is for terminal outcomes that must not be collapsed into `no_data` or retried blindly, such as duplicate/quota-like SAT
responses or a finished response without package ids.

`PACKAGE_READY` only records redacted package references and counts when SAT returns package ids. Package download remains a separate gated step.

## What not to do

Do not wrap verify in this shape:

```text
while True:
    verify()
    sleep(30)
```

That hides state in a process. The correct shape is persisted state plus a scheduled one-shot command:

```text
submit request -> persist state -> set next_check_at -> run verify-due once -> update state -> exit
```

## Windows Task Scheduler shape

After a future live verifier is gated and approved, Windows Task Scheduler should call the one-shot command periodically:

```powershell
cfdi-vault sat verify-due --profile default --limit 1
```

The schedule frequency belongs to Windows. Backoff enforcement belongs to `next_check_at`, so even a frequent task should not produce aggressive SAT retries.
