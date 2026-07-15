# SAT async verify scheduler

`cfdi-vault` treats SAT verification as persisted one-shot work, not as a long-running polling loop. SAT does not send webhooks, so the local state file stores when the next `VerificaSolicitudDescarga` check is allowed to run.

## Quick path

```powershell
cfdi-vault sat verify-due-runner --profile default --dry-run
cfdi-vault sat scheduler render-windows-task --profile default --working-directory C:\reviewed\cfdi-vault-mx
cfdi-vault download status --profile default
```

SAT-SCHED-001 provides the locked runner core, bounded scheduler grant model,
dry-run CLI, and pure XML renderer. Recurring live activation is **not enabled**:
non-dry CLI runs fail closed with `reason=activation-not-enabled`. The slice
does not call SAT, create requests, download packages, parse XML, or render PDF.

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

The core runner:

1. Acquires `state/sat-verify-due.lock` for the entire shared-state cycle.
2. Claims one invocation from a separate scheduler grant for authorized runs.
3. Reuses `run_verify_due(..., limit=1)`; the limit is not configurable.
4. Updates state/backoff through the existing verify policy and exits.

Dry-run still takes and releases the lock, but does not mutate request state,
claim a grant, or call a verifier. The persistent lock file is held by an OS
lock handle for the complete invocation (`msvcrt` on Windows; `fcntl` for test
portability). Process death releases the OS lock automatically. Old metadata is
harmless and is rewritten only after exclusive acquisition; release never
deletes another owner's pathname.

## Scheduler grant boundary

The scheduler grant is not a `LiveExecutionPermit`. It is bound to the profile,
repository path fingerprint, and `sat_due_verify_one` scope. It expires within
24 hours, allows at most 288 invocations, fixes per-request verification to 12
attempts, and explicitly denies request creation, download, XML, and PDF.

Persisted grant windows also fail closed: creation cannot be in the future,
creation must precede expiry, lifetime cannot exceed 24 hours, and consumed
invocations must remain between zero and the configured maximum.

Grant claims are serialized and persisted before verification. SAT-SCHED-001
does not expose grant issuance or live activation in the CLI; those remain a
separate human-approved change.

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

The rendered XML is a review-only template. It runs every five minutes, uses
`MultipleInstancesPolicy=IgnoreNew`, `ExecutionTimeLimit=PT4M`, and least
privilege. The required reviewed `WorkingDirectory` fixes the repository used
for grant binding instead of trusting an ambient scheduler directory. Its
one-shot action is:

```powershell
cfdi-vault sat verify-due-runner --profile default --grant SCHEDULER_GRANT_ID
```

The renderer never registers or installs the task. The placeholder cannot be
activated by this slice; `USER_SID` is also a review placeholder. Windows frequency only wakes the process;
`next_check_at` remains the retry authority.
