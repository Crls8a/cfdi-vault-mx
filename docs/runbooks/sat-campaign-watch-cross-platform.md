# Unattended re-check of an authorized live SAT campaign grant

This runbook covers Windows, macOS, and Linux. Since ADR 0005, unattended
re-checking is two separate processes, not one:

1. **The watch script** (`scripts/sat_campaign_watch.ps1` /
   `scripts/sat_campaign_watch.sh`, this runbook) queues a durable
   `sat_campaign_runs` row for a campaign/grant a human already created and
   authorized (`POST /api/campaign/{profile}/create` /
   `.../authorize` in the control panel — see ADR 0006; the retired
   `cfdi-vault sat campaign create`/`authorize` commands no longer exist).
   It never creates, authorizes, or expands a grant on its own, and it never
   contacts SAT itself — it only enqueues.
2. **The campaign-run consumer** (`cfdi-vault-campaign-run-worker`) claims
   the queued row and does the actual work. It must be running somewhere on
   the same host, either as a persistent `--loop` process or on its own
   schedule (`--once`, see `sat_windows_task.py::render_windows_task_xml`
   for a Task Scheduler template). **The watch script alone does nothing
   without this also running.**

Both `enqueue_campaign_run` (what the watch script calls) and the worker's
own execution are idempotent/no-op-safe when nothing is due: `enqueue_campaign_run`
returns the existing active run instead of duplicating it
(`src/cfdi_vault/sat_campaign_repository_runs.py`), and the worker's own
`next_check_at <= now` gate (`src/cfdi_vault/sat_campaign_repository.py`)
makes a claimed run that finds nothing due a safe, quick no-op. So scheduling
the watch script frequently does not spam SAT with extra contact.

Neither process accepts, prints, or persists the FIEL phrase. Only the
worker ever reads it, and only through the platform's own native secret
store — the same one `POST /api/setup` / the FIEL wizard already wrote it
to:

| Platform | Secret store | Watch-script scheduler | Worker scheduler |
|---|---|---|---|
| Windows | Windows Credential Manager | Task Scheduler | Task Scheduler (`--once`) or a persistent `--loop` process |
| macOS | Keychain | launchd user agent | launchd user agent or terminal `--loop` |
| Linux | Secret Service (GNOME Keyring) or KWallet | systemd `--user` timer | systemd `--user` service or terminal `--loop` |

**`sat-monitor` (the docker-compose service) cannot run the worker's half of
this on any of the three.** It runs inside a Linux container, so it has no
path to Windows Credential Manager or macOS Keychain, and even for the Linux
Secret Service/KWallet case, a container has no D-Bus session bus to the
host user's unlocked keyring. Host-side scheduling is the only path that
works regardless of platform — for the worker, not just the watch script.

You will need four values from the campaign you already created and
authorized: `--profile`, `--campaign-ref`, `--grant`, and `--commit-ref`
(the exact commit hash the campaign/grant were authorized against — see the
panel's create/authorize response, or `grant_ref`/`expires_at` from
`POST /api/campaign/{profile}/{campaign}/authorize`).

## Windows (Task Scheduler)

Register the watch script (enqueue side):

```powershell
$repoRoot = "<repo checkout>"
$scriptPath = Join-Path $repoRoot "scripts\sat_campaign_watch.ps1"
$argumentList = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" " +
  "-ProfileId `"<profile>`" -CampaignRef `"<campaign-ref>`" " +
  "-GrantRef `"<grant-ref>`" -CommitRef `"<commit-ref>`""

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argumentList -WorkingDirectory $repoRoot
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 30)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -Hidden
Register-ScheduledTask -TaskName "CfdiVaultMx-SatCampaignWatch" -Action $action -Trigger $trigger -Settings $settings -Force
```

`-WindowStyle Hidden` plus the task's own `-Hidden` setting keep a console
window from flashing on screen every 15 minutes; only the log file changes.

Log: `%LOCALAPPDATA%\cfdi-vault-mx\logs\sat-campaign-watch.log`.
Registered without an explicit principal, so it runs as the current user
and only fires while that user is logged on — irrelevant to this script
itself (it never touches Credential Manager), but required for the worker
task below, which does.

Stop it: `Unregister-ScheduledTask -TaskName "CfdiVaultMx-SatCampaignWatch" -Confirm:$false`.

`RepetitionDuration` is intentionally bounded (30 days, not indefinite):
`Register-ScheduledTask` rejects `[TimeSpan]::MaxValue` as an out-of-range
XML duration, and a bounded window also forces a periodic human check-in
before a grant's own 1-14 day expiry.

Now register the worker (execution side) — render the task XML with
`sat_windows_task.py::render_windows_task_xml(working_directory=...)` and
import it, or run `cfdi-vault-campaign-run-worker --loop` in a persistent
window/service instead. Set `CFDI_VAULT_LIVE_WORKER_ENABLED=1`,
`CFDI_VAULT_COMMIT_REF`, and the other live-worker environment variables on
*this* process only — never on the watch-script task above (see ADR 0005).

## macOS (launchd)

1. Make the shared shell script executable once: `chmod +x scripts/sat_campaign_watch.sh`.
2. Copy `scripts/templates/com.cfdi-vault-mx.sat-campaign-watch.plist.example`
   to `~/Library/LaunchAgents/com.cfdi-vault-mx.sat-campaign-watch.plist`
   and replace every `<REPLACE_*>` placeholder (repo path, profile,
   campaign ref, grant ref, commit ref, home directory).
3. Load it:

   ```bash
   launchctl load ~/Library/LaunchAgents/com.cfdi-vault-mx.sat-campaign-watch.plist
   ```

Runs as a **user agent**, not a system daemon. The template itself only
enqueues; separately run `cfdi-vault-campaign-run-worker --loop` (its own
launchd agent, or a terminal session that stays open) to actually process
what gets queued — that process is the one that needs the logged-in user's
unlocked Keychain, not this one.

Log: `~/Library/Application Support/cfdi-vault-mx/logs/sat-campaign-watch.log`
(script's own log) plus `...logs/sat-campaign-watch.launchd.log` (launchd
stdout/stderr, mainly useful if the script itself fails to start).

Stop it: `launchctl unload ~/Library/LaunchAgents/com.cfdi-vault-mx.sat-campaign-watch.plist`.

## Linux (systemd `--user` timer)

1. Make the shared shell script executable once: `chmod +x scripts/sat_campaign_watch.sh`.
2. Copy both templates from `scripts/templates/` into
   `~/.config/systemd/user/`, dropping the `.example` suffix
   (`sat-campaign-watch.service`, `sat-campaign-watch.timer`), and replace
   every `<REPLACE_*>` placeholder in the `.service` file.
3. Enable:

   ```bash
   systemctl --user daemon-reload
   systemctl --user enable --now sat-campaign-watch.timer
   ```

4. If this account is not always logged in interactively, also run once:

   ```bash
   loginctl enable-linger "$USER"
   ```

   so the `--user` systemd instance keeps running after logout.
   `enable-linger` alone does not guarantee the Secret Service/KWallet
   keyring stays unlocked without any interactive login — but that only
   matters for the worker unit below, not this enqueue-only timer; if the
   worker's log shows repeated read/verify failures, log in at the desktop
   at least once so the keyring unlocks, and prefer a keyring configured to
   unlock automatically at login over disabling its lock screen behavior.

Separately, run `cfdi-vault-campaign-run-worker --loop` as its own
`--user` systemd service (or a terminal session kept open) to process what
this timer queues.

Log: `~/.local/share/cfdi-vault-mx/logs/sat-campaign-watch.log` (or
`$XDG_DATA_HOME/cfdi-vault-mx/logs/...` if `XDG_DATA_HOME` is set).

Stop it: `systemctl --user disable --now sat-campaign-watch.timer`.

## Common failure modes on any platform

- **Watch-script log shows `"status": "rejected"`**: the enqueue's own
  pre-checks failed before anything was queued — the JSON `reason` field is
  one of `sat_campaign_db_cli.CampaignDatabaseError`'s codes (for example
  `campaign-not-found`, `campaign-grant-invalid`, `campaign-lane-required`).
  Nothing was queued; nothing will run. Re-check the profile/campaign/grant
  refs and the grant's expiry.
- **Watch-script log shows a `run_ref` but nothing seems to happen**: the
  row is queued but the worker isn't running, or hasn't reached it yet.
  Confirm `cfdi-vault-campaign-run-worker` is actually running on this host
  (`--loop` process alive, or its own scheduled task/timer firing), and
  check `GET /api/campaign/{profile}/{campaign}/status`'s `last_run` field
  for the terminal outcome once it does.
- **`last_run.result_code=commit-ref-mismatch`**: the worker process's own
  `CFDI_VAULT_COMMIT_REF` doesn't match what the grant was authorized
  against. This is deliberately fatal, not auto-corrected (ADR 0005) —
  update the worker's environment and let it pick the row up again, or let
  the reaper abandon it after its lease expires.
- **`last_run.result_code=runner-unavailable`**: the worker's own
  `_build_worker_factories` construction failed — a local misconfiguration
  on the worker's host (missing `CFDI_STORAGE_ROOT`/`RABBITMQ_URL`,
  `credential-provider-unsupported` if this ever ran in a container instead
  of the host, etc.). The reason itself is redacted by design; check the
  worker process's own logs directly for detail.
- **`last_verify_result=pending` for a long time**: normal. SAT can take
  hours to finish generating a metadata package; this is not a local
  failure, and `next_check_at` backs off automatically as attempts
  accumulate.
- **Grant expiry**: each grant is valid 1-14 days
  (`POST /api/campaign/{profile}/{campaign}/authorize`, `expires_days`).
  A watcher that outlives the grant will start failing with a grant-invalid
  reason; that is a required human re-authorization checkpoint, not a bug
  to route around.
