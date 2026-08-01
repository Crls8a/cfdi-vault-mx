# Unattended re-check of an authorized live SAT campaign grant

This runbook covers Windows, macOS, and Linux. It only re-runs
`cfdi-vault sat campaign run` for a campaign/grant a human already created
and authorized (`cfdi-vault sat campaign create` / `authorize`); none of
these mechanisms create, authorize, or expand a grant on their own. The
campaign repository's own `next_check_at <= now` filter
(`src/cfdi_vault/sat_campaign_repository.py`) makes calls before the due
time a safe no-op, so a 15-minute schedule does not spam SAT with extra
contact.

None of the three paths accept, print, or persist the FIEL phrase. Each
resolves it through the platform's own native secret store, the same one
`cfdi-vault setup` / the FIEL wizard already wrote it to:

| Platform | Secret store | Watcher mechanism | Script |
|---|---|---|---|
| Windows | Windows Credential Manager | Task Scheduler | `scripts/sat_campaign_watch.ps1` |
| macOS | Keychain | launchd user agent | `scripts/sat_campaign_watch.sh` |
| Linux | Secret Service (GNOME Keyring) or KWallet | systemd `--user` timer | `scripts/sat_campaign_watch.sh` |

**`sat-monitor` (the docker-compose service) cannot do this job on any of
the three.** It runs inside a Linux container, so it has no path to Windows
Credential Manager or macOS Keychain, and even for the Linux Secret
Service/KWallet case, a container has no D-Bus session bus to the host
user's unlocked keyring. Host-side scheduling is the only path that works
regardless of platform.

You will need four values from the campaign you already created and
authorized: `--profile`, `--campaign-ref`, `--grant`, and `--commit-ref`
(the exact commit hash the campaign/grant were authorized against — see
`cfdi-vault sat campaign create` / `authorize` output).

## Windows (Task Scheduler)

```powershell
$repoRoot = "<repo checkout>"
$scriptPath = Join-Path $repoRoot "scripts\sat_campaign_watch.ps1"
$argumentList = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" " +
  "-ProfileId `"<profile>`" -CampaignRef `"<campaign-ref>`" " +
  "-GrantRef `"<grant-ref>`" -CommitRef `"<commit-ref>`""

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argumentList -WorkingDirectory $repoRoot
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 30)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName "CfdiVaultMx-SatCampaignWatch" -Action $action -Trigger $trigger -Settings $settings -Force
```

Log: `%LOCALAPPDATA%\cfdi-vault-mx\logs\sat-campaign-watch.log`.
Registered without an explicit principal, so it runs as the current user
and only fires while that user is logged on — required, since Windows
Credential Manager entries are per-user.

Stop it: `Unregister-ScheduledTask -TaskName "CfdiVaultMx-SatCampaignWatch" -Confirm:$false`.

`RepetitionDuration` is intentionally bounded (30 days, not indefinite):
`Register-ScheduledTask` rejects `[TimeSpan]::MaxValue` as an out-of-range
XML duration, and a bounded window also forces a periodic human check-in
before a grant's own 1-14 day expiry.

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

Runs as a **user agent**, not a system daemon, so it only runs while that
user is logged in — required to reach the unlocked login Keychain.

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
   keyring stays unlocked without any interactive login; if the watch log
   shows repeated read/verify failures, log in at the desktop at least
   once so the keyring unlocks, and prefer a keyring configured to unlock
   automatically at login over disabling its lock screen behavior.

Log: `~/.local/share/cfdi-vault-mx/logs/sat-campaign-watch.log` (or
`$XDG_DATA_HOME/cfdi-vault-mx/logs/...` if `XDG_DATA_HOME` is set).

Stop it: `systemctl --user disable --now sat-campaign-watch.timer`.

## Common failure modes on any platform

- **Log shows `reason=campaign-live-runtime-unavailable` with no other
  detail**: the CLI redacts the underlying cause. Re-run the same command
  interactively without the watcher to see the real error (for example,
  missing `CFDI_STORAGE_ROOT`/`RABBITMQ_URL`, see
  `_build_artifact_coordinator` in `src/cfdi_vault/sat_live_worker_runtime.py`).
- **`last_verify_result=pending` for a long time**: normal. SAT can take
  hours to finish generating a metadata package; this is not a local
  failure, and `next_check_at` backs off automatically as attempts
  accumulate.
- **Grant expiry**: each grant is valid 1-14 days
  (`cfdi-vault sat campaign authorize --expires-days`). A watcher that
  outlives the grant will start failing with a grant-invalid reason; that
  is a required human re-authorization checkpoint, not a bug to route
  around.
