# Docker Compose persistence and restart

This repository uses Docker Compose for the durable local services. **PM2 is
not used**: PM2 is a Node.js process manager and does not own Docker
containers, Compose networks, health checks, or named volumes.

## What survives a restart

The following services use `restart: unless-stopped`:

- `postgres` (database volume: `postgres_data`)
- `rabbitmq` (volume: `rabbitmq_data`)
- `redis` (volume: `redis_data`)
- `worker`

If Docker Desktop/the Docker daemon starts again, these containers are
restarted automatically unless an operator explicitly stopped them. The
named volumes preserve durable state. `flyway` remains a one-shot migration
job and is started by its dependency gate; `app` remains a one-shot `doctor`
container. `ledger-publisher` is also intentionally not restarted: its
default `LEDGER_OUTBOX_ENABLED=0` makes it exit cleanly, so a restart policy
would create a busy loop.

`sat-monitor` deliberately has no restart policy. It is disabled by default
and must remain fail-closed until a human-reviewed SAT activation. Do not add
it to an unattended startup task.

## First setup or recovery after `docker compose down`

Enable **Start Docker Desktop when you sign in** in Docker Desktop, then run
the following from the repository checkout:

```powershell
docker compose up -d postgres rabbitmq redis worker
docker compose ps
docker compose logs --tail=50 worker
```

Compose starts `flyway` as required by the dependency graph. The first command
is still required after `docker compose down`, because `down` removes the
containers (the named volumes remain unless `--volumes` is supplied).

## Optional Windows wake task

If Docker Desktop is not guaranteed to be open at sign-in, an operator may
create a Windows Task Scheduler task that runs a one-shot PowerShell command
after Docker Desktop has had time to start:

```powershell
$action = New-ScheduledTaskAction `
  -Execute 'docker.exe' `
  -Argument 'compose up -d postgres rabbitmq redis worker' `
  -WorkingDirectory '<checkout>'
```

Use the same Windows user and checkout used for the local profile. Register
`$action` only after reviewing it, set a short startup delay, and do not place
passwords, certificates, keys, RFCs, SAT identifiers, or storage paths in its
arguments. The task only starts containers; it does not authorize or contact
SAT.

To roll back, disable/remove that task and run:

```powershell
docker compose stop worker
```

Do not use `docker compose down --volumes` unless deliberately deleting the
local database, broker, cache, and artifact volumes.

## Health and troubleshooting

```powershell
docker compose ps
docker compose logs --tail=100 postgres rabbitmq redis worker
docker compose config --quiet
```

`worker` should show `Up`; `postgres`, `rabbitmq`, and `redis` should become
healthy. `ledger-publisher` is expected to show `Exited (0)` while disabled.
Enable it explicitly only when the outbox publisher is needed:

```powershell
$env:LEDGER_OUTBOX_ENABLED = '1'
docker compose up -d ledger-publisher
```

A stopped `sat-monitor` is expected while the SAT feature flags are `0`.
Restart policies do not replace `next_check_at`, claims, or the 48-hour SAT
service window; those remain PostgreSQL rules.

## Observed local recovery (2026-07-24)

Before this runbook was applied, the existing PostgreSQL, RabbitMQ, Redis, and
worker containers had stopped together and still had `restart: no` because
they had been created by an older Compose definition. The named volumes were
still present. The database showed two existing requests, but zero packages,
artifacts, metadata imports, or parsing jobs; worker logs reported no queue
messages. This is local infrastructure evidence only and is not SAT evidence.

The services were recreated with the current definition using `docker compose
up -d postgres rabbitmq redis worker`. Their restart policy is now
`unless-stopped`, and a controlled worker-process restart returned the worker
to `Up`. The disabled `ledger-publisher` was separately recreated with no
restart policy, so it exits once with `feature_disabled` instead of looping.
The SAT monitor was not started and no SAT contact occurred.

At the same status-only check, both existing requests were past their local
service-window deadline and one still had a due verification. Because the
monitor was disabled, the rows were not automatically projected to
`service_window_exceeded`; they remain `uncertain`/`pending` evidence requiring
manual reconciliation. This must not be interpreted as `no_data`, and no
replacement request was created.

## Host port 5432 conflict with a native PostgreSQL service (2026-07-31)

On a machine that already runs PostgreSQL as a native Windows service, that
service can hold host port 5432 before Compose starts. Compose's `postgres`
service still starts and reports healthy internally, but Docker Desktop does
not surface a port-bind error in this situation; `docker inspect` shows an
empty `NetworkSettings.Ports` mapping instead of the expected
`5432/tcp -> 5432`. Any host-side client aimed at `localhost:5432` (the CLI,
the FIEL onboarding wizard's Doctor/Preflight buttons) silently reaches the
unrelated native service instead of the project's container, and fails
authentication because the passwords differ.

Symptom: `cfdi-vault preflight` (or the wizard's Preflight button) reports
`postgresql status=failed reason=local-check-failed` even though `docker
compose ps` shows `postgres` healthy.

Fix: publish the project's Postgres on a different host port and point
`DATABASE_URL` at that port instead. Do not stop or reconfigure the native
service; it may belong to an unrelated project.

```powershell
docker compose stop postgres
docker compose rm -f postgres
$env:POSTGRES_PORT = "5433"
docker compose up -d postgres
docker compose up flyway
```

Do not persist `POSTGRES_PORT` in a repo-root `.env` file: the sensitive
fixture scanner (`scripts/scan_sensitive_fixtures.py`) forbids any `.env`
file's mere presence, regardless of content, so a locally created `.env`
fails that check even though it is `.gitignore`d and never committed. Export
`POSTGRES_PORT` as a shell/session variable instead, or set it as a
Windows user environment variable outside the repository checkout.

## Unattended re-check of an authorized live SAT campaign grant (2026-07-31)

`sat-monitor` (docker-compose service) cannot be used to automate periodic
re-checks on a machine where the FIEL phrase is stored in Windows Credential
Manager: `sat-monitor` runs inside a Linux container and has no path to that
native Windows API. `docker compose up -d sat-monitor` would build and start,
but any live credential resolution inside it would fail closed.

The working alternative is a host-side Windows Scheduled Task that invokes
the CLI directly, where Windows Credential Manager is reachable. It never
creates or authorizes a campaign on its own — it only re-runs
`cfdi-vault sat campaign run` for a grant a human already authorized, and
relies on the campaign repository's own `next_check_at <= now` filter
(`sat_campaign_repository.py`) to make early calls a safe no-op instead of
extra SAT contact.

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

`scripts/sat_campaign_watch.ps1` never accepts or prints the FIEL phrase; it
resolves through the same OS secret provider the interactive CLI and wizard
use. It logs one line per invocation to
`%LOCALAPPDATA%\cfdi-vault-mx\logs\sat-campaign-watch.log`, including
no-op runs, so a stalled campaign is visible without opening a terminal.
`RepetitionDuration` is intentionally bounded (30 days, not indefinite):
`Register-ScheduledTask` rejects `[TimeSpan]::MaxValue` as an out-of-range
XML duration, and a bounded window also forces a periodic human check-in
before it silently re-authorizes itself past a grant's own 1-14 day expiry.

To stop it: `Unregister-ScheduledTask -TaskName "CfdiVaultMx-SatCampaignWatch" -Confirm:$false`.
