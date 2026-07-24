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
