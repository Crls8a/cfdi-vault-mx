<#
.SYNOPSIS
    Queue a due-work check for one already-authorized live SAT campaign
    grant on a schedule.

.DESCRIPTION
    Queues a durable sat_campaign_runs row for one profile/campaign/grant
    that was already created and authorized by a human operator, via the
    same enqueue_campaign_run PostgreSQL used by the control panel's
    POST /api/campaign/{profile}/{campaign}/run (ADR 0005/0006). It never
    creates or authorizes a campaign itself, and it never contacts SAT
    directly: the separate host-only cfdi-vault-campaign-run-worker
    process (run this script alongside, --loop or scheduled the same way)
    is what actually claims the row and decides whether anything is due -
    see sat_db_campaign_runner.py's own next_check_at gate. Queueing a run
    when nothing is due is a safe no-op there, so scheduling this
    frequently does not spam SAT with extra contact. enqueue_campaign_run
    is itself idempotent per (campaign, grant): a run already queued or in
    flight is returned as-is rather than duplicated.

    Intended to be invoked by a Windows Scheduled Task (see
    sat_windows_task.py for the task template, which now points at the
    worker's --once flag instead of this script - both are valid
    schedules for the two different halves of ADR 0005's split). Does not
    accept or print the FIEL phrase: enqueueing never touches the OS
    credential store, only the worker process does.

.PARAMETER ProfileId
    Local setup profile id (already onboarded via POST /api/setup or the
    FIEL wizard).

.PARAMETER CampaignRef
    Opaque campaign reference returned by POST /api/campaign/{profile}/create.

.PARAMETER GrantRef
    Opaque grant reference returned by POST /api/campaign/{profile}/{campaign}/authorize.

.PARAMETER CommitRef
    The exact commit hash the campaign/grant were created and authorized
    against. Must match exactly or the enqueue is rejected.
#>
param(
    [Parameter(Mandatory = $true)][string]$ProfileId,
    [Parameter(Mandatory = $true)][string]$CampaignRef,
    [Parameter(Mandatory = $true)][string]$GrantRef,
    [Parameter(Mandatory = $true)][string]$CommitRef,
    [string]$DatabaseUrl = "postgresql+psycopg://cfdi_vault:cfdi_vault@localhost:5433/cfdi_vault",
    [string]$RabbitMqUrl = "amqp://cfdi_vault:cfdi_vault@localhost:5672/",
    [string]$LogPath = "$env:LOCALAPPDATA\cfdi-vault-mx\logs\sat-campaign-watch.log",
    [string]$PythonPath = "python"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogPath) | Out-Null

$env:DATABASE_URL = $DatabaseUrl
$env:RABBITMQ_URL = $RabbitMqUrl
$env:CFDI_VAULT_COMMIT_REF = $CommitRef
$env:CFDI_VAULT_WATCH_PROFILE = $ProfileId
$env:CFDI_VAULT_WATCH_CAMPAIGN_REF = $CampaignRef
$env:CFDI_VAULT_WATCH_GRANT = $GrantRef

$timestamp = (Get-Date).ToUniversalTime().ToString("o")
$output = @"
import json
import os
from cfdi_vault.sat_campaign_db_cli import CampaignDatabaseError, enqueue_campaign_run, publish_campaign_run_hint

profile_id = os.environ["CFDI_VAULT_WATCH_PROFILE"]
campaign_ref = os.environ["CFDI_VAULT_WATCH_CAMPAIGN_REF"]
grant_ref = os.environ["CFDI_VAULT_WATCH_GRANT"]
try:
    queued = enqueue_campaign_run(profile_id, campaign_ref, grant_ref, requested_via="cli")
except CampaignDatabaseError as exc:
    print(json.dumps({"status": "rejected", "reason": exc.reason}, sort_keys=True))
    raise SystemExit(1)
published = publish_campaign_run_hint(profile_id, campaign_ref, grant_ref, str(queued["run_ref"]))
print(json.dumps({**queued, "hint_published": published}, sort_keys=True, default=str))
"@ | & $PythonPath - 2>&1
$exitCode = $LASTEXITCODE

$entry = @"
[$timestamp] exit=$exitCode
$output
"@
Add-Content -Path $LogPath -Value $entry
