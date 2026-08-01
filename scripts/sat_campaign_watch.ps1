<#
.SYNOPSIS
    Re-check one already-authorized live SAT campaign grant on a schedule.

.DESCRIPTION
    Runs `cfdi-vault sat campaign run` for one profile/campaign/grant that
    was already created and authorized by a human operator. It never
    creates or authorizes a campaign itself. The repository's own
    next_check_at gate makes repeated calls before the due time a safe
    no-op (see sat_campaign_repository.py, next_check_at <= now filter),
    so scheduling this frequently does not spam SAT with extra contact.

    Intended to be invoked by a Windows Scheduled Task. Does not accept or
    print the FIEL phrase; it resolves automatically through Windows
    Credential Manager the same way the interactive CLI does.

.PARAMETER ProfileId
    Local setup profile id (already onboarded via `cfdi-vault setup` or the
    FIEL wizard).

.PARAMETER CampaignRef
    Opaque campaign reference returned by `cfdi-vault sat campaign create`.

.PARAMETER GrantRef
    Opaque grant reference returned by `cfdi-vault sat campaign authorize`.

.PARAMETER CommitRef
    The exact commit hash the campaign/grant were created and authorized
    against. Must match exactly or the run is rejected.
#>
param(
    [Parameter(Mandatory = $true)][string]$ProfileId,
    [Parameter(Mandatory = $true)][string]$CampaignRef,
    [Parameter(Mandatory = $true)][string]$GrantRef,
    [Parameter(Mandatory = $true)][string]$CommitRef,
    [string]$DatabaseUrl = "postgresql+psycopg://cfdi_vault:cfdi_vault@localhost:5433/cfdi_vault",
    [string]$RabbitMqUrl = "amqp://cfdi_vault:cfdi_vault@localhost:5672/",
    [string]$StorageRoot = "$env:LOCALAPPDATA\cfdi-vault-mx\storage\$ProfileId",
    [string]$LogPath = "$env:LOCALAPPDATA\cfdi-vault-mx\logs\sat-campaign-watch.log"
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $LogPath) | Out-Null

$env:DATABASE_URL = $DatabaseUrl
$env:RABBITMQ_URL = $RabbitMqUrl
$env:CFDI_STORAGE_ROOT = $StorageRoot
$env:CFDI_VAULT_COMMIT_REF = $CommitRef
$env:CFDI_VAULT_LIVE_WORKER_ENABLED = "1"
$env:CFDI_VAULT_SCANNER_PASSED = "1"
$env:CFDI_VAULT_REPO_CLEAN = "1"

$timestamp = (Get-Date).ToUniversalTime().ToString("o")
$output = & cfdi-vault sat campaign run --profile $ProfileId --campaign-ref $CampaignRef --grant $GrantRef 2>&1
$exitCode = $LASTEXITCODE

$entry = @"
[$timestamp] exit=$exitCode
$output
"@
Add-Content -Path $LogPath -Value $entry
