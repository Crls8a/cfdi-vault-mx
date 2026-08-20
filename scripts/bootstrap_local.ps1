param(
    [string]$VenvPath = ".venv",
    [string]$ProfileId = "alpha-local",
    [string]$DatabaseUrl = $env:DATABASE_URL,
    [string]$TestDatabaseUrl = $env:CFDI_VAULT_TEST_DATABASE_URL,
    [switch]$SkipScanner,
    [switch]$SkipTests,
    [switch]$SkipOfflineSmoke
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    Write-Host "==> $Name"
    & $Command
}

function Clear-LiveSatEnv {
    foreach ($name in @("CFDI_VAULT_ALLOW_REAL_SAT", "CFDI_VAULT_ALLOW_REAL_CREDENTIALS")) {
        if (Test-Path "Env:\$name") {
            Remove-Item "Env:\$name"
        }
    }
}

function Get-DatabaseNameFromUrl {
    param([string]$Url)

    $withoutQuery = ($Url -split "[?#]", 2)[0]
    return ($withoutQuery -split "/")[-1]
}

function Assert-SafeTestDatabaseUrl {
    param(
        [string]$Url
    )

    if ([string]::IsNullOrWhiteSpace($Url)) {
        throw "CFDI_VAULT_TEST_DATABASE_URL or -TestDatabaseUrl is required for PostgreSQL-backed tests."
    }

    $databaseName = Get-DatabaseNameFromUrl -Url $Url
    if ($databaseName -notmatch "(?i)test" -and $env:CFDI_VAULT_ALLOW_DESTRUCTIVE_TEST_DB_RESET -ne "1") {
        throw "Refusing to run tests against database '$databaseName'. Use a dedicated test database or set CFDI_VAULT_ALLOW_DESTRUCTIVE_TEST_DB_RESET=1 for an explicit disposable database."
    }
}

Clear-LiveSatEnv

$venvFullPath = Resolve-Path -LiteralPath $VenvPath -ErrorAction SilentlyContinue
if ($null -eq $venvFullPath) {
    Invoke-Step "Create virtual environment" { py -m venv $VenvPath }
    $venvFullPath = Resolve-Path -LiteralPath $VenvPath
}

$python = Join-Path $venvFullPath "Scripts\python.exe"

Invoke-Step "Install editable package with dev and webapi dependencies" {
    & $python -m pip install --upgrade pip
    & $python -m pip install -e ".[dev,webapi]"
}

Invoke-Step "Validate installed package imports" {
    # There is no cfdi-vault CLI anymore (retired in favor of the control
    # panel); this validates the console-script entry points import cleanly
    # instead of running a --help command that no longer exists.
    & $python -c "import cfdi_vault.adapters.webapi.app, cfdi_vault.doctor_runner, cfdi_vault.worker_runner, cfdi_vault.sat_campaign_run_service" | Out-Null
}

if (-not $SkipScanner) {
    Invoke-Step "Run sensitive fixture scanner" {
        & $python scripts\scan_sensitive_fixtures.py --root .
    }
}

if (-not [string]::IsNullOrWhiteSpace($DatabaseUrl)) {
    $env:DATABASE_URL = $DatabaseUrl
}

if (-not $SkipTests) {
    Assert-SafeTestDatabaseUrl -Url $TestDatabaseUrl
    if (-not [string]::IsNullOrWhiteSpace($DatabaseUrl) -and $DatabaseUrl -eq $TestDatabaseUrl) {
        throw "Refusing to use the same URL for DATABASE_URL and CFDI_VAULT_TEST_DATABASE_URL. Use a separate disposable test database."
    }
    $env:CFDI_VAULT_TEST_DATABASE_URL = $TestDatabaseUrl

    Invoke-Step "Run pytest" {
        & $python -m pytest -q
    }
}

if (-not $SkipOfflineSmoke) {
    if ([string]::IsNullOrWhiteSpace($DatabaseUrl)) {
        throw "DATABASE_URL or -DatabaseUrl is required for the PostgreSQL-only offline smoke."
    }

    $smokeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("cfdi-vault-local-alpha-" + [System.Guid]::NewGuid().ToString("N"))
    $smokeAppData = Join-Path $smokeRoot "appdata"
    New-Item -ItemType Directory -Path $smokeAppData -Force | Out-Null

    $previousLocalAppData = $env:LOCALAPPDATA
    $previousAlphaProfile = $env:CFDI_VAULT_ALPHA_PROFILE
    $previousDatabaseUrl = $env:DATABASE_URL
    try {
        $env:LOCALAPPDATA = $smokeAppData
        $env:CFDI_VAULT_ALPHA_PROFILE = $ProfileId
        $env:DATABASE_URL = $DatabaseUrl

        Invoke-Step "Create synthetic AppData profile for offline smoke" {
            @"
from pathlib import Path
import os
from cfdi_vault import setup as setup_flow

profile_id = os.environ["CFDI_VAULT_ALPHA_PROFILE"]
paths = setup_flow.build_profile_paths(profile_id, env={"LOCALAPPDATA": os.environ["LOCALAPPDATA"]})
setup_flow.ensure_profile_layout(paths)
cert_path = paths.credentials_dir / "synthetic-profile-cert.txt"
key_path = paths.credentials_dir / "synthetic-profile-private.txt"
cert_path.write_text("synthetic placeholder for offline alpha only\n", encoding="utf-8")
key_path.write_text("synthetic placeholder for offline alpha only\n", encoding="utf-8")
profile = setup_flow.LocalProfile(
    profile_id=profile_id,
    rfc="XAXX010101000",
    storage_root=paths.storage_root,
    credential_mode=setup_flow.CredentialMode.REFERENCED,
    certificate_path=cert_path,
    private_key_path=key_path,
    phrase_ref=setup_flow.default_phrase_reference(profile_id),
    status=setup_flow.LocalProfileStatus.READY,
    certificate_fingerprint="0" * 64,
)
setup_flow.write_profile(profile, paths.profile_json)
"@ | & $python -
        }

        Invoke-Step "Run offline status and doctor" {
            $env:CFDI_VAULT_DOCTOR_STORAGE = Join-Path $smokeRoot "doctor-storage"
            @"
import os
from pathlib import Path
from cfdi_vault.setup_status import inspect_profile, format_profile_status
from cfdi_vault.panel_services import recovery_service

profile_id = os.environ["CFDI_VAULT_ALPHA_PROFILE"]
print(format_profile_status(inspect_profile(profile_id)))

service = recovery_service(os.environ["DATABASE_URL"], Path(os.environ["CFDI_VAULT_DOCTOR_STORAGE"]))
try:
    for check in service.doctor():
        print(f"{'OK' if check.ok else 'FAIL'} {check.name}: {check.detail}")
finally:
    service.close()
"@ | & $python -
        }

        # The fake/offline "download plan/request/sync/status" pipeline this
        # step used to smoke-test was deleted along with the Typer CLI: it was
        # already a parallel, disconnected harness (fake SAT client, its own
        # table set) with no bearing on the real PostgreSQL-backed campaign
        # path (docs/runbooks/sat-campaign.md), and nothing replaced it. There
        # is deliberately no smoke step here anymore - see the CLI-retirement
        # commit for why porting it forward was rejected rather than skipped
        # by oversight.
    }
    finally {
        if ($null -eq $previousLocalAppData) {
            Remove-Item Env:\LOCALAPPDATA -ErrorAction SilentlyContinue
        }
        else {
            $env:LOCALAPPDATA = $previousLocalAppData
        }
        if ($null -eq $previousAlphaProfile) {
            Remove-Item Env:\CFDI_VAULT_ALPHA_PROFILE -ErrorAction SilentlyContinue
        }
        else {
            $env:CFDI_VAULT_ALPHA_PROFILE = $previousAlphaProfile
        }
        if ($null -eq $previousDatabaseUrl) {
            Remove-Item Env:\DATABASE_URL -ErrorAction SilentlyContinue
        }
        else {
            $env:DATABASE_URL = $previousDatabaseUrl
        }
        Remove-Item Env:\CFDI_VAULT_DOCTOR_STORAGE -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $smokeRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Clear-LiveSatEnv
Write-Host "CFDI Vault MX local installer alpha checks passed. Live SAT was not executed."
