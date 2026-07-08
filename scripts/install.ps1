param(
    [switch]$SkipDockerUp
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is required. Install Docker Desktop before running this installer."
}

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example"
}

@("storage", "storage/packages", "storage/xml", "storage/exports", "logs") | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ | Out-Null
    }
}

if (-not $SkipDockerUp) {
    docker compose up -d --build postgres rabbitmq redis
    docker compose run --rm flyway
    docker compose run --rm app doctor
}

Write-Host "CFDI Vault MX local environment is ready."
