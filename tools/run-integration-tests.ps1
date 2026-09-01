[CmdletBinding()]
param(
    [switch]$KeepServices
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$composeFile = Join-Path $repoRoot 'docker-compose.integration.yml'
$project = 'bpc-integration'

try {
    docker compose -p $project -f $composeFile up --detach --wait
    $env:BPC_TEST_REDIS_URL = 'redis://127.0.0.1:6388'
    $env:BPC_TEST_POSTGRES_URL = 'postgresql://bpc_test:bpc-test-only-password@127.0.0.1:5545/bpc_test'
    Push-Location $repoRoot
    try {
        npm run build
        npm run test:redis
        npm run test:postgres
    } finally {
        Pop-Location
    }
} finally {
    Remove-Item Env:BPC_TEST_REDIS_URL -ErrorAction SilentlyContinue
    Remove-Item Env:BPC_TEST_POSTGRES_URL -ErrorAction SilentlyContinue
    if (-not $KeepServices) {
        docker compose -p $project -f $composeFile down --volumes --remove-orphans
    }
}
