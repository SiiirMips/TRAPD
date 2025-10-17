# TRAPD ClickHouse Bootstrap Script
# Windows PowerShell compatible

param(
    [switch]$CreateReadonly = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=== TRAPD ClickHouse Bootstrap ===" -ForegroundColor Cyan
Write-Host ""

# Check Docker is running
Write-Host "[1/7] Checking Docker..." -ForegroundColor Yellow
try {
    docker info | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running. Please start Docker Desktop."
    }
    Write-Host "  OK Docker is running" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
    exit 1
}

# Start Docker Compose
Write-Host ""
Write-Host "[2/7] Starting ClickHouse container..." -ForegroundColor Yellow
try {
    docker compose up -d
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start container"
    }
    Write-Host "  OK Container started" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
    exit 1
}

# Wait for ClickHouse to be ready
Write-Host ""
Write-Host "[3/7] Waiting for ClickHouse to be ready..." -ForegroundColor Yellow
$maxAttempts = 30
$attempt = 0
$ready = $false

while (-not $ready -and $attempt -lt $maxAttempts) {
    $attempt++
    Write-Host "  Attempt $attempt/$maxAttempts..." -NoNewline
    
    try {
        $testResult = docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query 'SELECT 1' 2>&1
        if ($LASTEXITCODE -eq 0 -and $testResult -match '1') {
            $ready = $true
            Write-Host " OK" -ForegroundColor Green
        } else {
            Write-Host " waiting..." -ForegroundColor Gray
            Start-Sleep -Seconds 2
        }
    } catch {
        Write-Host " waiting..." -ForegroundColor Gray
        Start-Sleep -Seconds 2
    }
}

if (-not $ready) {
    Write-Host "  ERROR Timeout waiting for ClickHouse" -ForegroundColor Red
    Write-Host "  Container logs:" -ForegroundColor Yellow
    docker logs trapd-clickhouse --tail 20
    exit 1
}

Write-Host "  OK ClickHouse is ready" -ForegroundColor Green

# Apply schema
Write-Host ""
Write-Host "[4/7] Applying schema..." -ForegroundColor Yellow
try {
    $schemaContent = Get-Content -Path "db/schema.sql" -Raw
    $null = $schemaContent | docker exec -i trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --multiquery
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to apply schema"
    }
    Write-Host "  OK Schema applied" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
    exit 1
}

# Apply indexes
Write-Host ""
Write-Host "[5/7] Applying indexes..." -ForegroundColor Yellow
try {
    $indexContent = Get-Content -Path "db/indexes.sql" -Raw
    $null = $indexContent | docker exec -i trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --multiquery
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to apply indexes"
    }
    Write-Host "  OK Indexes applied" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
    exit 1
}

# Run smoke test
Write-Host ""
Write-Host "[6/7] Running smoke test..." -ForegroundColor Yellow
try {
    $smokeContent = Get-Content -Path "db/smoke.sql" -Raw
    $smokeResult = $smokeContent | docker exec -i trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --multiquery
    if ($LASTEXITCODE -ne 0) {
        throw "Smoke test failed"
    }
    Write-Host "  OK Smoke test passed" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Smoke test results:" -ForegroundColor Cyan
    Write-Host $smokeResult
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
    exit 1
}

# Optional: Create readonly user
if ($CreateReadonly) {
    Write-Host ""
    Write-Host "[Optional] Creating readonly user..." -ForegroundColor Yellow
    try {
        $readonlyContent = Get-Content -Path "tools/create-readonly-user.sql" -Raw
        $null = $readonlyContent | docker exec -i trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --multiquery
        Write-Host "  OK Readonly user created" -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: $_" -ForegroundColor Red
    }
}

# Status check
Write-Host ""
Write-Host "[7/7] Status Check..." -ForegroundColor Yellow

# Check version
$version = docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query 'SELECT version()'
Write-Host "  ClickHouse Version: $version" -ForegroundColor Cyan

# Show table structure
Write-Host ""
Write-Host "Table Structure:" -ForegroundColor Cyan
docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query 'SHOW CREATE TABLE trapd.events FORMAT Vertical'

Write-Host ""
Write-Host "=== Bootstrap Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Connection Details:" -ForegroundColor Cyan
Write-Host "  HTTP:     http://localhost:8123"
Write-Host "  Native:   localhost:9000"
Write-Host "  User:     trapd"
Write-Host "  Password: trapd_pwd"
Write-Host "  Database: trapd"
Write-Host ""
