# TRAPD ClickHouse Export Script
# Windows PowerShell compatible

$ErrorActionPreference = "Stop"

Write-Host "=== TRAPD ClickHouse Export ===" -ForegroundColor Cyan
Write-Host ""

# Check if container is running
Write-Host "[1/4] Checking container status..." -ForegroundColor Yellow
$containerStatus = docker inspect -f '{{.State.Running}}' trapd-clickhouse 2>$null
if ($containerStatus -ne "true") {
    Write-Host "  ERROR Container trapd-clickhouse is not running" -ForegroundColor Red
    exit 1
}
Write-Host "  OK Container is running" -ForegroundColor Green

# Create backup directory in container
Write-Host ""
Write-Host "[2/4] Preparing export directory..." -ForegroundColor Yellow
try {
    docker exec trapd-clickhouse mkdir -p /var/lib/clickhouse/backup
    Write-Host "  OK Directory ready" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
    exit 1
}

# Export to Parquet
Write-Host ""
Write-Host "[3/4] Exporting trapd.events to Parquet..." -ForegroundColor Yellow
try {
    docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query "SELECT * FROM trapd.events INTO OUTFILE '/var/lib/clickhouse/backup/events.parquet' FORMAT Parquet"
    if ($LASTEXITCODE -ne 0) {
        throw "Export failed"
    }
    Write-Host "  OK Export completed" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
    exit 1
}

# Copy to host
Write-Host ""
Write-Host "[4/4] Copying to host..." -ForegroundColor Yellow
try {
    # Create local backup directory
    $backupDir = ".\backup"
    if (-not (Test-Path $backupDir)) {
        New-Item -ItemType Directory -Path $backupDir | Out-Null
    }
    
    # Copy file from container
    docker cp trapd-clickhouse:/var/lib/clickhouse/backup/events.parquet "$backupDir\events.parquet"
    if ($LASTEXITCODE -ne 0) {
        throw "Copy failed"
    }
    
    # Get file size
    $fileSize = (Get-Item "$backupDir\events.parquet").Length
    $fileSizeKB = [math]::Round($fileSize / 1KB, 2)
    
    Write-Host "  OK File copied to $backupDir\events.parquet" -ForegroundColor Green
    Write-Host "  OK File size: $fileSizeKB KB" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Export Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Export location: $backupDir\events.parquet" -ForegroundColor Cyan
Write-Host ""
