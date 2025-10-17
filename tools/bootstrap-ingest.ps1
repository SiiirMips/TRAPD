# Bootstrap Ingest SQL
$ErrorActionPreference = "Stop"
Write-Host "=== TRAPD Ingest Bootstrap ===" -ForegroundColor Cyan
Write-Host "Applying ingest.sql..."
docker cp db/ingest.sql trapd-clickhouse:/ingest.sql
$apply = docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --multiquery --queries-file /ingest.sql
Write-Host $apply
Write-Host "Checking tables..."
$tables = docker exec trapd-clickhouse clickhouse-client --user trapd --password trapd_pwd --query "SHOW TABLES FROM trapd"
Write-Host $tables
if ($tables -match "ingest_raw" -and $tables -match "mv_ingest_to_events") {
    Write-Host "OK: ingest_raw & mv_ingest_to_events exist." -ForegroundColor Green
} else {
    Write-Host "ERROR: Tables missing!" -ForegroundColor Red
    exit 1
}
