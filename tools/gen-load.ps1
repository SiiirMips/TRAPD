# Generate and load 1000 test events
$ErrorActionPreference = "Stop"
$api = "http://localhost:8080/ingest"
Write-Host "=== TRAPD Ingest Load Test ===" -ForegroundColor Cyan
Write-Host "Generating 1000 events..."
$events = @()
for ($i=1; $i -le 1000; $i++) {
    $events += [PSCustomObject]@{
        ts_str = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss.fffZ")
        org_id = "bna"
        sensor_id = "s-h1-01"
        event_type = "probe"
        src_ip = "198.51.100.42"
        src_port = 12001
        dst_port = 22
        proto = "TCP"
        severity = "low"
        payload = '{"k":"v"}'
    }
}
$json = $events | ConvertTo-Json
Write-Host "Sending events to $api..."
try {
    $resp = Invoke-WebRequest -Uri $api -Method POST -Body $json -ContentType "application/json"
    Write-Host "Response: $($resp.StatusCode)"
} catch {
    Write-Host "ERROR: $_" -ForegroundColor Red
    exit 1
}
