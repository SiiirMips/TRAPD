# tools/bootstrap.ps1
$ErrorActionPreference = "Stop"

function Test-Cmd($name, $args = "--version") {
    try {
        & $name $args | Out-Null
        Write-Host "✓ $name gefunden"
        return $true
    } catch {
        Write-Warning "✗ $name nicht gefunden"
        return $false
    }
}

Write-Host "== TRAPD Bootstrap =="

# 1) Grundchecks
$haveGit    = Test-Cmd git
$haveDocker = Test-Cmd docker "version"
$haveNode   = Test-Cmd node "--version"
$haveNpm    = Test-Cmd npm "--version"
$haveRust   = Test-Cmd rustc "--version"
$haveCargo  = Test-Cmd cargo "--version"

if (-not $haveGit)    { throw "Bitte Git installieren." }
if (-not $haveDocker) { throw "Bitte Docker Desktop installieren und starten." }
if (-not $haveNode)   { throw "Bitte Node.js (>= 18) installieren." }
if (-not $haveNpm)    { throw "npm fehlt (kommt i.d.R. mit Node)." }
if (-not $haveRust)   { throw "Bitte Rust (rustup) installieren." }
if (-not $haveCargo)  { throw "Cargo fehlt – kommt mit rustup." }

# 2) Node-Version anzeigen
$nodeVer = (& node --version)
Write-Host "Node: $nodeVer"

# 3) Frontend-Dependencies
$frontend = Join-Path $PSScriptRoot "..\frontend"
if (Test-Path $frontend) {
    Push-Location $frontend
    Write-Host "Installing frontend deps..."
    npm ci
    Pop-Location
}

# 4) Rust: release build aller Services
$services = @(
    "..\services\api-rs",
    "..\services\processor-rs",
    "..\services\sensor-rs"
)

foreach ($srv in $services) {
    $path = Join-Path $PSScriptRoot $srv
    if (Test-Path $path) {
        Push-Location $path
        Write-Host "Building $srv (release)..."
        cargo build --release
        Pop-Location
    } else {
        Write-Warning "Service-Pfad nicht gefunden: $path"
    }
}

Write-Host "== Bootstrap done =="
Write-Host "Tip: docker compose up -d  (im Repo-Root)"
