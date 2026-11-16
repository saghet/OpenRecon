<#
.SYNOPSIS
    Smart Launcher for OpenRecon 3.0 (Docker Compose + Web Console).
    Checks if http://127.0.0.1:8080/index.php is reachable; if not, starts
    the Docker Compose stack and waits for health before opening the browser.
#>
$ErrorActionPreference = "SilentlyContinue"
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$WebUrl = "http://127.0.0.1:8080/index.php"

function Test-OpenReconWeb {
    try {
        $resp = Invoke-WebRequest -Uri $WebUrl -UseBasicParsing -TimeoutSec 2
        return ($resp.StatusCode -eq 200)
    } catch {
        return $false
    }
}

if (-not (Test-OpenReconWeb)) {
    Push-Location $RepoRoot
    try {
        docker compose up -d | Out-Null
    } finally {
        Pop-Location
    }

    for ($i = 0; $i -lt 30; $i++) {
        if (Test-OpenReconWeb) { break }
        Start-Sleep -Seconds 2
    }
}

Start-Process $WebUrl
