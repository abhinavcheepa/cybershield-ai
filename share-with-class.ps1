# Share the lab with your class over the internet — no LAN, no cloud account.
#
# This opens a public https://<random>.trycloudflare.com URL that tunnels to
# your local backend (port 8010), which serves both the API and the *built*
# frontend. Students open that URL, register at /join, and their sites are live
# for you to attack from the CyberShield "Live Attack Range" panel.
#
# It tunnels the production build, not the Vite dev server. The dev server ships
# every source module separately and unminified — hundreds of requests through
# one tunnel — which is why the link used to take so long to open on a phone or
# a slow connection. The build is one HTML file plus a handful of hashed,
# gzipped, permanently cacheable assets.
#
# For a class you run more than once, deploy to Railway or Render instead and
# hand out a stable URL: see docs/DEPLOY.md.
#
# Usage:  right-click > Run with PowerShell,  or:  ./share-with-class.ps1
# Stop:   press Ctrl+C in this window.

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$exe  = Join-Path $root "cloudflared.exe"
$dist = Join-Path $root "frontend\dist\index.html"

function Test-Port($port) {
    $null -ne (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
}

# 1. Build the frontend if it has never been built.
if (-not (Test-Path $dist)) {
    Write-Host "Building the frontend (one-time, ~30 s)..." -ForegroundColor Cyan
    Push-Location (Join-Path $root "frontend")
    try {
        if (-not (Test-Path "node_modules")) { npm install }
        npm run build
    } finally { Pop-Location }
    Write-Host "Built. Restart the backend so it picks the build up." -ForegroundColor Yellow
}

# 2. The backend serves the API and the build on one port.
if (-not (Test-Port 8010)) {
    Write-Host "!! Backend is not running on port 8010." -ForegroundColor Yellow
    Write-Host "   Start it first:  cd backend; .\.venv\Scripts\python -m uvicorn app.main:app --port 8010"
    exit 1
}

# It only serves the SPA if the build existed when it started, so a stale
# process from before the first build would tunnel a JSON root instead.
try {
    $head = Invoke-WebRequest -Uri "http://127.0.0.1:8010/" -UseBasicParsing -TimeoutSec 5
    if ($head.Content -notmatch "<div id=""root""") {
        Write-Host "!! The backend is serving the API but not the frontend build." -ForegroundColor Yellow
        Write-Host "   Restart it now that frontend/dist exists, then run this again."
        exit 1
    }
} catch {
    Write-Host "!! Could not reach http://127.0.0.1:8010/ — is the backend healthy?" -ForegroundColor Yellow
    exit 1
}

# 3. Fetch cloudflared if we don't have it (official Cloudflare release).
if (-not (Test-Path $exe)) {
    Write-Host "Downloading cloudflared (official Cloudflare binary, ~50 MB)..." -ForegroundColor Cyan
    $url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
    Invoke-WebRequest -Uri $url -OutFile $exe
    Write-Host "Done." -ForegroundColor Green
}

# 4. Open the tunnel. cloudflared prints the public URL a few lines in — share
#    that trycloudflare.com link with your students.
Write-Host ""
Write-Host "Opening public tunnel to http://localhost:8010 ..." -ForegroundColor Cyan
Write-Host "Look for the https://<something>.trycloudflare.com URL below and share it." -ForegroundColor Cyan
Write-Host "Give students the /join page:  https://<something>.trycloudflare.com/join" -ForegroundColor Green
Write-Host ""
& $exe tunnel --url http://localhost:8010
