<#
.SYNOPSIS
    WAF — quick-start installer for Windows (PowerShell).

.DESCRIPTION
    Clones the repository, generates environment variables and starts the
    Docker Compose stack.

    One-liner:
        irm https://raw.githubusercontent.com/Cringeneers/demo-repository/main/scripts/install/install.ps1 | iex

    Optional environment variables:
        WAF_REPO      git URL to clone           (default: https://github.com/Cringeneers/demo-repository.git)
        WAF_DIR       target directory           (default: .\waf)
        WAF_BRANCH    branch to check out        (default: main)
        WAF_NO_START  set to 1 to skip the build (default: unset)
#>

$ErrorActionPreference = 'Stop'

$Repo   = if ($env:WAF_REPO)   { $env:WAF_REPO }   else { 'https://github.com/Cringeneers/demo-repository.git' }
$Dir    = if ($env:WAF_DIR)    { $env:WAF_DIR }    else { 'waf' }
$Branch = if ($env:WAF_BRANCH) { $env:WAF_BRANCH } else { 'main' }

function Write-Step { param($m) Write-Host "==> $m" -ForegroundColor Blue }
function Write-Info { param($m) Write-Host "[*] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function Die        { param($m) Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

function Require-Cmd {
    param($name, $hint)
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Die "'$name' is required but not installed. $hint"
    }
}

Write-Host "==============================================="
Write-Host "   WAF - Web Application Firewall Edge"
Write-Host "   Quick-start installer (Windows)"
Write-Host "==============================================="
Write-Host ""

# --- 1. Prerequisites -------------------------------------------------------
Write-Step "Checking prerequisites"
Require-Cmd git    "Install it from https://git-scm.com/download/win"
Require-Cmd docker "Install Docker Desktop from https://docs.docker.com/desktop/install/windows-install/"

try { docker info *> $null } catch { Die "Docker daemon is not running. Start Docker Desktop and re-run this installer." }
if ($LASTEXITCODE -ne 0) { Die "Docker daemon is not running. Start Docker Desktop and re-run this installer." }

docker compose version *> $null
if ($LASTEXITCODE -eq 0) {
    $Compose = @('docker', 'compose')
} elseif (Get-Command docker-compose -ErrorAction SilentlyContinue) {
    $Compose = @('docker-compose')
} else {
    Die "Docker Compose not found. It ships with Docker Desktop: https://docs.docker.com/compose/install/"
}
Write-Info "git, docker and '$($Compose -join ' ')' are available"

# --- 2. Clone --------------------------------------------------------------
Write-Step "Fetching the repository"
if (Test-Path (Join-Path $Dir '.git')) {
    Write-Info "'$Dir' already exists - pulling latest on '$Branch'"
    git -C $Dir fetch --depth 1 origin $Branch
    git -C $Dir checkout $Branch
    git -C $Dir pull --ff-only origin $Branch
} elseif (Test-Path $Dir) {
    Die "'$Dir' exists but is not a git repository. Remove it or set WAF_DIR=<other>."
} else {
    git clone --branch $Branch --depth 1 $Repo $Dir
}
Set-Location $Dir

# --- 3. Environment --------------------------------------------------------
Write-Step "Generating environment variables and keys"
if (Test-Path .env) {
    Write-Warn ".env already exists - keeping it (delete it and re-run to regenerate)"
} else {
    $bash = Get-Command bash -ErrorAction SilentlyContinue
    if ($bash) {
        bash ./scripts/setup/generate-env.sh
    } else {
        Write-Warn "'bash' not found - cannot run scripts/setup/generate-env.sh automatically."
        Write-Warn "Install Git Bash / WSL, then run:  bash ./scripts/setup/generate-env.sh"
        Die "Cannot continue without a .env file."
    }
}

# --- 4. Build & start ------------------------------------------------------
if ($env:WAF_NO_START -eq '1') {
    Write-Warn "WAF_NO_START=1 set - skipping 'docker compose up'"
} else {
    Write-Step "Building and starting the stack (this may take a few minutes)"
    & $Compose[0] $Compose[1..($Compose.Length-1)] up -d --build
    if ($LASTEXITCODE -ne 0) { Die "'$($Compose -join ' ') up' failed." }
}

# --- 5. Next steps ---------------------------------------------------------
Write-Host ""
Write-Info "WAF is up. Next steps:"
@"

  1. Open $Dir\.env and set WAF_PUBLIC_BASE_URL
     (use http://localhost:5173 for local development).

  2. Create the first administrator (Git Bash / WSL):
       cd $Dir
       ./scripts/ops/create-admin.sh --email you@yourdomain.com

  3. Open the control panel and register your TOTP (2FA) app.

  Useful commands:
     $($Compose -join ' ') ps            # service status
     $($Compose -join ' ') logs -f       # follow logs
     $($Compose -join ' ') down          # stop the stack

"@ | Write-Host
