﻿# ==============================================================================
#  ISOTOPE - Automated Installer & Setup Script (Windows PowerShell)
#  v4.0.0 - Post-Quantum Secure Messaging over Tor
#  Run as Administrator in PowerShell:  .\install.ps1
# ==============================================================================

#Requires -Version 5.1

param(
    [switch]$SkipTor,
    [switch]$SkipBuild,
    [switch]$SkipInstall
)

# -- Strict mode ----------------------------------------------------------------
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -- Colors and helpers ---------------------------------------------------------
function Write-Info    { param([string]$Msg) Write-Host "[INFO]  $Msg" -ForegroundColor Cyan }
function Write-Success { param([string]$Msg) Write-Host "[OK]    $Msg" -ForegroundColor Green }
function Write-Warn    { param([string]$Msg) Write-Host "[WARN]  $Msg" -ForegroundColor Yellow }
function Write-Fail    { param([string]$Msg) Write-Host "[ERROR] $Msg" -ForegroundColor Red; exit 1 }
function Write-Step    { param([string]$Msg) Write-Host "`n== $Msg " -ForegroundColor Cyan -NoNewline; Write-Host "" }
function Write-Divider { Write-Host ("-" * 52) -ForegroundColor DarkGray }

function Write-Banner {
    Write-Host @"

  ___  ____   ___ _____ ___  ____  _____ 
 |_ _|/ ___| / _ \_   _/ _ \|  _ \| ____|
  | | \___ \| | | || || | | | |_) |  _|  
  | |  ___) | |_| || || |_| |  __/| |___ 
 |___|____/ \___/ |_| \___/|_|   |_____|

       Post-Quantum Secure Messaging over Tor - v4.0.0
       Automated Installer for Windows
"@ -ForegroundColor Magenta
}

# -- Check if running as Administrator -----------------------------------------
function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# -- Detect Script Root ---------------------------------------------------------
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

# -- Install Chocolatey (package manager) ---------------------------------------
function Install-Choco {
    Write-Step "Checking Chocolatey Package Manager"
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Success "Chocolatey already installed: $(choco --version)"
        return
    }
    Write-Info "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    # Refresh PATH
    $env:PATH = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    Write-Success "Chocolatey installed."
}

# -- Install Git ----------------------------------------------------------------
function Install-Git {
    Write-Step "Checking Git"
    if (Get-Command git -ErrorAction SilentlyContinue) {
        Write-Success "Git already installed: $(git --version)"
        return
    }
    Write-Info "Installing Git via Chocolatey..."
    choco install git -y --no-progress
    $env:PATH = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    Write-Success "Git installed."
}

# -- Install Rust ---------------------------------------------------------------
function Install-Rust {
    Write-Step "Checking Rust Toolchain"
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        Write-Success "Rust already installed: $(cargo --version)"
        Write-Info "Updating Rust to latest stable..."
        rustup update stable 2>$null
        return
    }

    Write-Info "Downloading rustup-init.exe..."
    $rustupPath = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupPath -UseBasicParsing

    Write-Info "Installing Rust (stable, MSVC toolchain)..."
    & $rustupPath -y --default-toolchain stable --default-host x86_64-pc-windows-msvc 2>&1

    # Add cargo to current session PATH
    $env:PATH += ";$env:USERPROFILE\.cargo\bin"
    Write-Success "Rust installed: $(cargo --version)"
}

# -- Install Visual Studio Build Tools (required for Rust MSVC) ----------------
function Install-BuildTools {
    Write-Step "Checking Visual Studio Build Tools"
    $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vsWhere) {
        $vsInstalls = & $vsWhere -latest -products * -requires Microsoft.VisualCpp.Tools.HostX64.TargetX64 2>$null
        if ($vsInstalls) {
            Write-Success "Visual Studio Build Tools already present."
            return
        }
    }

    Write-Info "Installing Visual Studio Build Tools (C++ workload)..."
    Write-Info "This downloads a ~2 GB installer. Please wait..."
    $vsInstallerUrl = "https://aka.ms/vs/17/release/vs_BuildTools.exe"
    $vsInstallerPath = "$env:TEMP\vs_BuildTools.exe"
    Invoke-WebRequest -Uri $vsInstallerUrl -OutFile $vsInstallerPath -UseBasicParsing

    Start-Process -FilePath $vsInstallerPath -ArgumentList @(
        "--quiet",
        "--wait",
        "--norestart",
        "--add", "Microsoft.VisualStudio.Workload.VCTools",
        "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
        "--add", "Microsoft.VisualStudio.Component.Windows10SDK"
    ) -Wait

    Write-Success "Visual Studio Build Tools installed."
}

# -- Install & Configure Tor ----------------------------------------------------
function Install-Tor {
    if ($SkipTor) { Write-Warn "Skipping Tor setup (--SkipTor flag)."; return }

    Write-Step "Installing & Configuring Tor"

    $TorDir = "C:\Tor"
    $TorExe = "$TorDir\tor.exe"
    $TorRcFile = "$TorDir\torrc"
    $TorDataDir = "$TorDir\data"

    if (Test-Path $TorExe) {
        Write-Success "Tor already found at $TorExe"
    } else {
        Write-Info "Downloading Tor Expert Bundle for Windows..."
        $TorVersion = "15.0.4"
        $TorUrl = "https://archive.torproject.org/tor-package-archive/torbrowser/$TorVersion/tor-expert-bundle-windows-x86_64-$TorVersion.tar.gz"
        $TorArchive = "$env:TEMP\tor-expert-bundle.tar.gz"

        Invoke-WebRequest -Uri $TorUrl -OutFile $TorArchive -UseBasicParsing
        Write-Success "Tor downloaded."

        Write-Info "Extracting Tor..."
        # Use tar (available in Win10 build 17063+)
        $TorExtractDir = "$env:TEMP\tor_extract"
        New-Item -ItemType Directory -Path $TorExtractDir -Force | Out-Null
        & tar -xzf $TorArchive -C $TorExtractDir

        # Move to C:\Tor
        $ExtractedTorDir = Get-ChildItem $TorExtractDir -Recurse -Filter "tor.exe" | Select-Object -First 1 -ExpandProperty DirectoryName
        New-Item -ItemType Directory -Path $TorDir -Force | Out-Null
        Copy-Item "$ExtractedTorDir\*" -Destination $TorDir -Recurse -Force
        Write-Success "Tor extracted to $TorDir"
    }

    # Create data directory
    New-Item -ItemType Directory -Path $TorDataDir -Force | Out-Null

    # Write torrc
    if (-not (Test-Path $TorRcFile)) {
        Write-Info "Creating Tor configuration at $TorRcFile..."
        @"
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
DataDirectory $TorDataDir
"@ | Set-Content -Path $TorRcFile -Encoding UTF8
        Write-Success "Tor config written: $TorRcFile"
    } else {
        Write-Success "Tor config already exists at $TorRcFile"
    }

    # Create a Tor startup script
    $TorStartScript = "$ScriptRoot\start-tor.ps1"
    @"
# ISOTOPE - Start Tor Service (Windows)
Write-Host "[*] Starting Tor..." -ForegroundColor Cyan
Write-Host "[*] Waiting for Tor to bootstrap (100%)..."
Write-Host "[*] Leave this window open while using ISOTOPE." -ForegroundColor Yellow
& "C:\Tor\tor.exe" -f "C:\Tor\torrc"
"@ | Set-Content -Path $TorStartScript -Encoding UTF8

    Write-Success "Tor startup script created: $TorStartScript"
    Write-Warn "Start Tor first with: .\start-tor.ps1  (keep it running in a separate window)"
}

# -- Build ISOTOPE --------------------------------------------------------------
function Build-Isotope {
    if ($SkipBuild) { Write-Warn "Skipping build (--SkipBuild flag)."; return }

    Write-Step "Building ISOTOPE (Release Mode)"
    Write-Info "Compiling cryptographic dependencies - this may take a few minutes..."

    if (-not (Test-Path "$ScriptRoot\Cargo.toml")) {
        Write-Fail "Cargo.toml not found. Run this script from the isotope project root directory."
    }

    Push-Location $ScriptRoot
    try {
        cargo build --release
        Write-Success "Build complete: $ScriptRoot\target\release\isotope.exe"
    } finally {
        Pop-Location
    }
}

# -- Install binary to user PATH ------------------------------------------------
function Install-Binary {
    if ($SkipInstall) { Write-Warn "Skipping binary install (--SkipInstall flag)."; return }

    Write-Step "Installing ISOTOPE to User PATH"
    $BinarySource = "$ScriptRoot\target\release\isotope.exe"

    if (-not (Test-Path $BinarySource)) {
        Write-Warn "Binary not found at $BinarySource. Skipping install."
        return
    }

    $InstallDir = "$env:USERPROFILE\.local\bin"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item $BinarySource -Destination "$InstallDir\isotope.exe" -Force

    # Add to user PATH if not already there
    $CurrentPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    if ($CurrentPath -notlike "*$InstallDir*") {
        [System.Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$InstallDir", "User")
        $env:PATH += ";$InstallDir"
        Write-Info "Added $InstallDir to user PATH."
        Write-Warn "Restart your terminal for 'isotope' to be available globally."
    }

    Write-Success "Installed: $InstallDir\isotope.exe"
}

# -- Generate Quick-Start Scripts -----------------------------------------------
function Generate-QuickStart {
    Write-Step "Generating Quick-Start Scripts"

    # -- Server script ----------------------------------------------------------
    @'
# ISOTOPE - Start Hub (Server) Mode
param(
    [int]$Port = 7878,
    [string]$IdentityFile = "server.id"
)
Write-Host "[*] Starting ISOTOPE server on port $Port with identity: $IdentityFile" -ForegroundColor Cyan
Write-Host "[*] Tor must be running (run .\start-tor.ps1 first)" -ForegroundColor Yellow
Write-Host ""
& isotope server --port $Port --identity $IdentityFile
'@ | Set-Content -Path "$ScriptRoot\start-server.ps1" -Encoding UTF8

    # -- Client script ----------------------------------------------------------
    @'
# ISOTOPE - Start Client (Connect) Mode
param(
    [Parameter(Mandatory=$true)]  [string]$Address,
    [Parameter(Mandatory=$true)]  [string]$Username,
    [Parameter(Mandatory=$true)]  [string]$Fingerprint,
    [string]$IdentityFile = "isotope.id"
)
Write-Host "[*] Connecting to $Address as '$Username'" -ForegroundColor Cyan
Write-Host "[*] Tor must be running (run .\start-tor.ps1 first)" -ForegroundColor Yellow
Write-Host ""
& isotope client `
    --address $Address `
    --username $Username `
    --peer-fingerprint $Fingerprint `
    --identity $IdentityFile
'@ | Set-Content -Path "$ScriptRoot\start-client.ps1" -Encoding UTF8

    # -- Ephemeral script -------------------------------------------------------
    @'
# ISOTOPE - Start Ephemeral (Zero-Trace) Client
param(
    [Parameter(Mandatory=$true)]  [string]$Address,
    [Parameter(Mandatory=$true)]  [string]$Username,
    [Parameter(Mandatory=$true)]  [string]$Fingerprint
)
Write-Host "[*] Starting EPHEMERAL session (no identity stored)" -ForegroundColor Cyan
Write-Host "[*] Tor must be running (run .\start-tor.ps1 first)" -ForegroundColor Yellow
Write-Host ""
& isotope client `
    --address $Address `
    --username $Username `
    --peer-fingerprint $Fingerprint `
    --temp
'@ | Set-Content -Path "$ScriptRoot\start-ephemeral.ps1" -Encoding UTF8

    # -- Tor status checker -----------------------------------------------------
    @'
# ISOTOPE - Check Tor Connectivity
Write-Host "[*] Checking Tor SOCKS proxy on 127.0.0.1:9050..." -ForegroundColor Cyan
$TorTest = Test-NetConnection -ComputerName 127.0.0.1 -Port 9050 -WarningAction SilentlyContinue
if ($TorTest.TcpTestSucceeded) {
    Write-Host "[OK] Tor SOCKS5 port is open." -ForegroundColor Green
} else {
    Write-Host "[FAIL] Tor SOCKS port 9050 is NOT reachable." -ForegroundColor Red
    Write-Host "       Start Tor with: .\start-tor.ps1" -ForegroundColor Yellow
    exit 1
}
Write-Host "[*] Testing Tor network connectivity..." -ForegroundColor Cyan
try {
    $Response = Invoke-RestMethod -Uri "https://check.torproject.org/api/ip" `
        -Proxy "socks5://127.0.0.1:9050" -TimeoutSec 20 -ErrorAction Stop
    if ($Response.IsTor) {
        Write-Host "[OK] Connected via Tor! Exit IP: $($Response.IP)" -ForegroundColor Green
    } else {
        Write-Host "[WARN] Tor check returned: $($Response | ConvertTo-Json)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARN] Could not verify Tor routing (SOCKS proxy may not be supported by Invoke-RestMethod on this version)." -ForegroundColor Yellow
    Write-Host "       Verify manually: curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org" -ForegroundColor DarkGray
}
'@ | Set-Content -Path "$ScriptRoot\check-tor.ps1" -Encoding UTF8

    Write-Success "Quick-start scripts created:"
    Write-Host "  -> start-server.ps1    - Launch ISOTOPE as a Hub/Server" -ForegroundColor Green
    Write-Host "  -> start-client.ps1    - Connect to an existing Hub" -ForegroundColor Green
    Write-Host "  -> start-ephemeral.ps1 - Connect with zero-trace ephemeral mode" -ForegroundColor Green
    Write-Host "  -> start-tor.ps1       - Start the Tor service" -ForegroundColor Green
    Write-Host "  -> check-tor.ps1       - Verify Tor is routing correctly" -ForegroundColor Green
}

# -- Print Summary --------------------------------------------------------------
function Print-Summary {
    Write-Divider
    Write-Host ""
    Write-Host "  ISOTOPE installation complete!" -ForegroundColor Green -NoNewline
    Write-Host ""
    Write-Host ""
    Write-Host "  Quick Start (Windows):" -ForegroundColor White
    Write-Host "  # 1. Start Tor (keep this window open):" -ForegroundColor DarkGray
    Write-Host "  .\start-tor.ps1" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  # 2. Start a server:" -ForegroundColor DarkGray
    Write-Host "  .\start-server.ps1 -Port 7878 -IdentityFile server.id" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  # 3. Connect as client:" -ForegroundColor DarkGray
    Write-Host "  .\start-client.ps1 -Address abc.onion:7878 -Username Ghost -Fingerprint AABB...FF" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  # 4. Zero-trace ephemeral mode:" -ForegroundColor DarkGray
    Write-Host "  .\start-ephemeral.ps1 -Address abc.onion:7878 -Username Ghost -Fingerprint AABB...FF" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Emergency: Press Ctrl+X inside ISOTOPE to trigger instant panic wipe." -ForegroundColor Yellow
    Write-Host ""
    Write-Divider
}

# -- Main -----------------------------------------------------------------------
Write-Banner

if (-not (Test-Admin)) {
    Write-Warn "Not running as Administrator. Some steps (Tor install, system PATH) may require elevation."
    Write-Warn "Re-run as Administrator if you encounter permission errors."
}

Install-Choco
Install-Git
Install-BuildTools
Install-Rust
Install-Tor
Build-Isotope
Install-Binary
Generate-QuickStart
Print-Summary
