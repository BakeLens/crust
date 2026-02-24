#Requires -Version 5.1
<#
.SYNOPSIS
    Crust Installer (Open Source) for Windows.
    https://getcrust.io

.DESCRIPTION
    Installs the Crust Go binary to %LOCALAPPDATA%\Crust\.

.PARAMETER Version
    Install a specific version or branch (e.g. v2.0.0, main). Default: latest.

.PARAMETER NoTUI
    Build without TUI dependencies (plain text only). Also skips font install.

.PARAMETER NoFont
    Skip Nerd Font installation.

.PARAMETER Uninstall
    Uninstall crust completely.

.PARAMETER Help
    Show usage help.

.EXAMPLE
    irm https://install.cat/BakeLens/crust | iex

.EXAMPLE
    .\install.ps1 -Version v2.0.0
    .\install.ps1 -Version main
#>
param(
    [string]$Version = "latest",
    [switch]$NoTUI,
    [switch]$NoFont,
    [switch]$Uninstall,
    [Alias("h")]
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# Configuration
$GitHubRepo = "BakeLens/crust"
$BinaryName = "crust.exe"
$InstallDir = Join-Path $env:LOCALAPPDATA "Crust"
$DataDir    = Join-Path $env:USERPROFILE ".crust"

# --- Help ---
if ($Help) {
    Write-Host "Crust Installer (Open Source)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Version <ver>   Install specific version or branch (e.g. v2.0.0, main)"
    Write-Host "  -NoTUI           Build without TUI dependencies (plain text only)"
    Write-Host "  -NoFont          Skip Nerd Font installation"
    Write-Host "  -Uninstall       Uninstall crust completely"
    Write-Host "  -Help, -h        Show this help"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\install.ps1"
    Write-Host "  .\install.ps1 -Version v2.0.0"
    Write-Host "  .\install.ps1 -NoTUI"
    Write-Host "  .\install.ps1 -Uninstall"
    exit 0
}

function Write-Banner {
    Write-Host ""
    Write-Host "  ____                _   " -ForegroundColor Cyan
    Write-Host " / ___|_ __ _   _ ___| |_ " -ForegroundColor Cyan
    Write-Host "| |   | '__| | | / __| __|" -ForegroundColor Cyan
    Write-Host "| |___| |  | |_| \__ \ |_ " -ForegroundColor Cyan
    Write-Host " \____|_|   \__,_|___/\__|" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Secure gateway for AI agents" -ForegroundColor Blue
    Write-Host ""
}

function Test-Command {
    param([string]$Name)
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-LatestVersion {
    $url = "https://api.github.com/repos/$GitHubRepo/releases/latest"
    try {
        $release = Invoke-RestMethod -Uri $url -UseBasicParsing
        return $release.tag_name
    } catch {
        return "main"
    }
}

function Get-Platform {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64"   { return "amd64" }
        "Arm64" { return "arm64" }
        default {
            Write-Host "Error: Unsupported architecture: $arch" -ForegroundColor Red
            exit 1
        }
    }
}

function Install-NerdFont {
    if ($NoTUI -or $NoFont) { return }

    $nfVersion = "v3.3.0"
    $fontName  = "CascadiaMono"
    $fontUrl   = "https://github.com/ryanoasis/nerd-fonts/releases/download/$nfVersion/$fontName.zip"
    $fontDir   = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts"

    # Skip if already installed
    if (Test-Path (Join-Path $fontDir "CascadiaMonoNF*.ttf")) {
        Write-Host "  Cascadia Mono NF already installed" -ForegroundColor Green
        return
    }

    Write-Host "Installing Cascadia Mono NF (Nerd Font)..." -ForegroundColor Yellow

    $tmpZip = Join-Path ([System.IO.Path]::GetTempPath()) "crust-font-$(Get-Random).zip"
    try {
        Invoke-WebRequest -Uri $fontUrl -OutFile $tmpZip -UseBasicParsing
    } catch {
        Write-Host "  Font download failed (non-fatal)" -ForegroundColor Yellow
        return
    }

    try {
        New-Item -ItemType Directory -Path $fontDir -Force | Out-Null
        $tmpExtract = Join-Path ([System.IO.Path]::GetTempPath()) "crust-font-extract-$(Get-Random)"
        Expand-Archive -Path $tmpZip -DestinationPath $tmpExtract -Force
        $ttfFiles = Get-ChildItem -Path $tmpExtract -Filter "*.ttf" -Recurse
        foreach ($ttf in $ttfFiles) {
            Copy-Item $ttf.FullName (Join-Path $fontDir $ttf.Name) -Force
        }
        # Register fonts with Windows (per-user, no admin needed)
        $regPath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
        foreach ($ttf in $ttfFiles) {
            $fontPath = Join-Path $fontDir $ttf.Name
            Set-ItemProperty -Path $regPath -Name $ttf.BaseName -Value $fontPath -ErrorAction SilentlyContinue
        }
        Write-Host "  Installed to $fontDir" -ForegroundColor Green
        Remove-Item $tmpExtract -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  Font extraction failed (non-fatal)" -ForegroundColor Yellow
    } finally {
        Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue
    }
}

# --- Uninstall ---
if ($Uninstall) {
    Write-Banner
    Write-Host "Uninstalling Crust..." -ForegroundColor White

    # Stop crust if running
    if (Test-Command "crust") {
        Write-Host "Stopping crust..." -ForegroundColor Yellow
        try { crust stop 2>$null } catch {}
    }

    # Remove shell completion
    $crustBin = Join-Path $InstallDir $BinaryName
    if (Test-Path $crustBin) {
        Write-Host "Removing shell completion..." -ForegroundColor Yellow
        try { & $crustBin completion --uninstall 2>$null } catch {}
    }

    # Remove binary
    if (Test-Path $crustBin) {
        Write-Host "Removing binary..." -ForegroundColor Yellow
        Remove-Item $crustBin -Force
        Write-Host "  Removed: $crustBin" -ForegroundColor Green
    }

    # Remove install directory if empty
    if ((Test-Path $InstallDir) -and @(Get-ChildItem $InstallDir).Count -eq 0) {
        Remove-Item $InstallDir -Force
    }

    # Remove from PATH
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -like "*$InstallDir*") {
        Write-Host "Removing from PATH..." -ForegroundColor Yellow
        $newPath = ($userPath -split ';' | Where-Object { $_ -ne $InstallDir }) -join ';'
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        Write-Host "  PATH updated" -ForegroundColor Green
    }

    # Ask about data directory
    if (Test-Path $DataDir) {
        Write-Host ""
        $confirm = Read-Host "Remove data directory ($DataDir)? This contains config, rules, and telemetry [y/N]"
        if ($confirm -eq 'y' -or $confirm -eq 'Y') {
            Remove-Item $DataDir -Recurse -Force
            Write-Host "  Removed: $DataDir" -ForegroundColor Green
        } else {
            Write-Host "  Kept: $DataDir" -ForegroundColor Blue
        }
    }

    Write-Host ""
    Write-Host "Crust uninstalled successfully." -ForegroundColor Green
    Write-Host ""
    exit 0
}

# --- Main ---
Write-Banner

# Check requirements
if (-not (Test-Command "go")) {
    Write-Host "Error: Go is required but not found. Install from https://go.dev/dl/" -ForegroundColor Red
    exit 1
}
if (-not (Test-Command "git")) {
    Write-Host "Error: Git is required but not found. Install from https://git-scm.com/" -ForegroundColor Red
    exit 1
}

# Detect platform
$Arch = Get-Platform
Write-Host "  OS:   windows" -ForegroundColor Green
Write-Host "  Arch: $Arch" -ForegroundColor Green
Write-Host ""

# Resolve version
if ($Version -eq "latest") {
    Write-Host "Fetching latest version..." -ForegroundColor Yellow
    $Version = Get-LatestVersion
}
Write-Host "  Version: $Version" -ForegroundColor Green
Write-Host ""

# Clone repo
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "crust-install-$(Get-Random)"
try {
    Write-Host "Cloning repository..." -ForegroundColor Yellow
    $CloneUrl = "https://github.com/$GitHubRepo.git"
    # Use Start-Process to avoid $ErrorActionPreference="Stop" killing on git stderr
    $gitResult = Start-Process -FilePath "git" -ArgumentList "clone","--depth","1","--branch",$Version,$CloneUrl,$TmpDir -Wait -NoNewWindow -PassThru 2>$null
    if ($gitResult.ExitCode -ne 0) {
        & git clone --depth 1 $CloneUrl $TmpDir 2>$null
    }

    # Build Go binary
    $versionFlag = $Version -replace '^v', ''
    $buildArgs = @("build", "-ldflags", "-X main.Version=$versionFlag", "-o", "crust.exe", ".")
    if ($NoTUI) {
        Write-Host "Building Crust (no TUI)..." -ForegroundColor Yellow
        $buildArgs = @("build", "-tags", "notui", "-ldflags", "-X main.Version=$versionFlag", "-o", "crust.exe", ".")
    } else {
        Write-Host "Building Crust..." -ForegroundColor Yellow
    }
    Push-Location $TmpDir
    & go @buildArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Build failed" -ForegroundColor Red
        exit 1
    }
    Pop-Location

    # Install
    Write-Host "Installing to $InstallDir..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item (Join-Path $TmpDir "crust.exe") (Join-Path $InstallDir $BinaryName) -Force

    # Create data directory
    Write-Host "Creating data directory..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $DataDir "rules.d") -Force | Out-Null

    # Add to PATH if needed
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -notlike "*$InstallDir*") {
        Write-Host "Adding $InstallDir to user PATH..." -ForegroundColor Yellow
        [Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$userPath", "User")
        $env:PATH = "$InstallDir;$env:PATH"
        Write-Host "  PATH updated (restart your terminal to apply)" -ForegroundColor Yellow
    }

    # Install shell completion
    Write-Host "Installing shell completion..." -ForegroundColor Yellow
    $crustBin = Join-Path $InstallDir $BinaryName
    try {
        & $crustBin completion --install 2>$null
        Write-Host "  Shell completion installed" -ForegroundColor Green
        Write-Host "  Restart your shell to activate" -ForegroundColor Yellow
    } catch {
        Write-Host "  Shell completion setup skipped (non-fatal)" -ForegroundColor Yellow
    }

    # Install Nerd Font
    Install-NerdFont

    # Success
    Write-Host ""
    Write-Host "Crust installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Binary: $InstallDir\$BinaryName" -ForegroundColor Blue
    Write-Host "  Data:   $DataDir\" -ForegroundColor Blue
    Write-Host ""
    Write-Host "Quick Start:" -ForegroundColor White
    Write-Host ""
    Write-Host "  crust start                    # Start with interactive setup"
    Write-Host "  crust status                   # Check status"
    Write-Host "  crust logs -f                  # Follow logs"
    Write-Host "  crust stop                     # Stop crust"
    Write-Host ""
} finally {
    if (Test-Path $TmpDir) {
        Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
