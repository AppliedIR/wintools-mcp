#Requires -Version 5.1
<#
.SYNOPSIS
    AIIR Platform Installer for Windows Forensic Workstation

.DESCRIPTION
    Installs wintools-mcp on an isolated Windows forensic workstation.
    Scans for forensic tools, generates an inventory report, starts the
    MCP server, and configures auto-start.

    SECURITY: This installer opens an HTTP endpoint that allows an LLM
    to execute forensic tools on this system. It must only be installed
    on dedicated forensic workstations that are isolated behind firewalls
    on a trusted network segment. Never install on personal laptops,
    production systems, or machines containing data outside the scope
    of the investigation.

    Two installation modes are supported:

    AIIR Mode (default):
      Integrates with the full AIIR platform on a SIFT workstation.
      Case directory is accessed via SMB from the SIFT share. Audit
      trail, evidence files, and tool output are written to the shared
      case directory. Requires network access to the SIFT workstation.

    Standalone Mode (-Standalone):
      Runs independently without a SIFT workstation. Case directory
      and audit trail are stored locally. Useful for single-machine
      forensic analysis or when SIFT integration is not available.

.PARAMETER AcknowledgeSecurityHole
    Bypass the interactive security acknowledgment prompt. Required for
    non-interactive installations. Confirms you understand that this MCP
    opens attack vectors where connected LLM clients can execute tools
    on this system.

.PARAMETER Standalone
    Install in standalone mode without SIFT integration. Case directory
    and audit trail are stored locally instead of on a shared SMB mount.

.PARAMETER NonInteractive
    Run without interactive prompts. Uses defaults for all options.
    Requires -AcknowledgeSecurityHole.

.PARAMETER InstallDir
    Installation directory. Default: C:\Tools\aiir or %USERPROFILE%\aiir.

.PARAMETER Examiner
    Examiner identity slug (lowercase, e.g., "steve"). Default: current
    Windows username.

.PARAMETER Port
    HTTP server port. Default: 4624.

.PARAMETER BindAddress
    HTTP server bind address. Default: 0.0.0.0 (all interfaces).

.PARAMETER NoAuth
    Skip API key generation. The wintools-mcp server will accept
    unauthenticated requests. Use only for development on isolated networks.

.EXAMPLE
    # Interactive install with full AIIR integration
    .\setup-windows.ps1

.EXAMPLE
    # Interactive standalone install (no SIFT needed)
    .\setup-windows.ps1 -Standalone

.EXAMPLE
    # Non-interactive with AIIR integration
    .\setup-windows.ps1 -NonInteractive -AcknowledgeSecurityHole

.EXAMPLE
    # Non-interactive standalone with custom directory
    .\setup-windows.ps1 -Standalone -NonInteractive -AcknowledgeSecurityHole -InstallDir "D:\Forensics\aiir"

.EXAMPLE
    # Custom port and examiner
    .\setup-windows.ps1 -Examiner "steve" -Port 8443

.EXAMPLE
    # Deployment: Solo analyst, one Windows VM
    #   1. Install forensic tools (Zimmerman, Hayabusa, Sysinternals)
    #   2. Run this installer in standalone mode
    #   3. Configure your LLM client to connect to this machine
    .\setup-windows.ps1 -Standalone
    # Then on the analyst machine:
    #   aiir setup client --windows=WIN_IP:4624

.EXAMPLE
    # Deployment: SIFT + Windows (typical team setup)
    #   1. Install AIIR on SIFT:  ./sift-install.sh
    #   2. Install on Windows:    .\setup-windows.ps1
    #   3. Map SMB share:         net use Z: \\SIFT_IP\cases
    #   4. Set case dir:          set AIIR_CASE_DIR=Z:\INC-2026-0001
    #   5. Configure client:      aiir setup client --sift=SIFT_IP:4508 --windows=WIN_IP:4624
    .\setup-windows.ps1

.EXAMPLE
    # Deployment: Air-gapped lab
    #   Pre-stage: clone wintools-mcp repo to USB, transfer to lab
    #   Then run installer pointing to pre-staged directory
    .\setup-windows.ps1 -Standalone -InstallDir "E:\aiir"
#>
[CmdletBinding()]
param(
    [switch]$AcknowledgeSecurityHole,
    [switch]$Standalone,
    [switch]$NonInteractive,
    [string]$InstallDir = "",
    [string]$Examiner = "",
    [int]$Port = 4624,
    [string]$BindAddress = "0.0.0.0",
    [switch]$NoAuth
)

$ErrorActionPreference = "Stop"

# =============================================================================
# Helpers
# =============================================================================

function Write-Info   { param($msg) Write-Host "[INFO] " -ForegroundColor Blue -NoNewline; Write-Host $msg }
function Write-Ok     { param($msg) Write-Host "[OK] " -ForegroundColor Green -NoNewline; Write-Host $msg }
function Write-Warn   { param($msg) Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline; Write-Host $msg }
function Write-Err    { param($msg) Write-Host "[ERROR] " -ForegroundColor Red -NoNewline; Write-Host $msg }
function Write-Header { param($msg) Write-Host "`n=== $msg ===`n" -ForegroundColor White }

function Read-Prompt {
    param([string]$Message, [string]$Default = "")
    if ($NonInteractive) { return $Default }
    if ($Default) {
        $answer = Read-Host "$Message [$Default]"
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        return $answer
    }
    return Read-Host $Message
}

function Read-YesNo {
    param([string]$Message, [bool]$Default = $true)
    if ($NonInteractive) { return $Default }
    if ($Default) { $suffix = "[Y/n]" } else { $suffix = "[y/N]" }
    $answer = Read-Host "$Message $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    return $answer.ToLower().StartsWith("y")
}

# =============================================================================
# Banner
# =============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "  AIIR - Artificial Intelligence Incident Response" -ForegroundColor White
Write-Host "  Windows Workstation Installer" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if ($Standalone) {
    Write-Host "  Mode: Standalone (local case directory)" -ForegroundColor Cyan
} else {
    Write-Host "  Mode: AIIR-integrated (SMB to SIFT workstation)" -ForegroundColor Cyan
}
Write-Host ""

# =============================================================================
# Security Acknowledgment
# =============================================================================

if (-not $AcknowledgeSecurityHole) {
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "  SECURITY WARNING - READ CAREFULLY" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  This installer sets up an MCP server that allows connected" -ForegroundColor Yellow
    Write-Host "  LLM clients to execute forensic tools on this system." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  This opens attack vectors where malicious actors could" -ForegroundColor Yellow
    Write-Host "  potentially run arbitrary code on this machine through" -ForegroundColor Yellow
    Write-Host "  the MCP interface." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  This system MUST be:" -ForegroundColor White
    Write-Host "    - A dedicated forensic workstation, NOT a personal" -ForegroundColor White
    Write-Host "      laptop or production system" -ForegroundColor White
    Write-Host "    - Isolated behind firewalls on a trusted network" -ForegroundColor White
    Write-Host "      segment with no inbound Internet access" -ForegroundColor White
    Write-Host "    - Free of sensitive data outside the scope of" -ForegroundColor White
    Write-Host "      the current investigation" -ForegroundColor White
    Write-Host "    - A system you are willing to rebuild if compromised" -ForegroundColor White
    Write-Host ""
    Write-Host "  Any data on this system may be transmitted to the" -ForegroundColor Yellow
    Write-Host "  configured AI provider. Never place original evidence" -ForegroundColor Yellow
    Write-Host "  on this system. Only use working copies." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Despite defense-in-depth measures (catalog allowlists," -ForegroundColor White
    Write-Host "  denylist of dangerous binaries, argument sanitization," -ForegroundColor White
    Write-Host "  shell=False execution), this MCP is NOT hardened for" -ForegroundColor White
    Write-Host "  hostile environments." -ForegroundColor White
    Write-Host ""

    if ($NonInteractive) {
        Write-Err "Non-interactive mode requires -AcknowledgeSecurityHole"
        Write-Host ""
        Write-Host "  Usage: .\setup-windows.ps1 -NonInteractive -AcknowledgeSecurityHole"
        Write-Host ""
        exit 1
    }

    Write-Host "  To proceed, type: security_hole" -ForegroundColor Red
    Write-Host ""
    $ack = Read-Host "  Acknowledgment"
    if ($ack -ne "security_hole") {
        Write-Err "Installation cancelled. You must type 'security_hole' exactly to proceed."
        Write-Host ""
        Write-Host "  If you want to bypass this prompt in scripts, use:"
        Write-Host "  .\setup-windows.ps1 -AcknowledgeSecurityHole"
        Write-Host ""
        exit 1
    }
    Write-Ok "Security acknowledgment accepted"
    Write-Host ""
} else {
    Write-Info "Security acknowledgment provided via -AcknowledgeSecurityHole"
}

# =============================================================================
# Prerequisites
# =============================================================================

Write-Header "Phase 1: Prerequisites"

# Python 3.11+
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py -3")) {
    try {
        $ver = & ($cmd.Split(" ")[0]) @($cmd.Split(" ") | Select-Object -Skip 1) -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>&1
        if ($ver) {
            $parts = $ver.Split(".")
            $major = [int]$parts[0]
            $minor = [int]$parts[1]
            if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 11)) {
                $pythonCmd = $cmd
                Write-Ok "Python $ver"
                break
            }
        }
    } catch { }
}

if (-not $pythonCmd) {
    Write-Err "Python 3.11+ not found"
    Write-Host "  Install from: https://www.python.org/downloads/"
    Write-Host "  Or via winget: winget install Python.Python.3.12"
    exit 1
}

# pip
try {
    & ($pythonCmd.Split(" ")[0]) @($pythonCmd.Split(" ") | Select-Object -Skip 1) -m pip --version 2>&1 | Out-Null
    Write-Ok "pip available"
} catch {
    Write-Err "pip not found"
    Write-Host "  Run: $pythonCmd -m ensurepip --upgrade"
    exit 1
}

# git (optional -- ZIP fallback available)
$hasGit = $null -ne (Get-Command git -ErrorAction SilentlyContinue)
if ($hasGit) {
    try { $gitVer = (git --version 2>&1) -replace "git version ", "" } catch { $gitVer = "unknown" }
    Write-Ok "git $gitVer"
} else {
    Write-Info "git not found -- will download as ZIP (updates require git)"
}

# .NET Runtime (for Zimmerman tools)
$hasDotnet = $false
try {
    if (Get-Command dotnet -ErrorAction SilentlyContinue) {
        $dotnetVer = (dotnet --version 2>&1)
        if ($LASTEXITCODE -eq 0 -and $dotnetVer) {
            Write-Ok ".NET $dotnetVer"
            $hasDotnet = $true
        }
    }
} catch { }
if (-not $hasDotnet) {
    Write-Warn ".NET Runtime not found (needed for Zimmerman tools)"
    Write-Host "  Install from: https://dotnet.microsoft.com/download"
    Write-Host "  Or via winget: winget install Microsoft.DotNet.Runtime.8"
}

# Network (test with a public endpoint -- AppliedIR repos may be private)
$networkOk = $false
try {
    $null = Invoke-WebRequest -Uri "https://github.com" -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    $networkOk = $true
} catch { }
if (-not $networkOk -and $hasGit) {
    try {
        git ls-remote https://github.com/AppliedIR/wintools-mcp.git HEAD 2>&1 | Out-Null
        $networkOk = $true
    } catch { }
}
if ($networkOk) {
    Write-Ok "Network access to GitHub"
} else {
    Write-Warn "Cannot reach GitHub -- installation requires network access"
    exit 1
}

# =============================================================================
# Install
# =============================================================================

Write-Header "Phase 2: Installing wintools-mcp"

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $defaultDir = "C:\Tools\aiir"
    if (-not (Test-Path "C:\Tools")) {
        $defaultDir = "$env:USERPROFILE\aiir"
    }
    $InstallDir = Read-Prompt "Installation directory" $defaultDir
}

if (-not (Test-Path $InstallDir)) {
    try {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    } catch {
        Write-Err "Cannot create directory: $InstallDir"
        exit 1
    }
}
Write-Info "Installing to $InstallDir"

$githubOrg = "https://github.com/AppliedIR"
$wintoolsDir = Join-Path $InstallDir "wintools-mcp"
$wintoolsConfigPath = Join-Path $wintoolsDir "config.yaml"

# Helper: download a repo as ZIP (no git required)
function Get-RepoAsZip {
    param([string]$RepoName, [string]$DestDir)
    $zipUrl = "$githubOrg/$RepoName/archive/refs/heads/main.zip"
    $zipPath = Join-Path $InstallDir "$RepoName.zip"
    $extractedDir = Join-Path $InstallDir "$RepoName-main"
    Write-Info "Downloading $RepoName..."
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
    } catch {
        Remove-Item $zipPath -ErrorAction SilentlyContinue
        throw "Download failed for $RepoName`: $_"
    }
    try {
        Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force
    } catch {
        Remove-Item $zipPath -ErrorAction SilentlyContinue
        throw "Extract failed for $RepoName`: $_"
    }
    Remove-Item $zipPath -ErrorAction SilentlyContinue
    if (Test-Path $extractedDir) {
        if (Test-Path $DestDir) { Remove-Item $DestDir -Recurse -Force }
        Rename-Item $extractedDir $DestDir
    } else {
        throw "Expected directory $extractedDir not found after extraction"
    }
}

# Clone or download wintools-mcp
$cloneOk = $false
if ($hasGit) {
    try {
        if (Test-Path $wintoolsDir) {
            Write-Info "Directory exists, pulling latest..."
            Push-Location $wintoolsDir
            try { git pull --quiet 2>&1 | Out-Null } catch { Write-Warn "Could not update (network issue?)" }
            Pop-Location
            $cloneOk = $true
        } else {
            git clone --quiet "$githubOrg/wintools-mcp.git" $wintoolsDir 2>&1 | Out-Null
            $cloneOk = $true
        }
    } catch {
        Write-Warn "git clone failed, falling back to ZIP download"
    }
}
if (-not $cloneOk) {
    try {
        if (Test-Path $wintoolsDir) {
            Write-Info "Directory exists, re-downloading..."
        }
        Get-RepoAsZip "wintools-mcp" $wintoolsDir
        Write-Ok "wintools-mcp downloaded"
    } catch {
        Write-Err "Failed to download wintools-mcp"
        exit 1
    }
}

# Create venv and install
$venvDir = Join-Path $wintoolsDir ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

if (-not (Test-Path $venvDir)) {
    try {
        & ($pythonCmd.Split(" ")[0]) @($pythonCmd.Split(" ") | Select-Object -Skip 1) -m venv $venvDir
    } catch {
        Write-Err "Failed to create Python virtual environment"
        exit 1
    }
}
if (-not (Test-Path $venvPython)) {
    Write-Err "Virtual environment created but python.exe not found at: $venvPython"
    exit 1
}

try { & $venvPython -m pip install --progress-bar off --upgrade pip 2>&1 | Out-Null } catch { }

# Install wintools-mcp without FK first (always works)
try { & $venvPython -m pip install --progress-bar off -e "$wintoolsDir" 2>&1 | Out-Null } catch {
    Write-Err "Failed to install wintools-mcp"
    exit 1
}

# Try to install forensic-knowledge (best-effort)
$fkDir = Join-Path $InstallDir "forensic-knowledge"
$fkInstalled = $false

# Try pip install first (works if published to PyPI or private index)
try {
    & $venvPython -m pip install --progress-bar off forensic-knowledge 2>&1 | Out-Null
    $fkTest = & $venvPython -c "import forensic_knowledge; print('ok')" 2>&1
    if ($fkTest -eq "ok") { $fkInstalled = $true }
} catch { }

# If pip didn't work, try git clone / ZIP (existing logic)
if (-not $fkInstalled -and -not (Test-Path $fkDir)) {
    $fkCloneOk = $false
    if ($hasGit) {
        try {
            git clone --quiet "$githubOrg/forensic-knowledge.git" $fkDir 2>&1 | Out-Null
            $fkCloneOk = $true
        } catch {
            Write-Warn "git clone failed for forensic-knowledge, trying ZIP download"
        }
    }
    if (-not $fkCloneOk) {
        try {
            Get-RepoAsZip "forensic-knowledge" $fkDir
        } catch {
            Write-Warn "Could not download forensic-knowledge (FK enrichment will be unavailable)"
        }
    }
}

if (-not $fkInstalled -and (Test-Path $fkDir)) {
    try {
        & $venvPython -m pip install --progress-bar off -e $fkDir 2>&1 | Out-Null
        $fkTest = & $venvPython -c "import forensic_knowledge; print('ok')" 2>&1
        if ($fkTest -eq "ok") {
            $fkInstalled = $true
        }
    } catch { }
}

if ($fkInstalled) {
    Write-Ok "forensic-knowledge installed (FK enrichment enabled)"
} else {
    Write-Warn "forensic-knowledge not available (FK enrichment disabled -- wintools-mcp works without it)"
}

# Smoke test
try {
    $result = & $venvPython -c "import wintools_mcp; print('ok')" 2>&1
    if ($result -eq "ok") {
        Write-Ok "wintools-mcp installed and importable"
    } else {
        Write-Warn "wintools-mcp installed but import failed -- check dependencies"
    }
} catch {
    Write-Warn "wintools-mcp installed but import failed -- check dependencies"
}

# =============================================================================
# Examiner Identity
# =============================================================================

Write-Header "Phase 3: Examiner Identity"

Write-Host "Your examiner name identifies your work in audit trails."
Write-Host "Use a short slug (e.g., steve, jane, analyst1)."
Write-Host ""

if ([string]::IsNullOrWhiteSpace($Examiner)) {
    $defaultExaminer = $env:USERNAME.ToLower() -replace "[^a-z0-9-]", ""
    $Examiner = Read-Prompt "Examiner name" $defaultExaminer
}
$Examiner = $Examiner.ToLower() -replace "[^a-z0-9-]", ""
if ([string]::IsNullOrWhiteSpace($Examiner)) {
    $Examiner = $env:USERNAME.ToLower() -replace "[^a-z0-9-]", ""
}

# Save config
try {
    $aiirConfigDir = Join-Path $env:USERPROFILE ".aiir"
    if (-not (Test-Path $aiirConfigDir)) {
        New-Item -ItemType Directory -Path $aiirConfigDir -Force | Out-Null
    }
    "examiner: $Examiner" | Set-Content -Path (Join-Path $aiirConfigDir "config.yaml") -Encoding UTF8
    Write-Ok "Saved examiner identity: $Examiner"
} catch {
    Write-Warn "Could not save examiner config to ~/.aiir/config.yaml"
}

# Set env var persistently
try {
    [Environment]::SetEnvironmentVariable("AIIR_EXAMINER", $Examiner, "User")
    $env:AIIR_EXAMINER = $Examiner
    Write-Ok "Set AIIR_EXAMINER=$Examiner"
} catch {
    Write-Warn "Could not set AIIR_EXAMINER environment variable"
    $env:AIIR_EXAMINER = $Examiner
}

# =============================================================================
# Tool Inventory
# =============================================================================

Write-Header "Phase 4: Scanning for Forensic Tools"

# Run scan and capture output
try { $scanOutput = & $venvPython -m wintools_mcp --scan 2>&1 } catch { $scanOutput = $null }

if ($scanOutput) {
    Write-Host $($scanOutput -join "`n")
} else {
    Write-Warn "Tool scan could not run"
}

# Generate TOOLS_OVERVIEW.md
Write-Host ""
Write-Info "Generating tool inventory report..."

$overviewPath = Join-Path $InstallDir "TOOLS_OVERVIEW.md"
try {
$overviewContent = & $venvPython -c @"
import json
from datetime import datetime
from wintools_mcp.catalog import load_catalog
from wintools_mcp.environment import find_binary

catalog = load_catalog()
found = []
missing = []
for name, td in sorted(catalog.items()):
    path = find_binary(td.binary)
    if path:
        found.append((td.name, td.category, td.binary, path))
    else:
        missing.append((td.name, td.category, td.description or ''))

lines = []
lines.append(f'# AIIR Tool Inventory - {datetime.now().strftime("%Y-%m-%d %H:%M")}')
lines.append('')
lines.append(f'Generated by setup-windows.ps1 on {datetime.now().strftime("%Y-%m-%d")}.')
lines.append(f'wintools-mcp rescans automatically on each discovery call.')
lines.append('')
lines.append(f'## Installed ({len(found)}/{len(found)+len(missing)})')
lines.append('')
if found:
    lines.append('| Tool | Category | Path |')
    lines.append('|------|----------|------|')
    for name, cat, binary, path in found:
        lines.append(f'| {name} | {cat} | {path} |')
else:
    lines.append('No tools found.')
lines.append('')
lines.append(f'## Missing ({len(missing)}/{len(found)+len(missing)})')
lines.append('')
if missing:
    lines.append('| Tool | Category | Description |')
    lines.append('|------|----------|-------------|')
    for name, cat, desc in missing:
        lines.append(f'| {name} | {cat} | {desc} |')
else:
    lines.append('All catalog tools are installed.')
lines.append('')
lines.append('## Notes')
lines.append('')
lines.append('- Install missing tools and restart wintools-mcp (or call scan_tools via MCP)')
lines.append('- wintools-mcp checks tool availability dynamically on each discovery call')
lines.append('- Common tool sources:')
lines.append('  - Zimmerman Suite: https://ericzimmerman.github.io/')
lines.append('  - Hayabusa: https://github.com/Yamato-Security/hayabusa/releases')
lines.append('  - Sysinternals: winget install Microsoft.Sysinternals')
lines.append('')
print('\n'.join(lines))
"@ 2>&1
} catch { $overviewContent = $null }

if ($overviewContent) {
    try {
        $overviewContent -join "`n" | Set-Content -Path $overviewPath -Encoding UTF8
        Write-Ok "Generated: $overviewPath"
    } catch {
        Write-Warn "Could not write TOOLS_OVERVIEW.md"
    }
} else {
    Write-Warn "Could not generate TOOLS_OVERVIEW.md"
}

# =============================================================================
# Case Directory Setup (mode-dependent)
# =============================================================================

# Detect local IP early -- needed for gateway config snippets in Phase 5
$localIp = $null
try {
    $localIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "Loopback*" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress
} catch { }
if (-not $localIp) { $localIp = "THIS_MACHINE_IP" }

Write-Header "Phase 5: Case Directory"

$wintoolsApiKey = ""

if ($Standalone) {
    # --- Standalone mode: local case directory ---
    $defaultCaseDir = Join-Path $InstallDir "cases"
    $caseDir = Read-Prompt "Local case directory" $defaultCaseDir

    if (-not (Test-Path $caseDir)) {
        try {
            New-Item -ItemType Directory -Path $caseDir -Force | Out-Null
        } catch {
            Write-Err "Cannot create case directory: $caseDir"
            exit 1
        }
    }
    Write-Ok "Case directory: $caseDir"

    Write-Host ""
    Write-Host "  In standalone mode, each case gets a subdirectory:" -ForegroundColor White
    Write-Host "    $caseDir\INC-2026-0001\" -ForegroundColor White
    Write-Host "    $caseDir\INC-2026-0001\examiners\$Examiner\" -ForegroundColor White
    Write-Host "    $caseDir\INC-2026-0001\examiners\$Examiner\audit\" -ForegroundColor White
    Write-Host ""
    Write-Host "  Set AIIR_CASE_DIR before starting a case:" -ForegroundColor White
    Write-Host "    set AIIR_CASE_DIR=$caseDir\INC-2026-0001" -ForegroundColor White
    Write-Host ""
    Write-Host "  Place evidence working copies in the case directory." -ForegroundColor White
    Write-Host "  Tool output and audit entries are written alongside" -ForegroundColor White
    Write-Host "  the evidence in the examiner's subdirectory." -ForegroundColor White
    Write-Host ""

    # Save standalone config
    try {
        [Environment]::SetEnvironmentVariable("WINTOOLS_CASE_ROOT", $caseDir, "User")
        $env:WINTOOLS_CASE_ROOT = $caseDir
        Write-Ok "Set WINTOOLS_CASE_ROOT=$caseDir"
    } catch {
        Write-Warn "Could not set WINTOOLS_CASE_ROOT environment variable"
        $env:WINTOOLS_CASE_ROOT = $caseDir
    }

    # Write standalone config.yaml (no API key by default for single-machine use)
    if (-not (Test-Path $wintoolsConfigPath)) {
        try {
            @"
# wintools-mcp configuration (generated by setup-windows.ps1)
http_host: "$BindAddress"
http_port: $Port
"@ | Set-Content -Path $wintoolsConfigPath -Encoding UTF8
            Write-Ok "Wrote config: $wintoolsConfigPath"
        } catch {
            Write-Warn "Could not write config.yaml"
        }
    } else {
        Write-Info "Existing config found -- preserving: $wintoolsConfigPath"
    }
} else {
    # --- AIIR mode: SMB to SIFT ---
    Write-Host "  In AIIR mode, the case directory lives on the SIFT" -ForegroundColor White
    Write-Host "  workstation and is accessed via SMB share." -ForegroundColor White
    Write-Host ""
    Write-Host "  Setup steps:" -ForegroundColor White
    Write-Host ""
    Write-Host "  1. On the SIFT workstation, share the cases directory:" -ForegroundColor White
    Write-Host "     sudo mkdir -p /cases" -ForegroundColor Gray
    Write-Host "     sudo chown \$USER:forensics /cases" -ForegroundColor Gray
    Write-Host ""
    Write-Host "     # Option A: Samba (recommended for Windows clients)" -ForegroundColor Gray
    Write-Host "     # Add to /etc/samba/smb.conf:" -ForegroundColor Gray
    Write-Host "     [cases]" -ForegroundColor Gray
    Write-Host "         path = /cases" -ForegroundColor Gray
    Write-Host "         browsable = yes" -ForegroundColor Gray
    Write-Host "         writable = yes" -ForegroundColor Gray
    Write-Host "         valid users = @forensics" -ForegroundColor Gray
    Write-Host "     # Then: sudo systemctl restart smbd" -ForegroundColor Gray
    Write-Host ""
    Write-Host "     # Option B: net usershare (simpler, single user)" -ForegroundColor Gray
    Write-Host "     sudo net usershare add cases /cases" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  2. On this Windows machine, map the share:" -ForegroundColor White
    Write-Host "     net use Z: \\SIFT_IP\cases /persistent:yes" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  3. Set AIIR_CASE_DIR when starting a case:" -ForegroundColor White
    Write-Host "     set AIIR_CASE_DIR=Z:\INC-2026-0001" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  This ensures that audit trail entries from wintools-mcp" -ForegroundColor White
    Write-Host "  are written to the same case directory as the SIFT MCPs," -ForegroundColor White
    Write-Host "  maintaining a unified evidence record." -ForegroundColor White
    Write-Host ""

    # --- Gateway connectivity ---
    Write-Host "--- SIFT Gateway Integration ---" -ForegroundColor White
    Write-Host ""
    Write-Host "  The SIFT gateway connects to this wintools-mcp server" -ForegroundColor White
    Write-Host "  as an HTTP backend. An API key protects this endpoint" -ForegroundColor White
    Write-Host "  so only the gateway can issue tool calls." -ForegroundColor White
    Write-Host ""

    # Generate an API key for gateway-to-wintools auth
    $gatewayScheme = "http"
    if (-not $NonInteractive) {
        $siftIp = Read-Prompt "SIFT workstation IP or hostname (blank to skip)" ""
        if ($siftIp) {
            $siftPort = Read-Prompt "SIFT gateway port" "4508"

            # Try HTTPS first (TLS-enabled gateway), fall back to HTTP
            $gatewayReachable = $false
            foreach ($scheme in @("https", "http")) {
                try {
                    $response = Invoke-WebRequest -Uri "${scheme}://${siftIp}:${siftPort}/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
                    Write-Ok "Connected to SIFT gateway at ${scheme}://${siftIp}:${siftPort}"
                    $gatewayReachable = $true
                    $gatewayScheme = $scheme
                    break
                } catch { }
            }
            if (-not $gatewayReachable) {
                Write-Warn "Cannot reach SIFT gateway at ${siftIp}:${siftPort}"
                Write-Host "  Ensure the AIIR gateway is running on the SIFT workstation"
            }
        }
    }

    # Token generation: always in AIIR mode unless --NoAuth
    if ($NoAuth) {
        Write-Warn "No API key configured -- wintools-mcp is unprotected"
        Write-Host "  Use --NoAuth only for development on isolated networks"
    } else {
        try {
            # Generate a random key: aiir_wt_ + 24 hex chars
            $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
            $bytes = New-Object byte[] 12
            $rng.GetBytes($bytes)
            $wintoolsApiKey = "aiir_wt_" + [BitConverter]::ToString($bytes).Replace("-", "").ToLower()
            $rng.Dispose()
            Write-Ok "Generated API key: $wintoolsApiKey"
        } catch {
            Write-Warn "Could not generate API key"
        }
    }

    # Write wintools-mcp config.yaml with API key if provided
    # Preserve existing config on re-run (delete config.yaml to regenerate)
    if (Test-Path $wintoolsConfigPath) {
        Write-Info "Existing config found -- preserving: $wintoolsConfigPath"
        Write-Host "  Delete $wintoolsConfigPath and re-run to regenerate"
    } else {
    try {
    if ($wintoolsApiKey) {
        @"
# wintools-mcp configuration (generated by setup-windows.ps1)
http_host: "$BindAddress"
http_port: $Port

api_keys:
  ${wintoolsApiKey}:
    examiner: "gateway"
    role: "examiner"
"@ | Set-Content -Path $wintoolsConfigPath -Encoding UTF8
        Write-Ok "Wrote config with API key: $wintoolsConfigPath"
        Write-Host ""
        Write-Host "  Add this to your SIFT gateway.yaml backends:" -ForegroundColor White
        Write-Host "    wintools-mcp:" -ForegroundColor Gray
        Write-Host "      type: http" -ForegroundColor Gray
        Write-Host "      url: `"http://${localIp}:${Port}/mcp`"" -ForegroundColor Gray
        Write-Host "      bearer_token: `"$wintoolsApiKey`"" -ForegroundColor Gray
        Write-Host "      enabled: true" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  Once configured, clients access wintools via the gateway at:" -ForegroundColor White
        Write-Host "    http://SIFT_IP:4508/mcp/wintools-mcp" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  No direct connection to the Windows VM needed from client machines." -ForegroundColor White
        Write-Host ""
    } else {
        @"
# wintools-mcp configuration (generated by setup-windows.ps1)
http_host: "$BindAddress"
http_port: $Port
"@ | Set-Content -Path $wintoolsConfigPath -Encoding UTF8
        Write-Ok "Wrote config (no API key): $wintoolsConfigPath"
    }
    } catch {
        Write-Warn "Could not write config.yaml"
    }
    } # end config preservation else
}

# =============================================================================
# Start MCP Server
# =============================================================================

Write-Header "Phase 6: Starting wintools-mcp"

# Check if port is already in use
try {
    $existing = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($existing) {
        $existingPid = ($existing | Select-Object -First 1).OwningProcess
        $existingName = (Get-Process -Id $existingPid -ErrorAction SilentlyContinue).ProcessName
        Write-Warn "Port $Port is already in use (PID $existingPid, $existingName)"
        Write-Host "  If this is a previous wintools-mcp instance, stop it first:"
        Write-Host "  Stop-Process -Id $existingPid"
        Write-Host ""
        if (-not (Read-YesNo "Continue anyway?" $false)) {
            Write-Info "Skipping server start. Fix the port conflict and re-run."
        }
    }
} catch { }

Write-Info "Starting wintools-mcp on port $Port..."

# Start in background to validate it works
$startArgs = @("-m", "wintools_mcp", "--http", "--host", $BindAddress, "--port", "$Port")
if (Test-Path $wintoolsConfigPath) {
    $startArgs += @("--config", $wintoolsConfigPath)
}
# Set env var before starting (PS 5.1 compatible -- -Environment requires PS 7+)
$env:AIIR_EXAMINER = $Examiner

try {
    $process = Start-Process -FilePath $venvPython -ArgumentList $startArgs -PassThru -WindowStyle Hidden

    Start-Sleep -Seconds 3

    # Check if it's running
    if (-not $process.HasExited) {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:$Port/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            Write-Ok "wintools-mcp running on port $Port"
        } catch {
            Write-Warn "wintools-mcp started but health check failed"
        }
    } else {
        Write-Warn "wintools-mcp exited immediately - check configuration"
    }
} catch {
    Write-Warn "Could not start wintools-mcp"
}

# =============================================================================
# Auto-Start Configuration
# =============================================================================

Write-Header "Phase 7: Startup Configuration"

Write-Host "wintools-mcp is running now. How should it start in the future?"
Write-Host ""
Write-Host "  1. Auto-start at boot (scheduled task)"
Write-Host "  2. Manual start (generates start-wintools.ps1)"
Write-Host ""

$startChoice = Read-Prompt "Choose" "1"

# Always generate the startup script (useful either way)
$startupPath = Join-Path $InstallDir "start-wintools.ps1"
$scriptArgs = "--http --host $BindAddress --port $Port"
if (Test-Path $wintoolsConfigPath) {
    $scriptArgs += " --config `"$wintoolsConfigPath`""
}
try {
    @"
# Start wintools-mcp in HTTP mode
# AIIR_EXAMINER is set here (not read from system env vars)
# because the scheduled task runs as SYSTEM which doesn't see User-level vars
`$env:AIIR_EXAMINER = "$Examiner"
& "$venvPython" -m wintools_mcp $scriptArgs
"@ | Set-Content -Path $startupPath -Encoding UTF8
} catch {
    Write-Warn "Could not write startup script"
}

if ($startChoice -eq "1") {
    # Register scheduled task for auto-start
    $taskName = "AIIR wintools-mcp"

    try {
        # Remove existing task if present
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existing) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Info "Removed existing scheduled task"
        }

        # Run the startup script (which sets AIIR_EXAMINER and passes --config)
        $action = New-ScheduledTaskAction `
            -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$startupPath`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -StartWhenAvailable `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1)

        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -RunLevel Highest `
            -User "SYSTEM" `
            -Description "AIIR wintools-mcp forensic tool server" | Out-Null

        Write-Ok "Scheduled task registered: $taskName"
        Write-Ok "Will auto-start at boot"
    } catch {
        Write-Warn "Could not register scheduled task (run as Administrator)"
        Write-Host "  To register manually (as Administrator):"
        Write-Host "  schtasks /create /tn `"$taskName`" /tr `"powershell.exe -ExecutionPolicy Bypass -File \`"$startupPath\`"`" /sc onstart /ru SYSTEM"
        Write-Host ""
        Write-Host "  Or use the startup script: $startupPath"
    }

    # Add firewall rule
    try {
        $ruleName = "AIIR wintools-mcp"
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existingRule) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null
            Write-Ok "Firewall rule added for TCP port $Port"
        } else {
            Write-Ok "Firewall rule already exists"
        }
    } catch {
        Write-Warn "Could not add firewall rule (run as Administrator)"
        Write-Host "  Manual: netsh advfirewall firewall add rule name=`"AIIR wintools-mcp`" dir=in action=allow protocol=TCP localport=$Port"
    }
} else {
    Write-Ok "Generated startup script: $startupPath"
    Write-Host "  Run it to start wintools-mcp: $startupPath"
}

# =============================================================================
# Summary
# =============================================================================

Write-Header "Installation Complete"

Write-Ok "wintools-mcp installed and running"
Write-Host ""
Write-Host "  Examiner:       $Examiner"
Write-Host "  Install dir:    $InstallDir"
Write-Host "  HTTP server:    http://localhost:$Port"
Write-Host "  Health check:   http://localhost:$Port/health"
Write-Host "  MCP endpoint:   http://localhost:$Port/mcp"
Write-Host "  Tool inventory: $overviewPath"

if ($wintoolsApiKey) {
    Write-Host "  API key:        $wintoolsApiKey"
}

if ($Standalone) {
    Write-Host "  Mode:           Standalone (local case directory)"
    Write-Host "  Case root:      $caseDir"
} else {
    Write-Host "  Mode:           AIIR-integrated (SMB to SIFT)"
}

Write-Host ""

if (-not $Standalone) {
    Write-Host "--- SIFT Gateway Configuration ---" -ForegroundColor White
    Write-Host ""
    if ($wintoolsApiKey) {
        Write-Host "  Add to your SIFT gateway.yaml:" -ForegroundColor White
        Write-Host "    backends:"
        Write-Host "      wintools-mcp:"
        Write-Host "        type: http"
        Write-Host "        url: `"http://${localIp}:${Port}/mcp`""
        Write-Host "        bearer_token: `"$wintoolsApiKey`""
        Write-Host "        enabled: true"
    } else {
        Write-Host "  Add to your SIFT gateway.yaml:" -ForegroundColor White
        Write-Host "    backends:"
        Write-Host "      wintools-mcp:"
        Write-Host "        type: http"
        Write-Host "        url: `"http://${localIp}:${Port}/mcp`""
        Write-Host "        enabled: true"
    }
    Write-Host ""
    Write-Host "  Once configured, clients access wintools via the gateway at:" -ForegroundColor White
    Write-Host "    http://SIFT_IP:4508/mcp/wintools-mcp" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  No direct connection to the Windows VM needed from client machines." -ForegroundColor White
    Write-Host ""
}

Write-Host "--- LLM Client Configuration ---" -ForegroundColor White
Write-Host ""
Write-Host "  On the analyst machine, run:" -ForegroundColor White
if ($Standalone) {
    Write-Host "    aiir setup client --windows=${localIp}:${Port}" -ForegroundColor Gray
} else {
    Write-Host "    aiir setup client --sift=SIFT_IP:4508 --windows=${localIp}:${Port}" -ForegroundColor Gray
}
Write-Host ""
Write-Host "  Or add to .mcp.json manually:" -ForegroundColor White
Write-Host "    {" -ForegroundColor Gray
Write-Host "      `"mcpServers`": {" -ForegroundColor Gray
Write-Host "        `"wintools-mcp`": {" -ForegroundColor Gray
Write-Host "          `"type`": `"streamable-http`"," -ForegroundColor Gray
if ($wintoolsApiKey) {
    Write-Host "          `"url`": `"http://${localIp}:${Port}/mcp`"," -ForegroundColor Gray
    Write-Host "          `"headers`": {" -ForegroundColor Gray
    Write-Host "            `"Authorization`": `"Bearer $wintoolsApiKey`"" -ForegroundColor Gray
    Write-Host "          }" -ForegroundColor Gray
} else {
    Write-Host "          `"url`": `"http://${localIp}:${Port}/mcp`"" -ForegroundColor Gray
}
Write-Host "        }" -ForegroundColor Gray
Write-Host "      }" -ForegroundColor Gray
Write-Host "    }" -ForegroundColor Gray
Write-Host ""

if ($startChoice -eq "1") {
    Write-Host "  Auto-start: enabled (scheduled task)" -ForegroundColor Green
} else {
    Write-Host "  Manual start: $startupPath" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "--- Next Steps ---" -ForegroundColor White
Write-Host ""
if ($Standalone) {
    Write-Host "  1. Install forensic tools (Zimmerman, Hayabusa, Sysinternals)" -ForegroundColor White
    Write-Host "     See: $overviewPath" -ForegroundColor Gray
    Write-Host "  2. Create a case directory:" -ForegroundColor White
    Write-Host "     mkdir $caseDir\INC-2026-0001" -ForegroundColor Gray
    Write-Host "  3. Set the active case:" -ForegroundColor White
    Write-Host "     set AIIR_CASE_DIR=$caseDir\INC-2026-0001" -ForegroundColor Gray
    Write-Host "  4. Configure your LLM client:" -ForegroundColor White
    Write-Host "     aiir setup client --windows=${localIp}:${Port}" -ForegroundColor Gray
    Write-Host "  5. Start investigating" -ForegroundColor White
} else {
    Write-Host "  1. Install forensic tools (Zimmerman, Hayabusa, Sysinternals)" -ForegroundColor White
    Write-Host "     See: $overviewPath" -ForegroundColor Gray
    Write-Host "  2. Map the SIFT case share:" -ForegroundColor White
    Write-Host "     net use Z: \\SIFT_IP\cases /persistent:yes" -ForegroundColor Gray
    Write-Host "  3. Set the active case:" -ForegroundColor White
    Write-Host "     set AIIR_CASE_DIR=Z:\INC-2026-0001" -ForegroundColor Gray
    Write-Host "  4. Configure your LLM client (on SIFT or analyst machine):" -ForegroundColor White
    Write-Host "     aiir setup client --sift=SIFT_IP:4508 --windows=${localIp}:${Port}" -ForegroundColor Gray
    Write-Host "  5. Start investigating" -ForegroundColor White
}
Write-Host ""
if ($startChoice -eq "1") {
    Write-Host "  Note: AIIR_CASE_DIR is set per case and must be updated when" -ForegroundColor Yellow
    Write-Host "  switching cases. If using auto-start (scheduled task), set it" -ForegroundColor Yellow
    Write-Host "  as a Machine-level environment variable:" -ForegroundColor Yellow
    Write-Host "    [Environment]::SetEnvironmentVariable(`"AIIR_CASE_DIR`", `"Z:\INC-2026-0001`", `"Machine`")" -ForegroundColor Gray
    Write-Host "  Or restart wintools-mcp manually after changing cases." -ForegroundColor Yellow
    Write-Host ""
}
Write-Host ""
