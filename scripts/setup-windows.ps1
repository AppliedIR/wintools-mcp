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

.PARAMETER StaticIP
    Static IP address for this Windows machine. If provided, configures the
    network adapter without prompting. Must be a private address (RFC1918).

.PARAMETER NoAuth
    Skip API key generation. The wintools-mcp server will accept
    unauthenticated requests. Use only for development on isolated networks.

.PARAMETER GatewayHost
    SIFT gateway IP or hostname (for NonInteractive mode).

.PARAMETER GatewayPort
    SIFT gateway port. Default: 4508.

.PARAMETER JoinCode
    One-time join code from 'aiir setup join-code' on SIFT workstation.
    Enables automated credential exchange instead of manual copy-paste.

.PARAMETER Uninstall
    Remove wintools-mcp: scheduled task, firewall rule, environment variables,
    and optionally the install directory. Prompts for confirmation on each
    component. After uninstalling on Windows, also run
    'aiir setup client --uninstall' on the SIFT workstation.

.PARAMETER Update
    Update wintools-mcp: git pull, pip reinstall, restart scheduled task.
    Fails cleanly on dirty working tree or merge conflicts instead of
    silently proceeding with stale code.

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
    # Non-interactive with automated join
    .\setup-windows.ps1 -NonInteractive -AcknowledgeSecurityHole `
        -GatewayHost 10.0.0.1 -JoinCode "ABCD-EFGH" -Examiner "analyst1"

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
    [string]$StaticIP = "",
    [switch]$NoAuth,
    [string]$GatewayHost = "",
    [int]$GatewayPort = 4508,
    [string]$JoinCode = "",
    [switch]$Uninstall,
    [switch]$Update
)

$ErrorActionPreference = "Stop"

$process = $null
$skipServerStart = $false
$serverHealthy = $false
$joinSucceeded = $false

trap {
    if ($process -and -not $process.HasExited) {
        try { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } catch { }
    }
    Write-Host ""
    Write-Err "Installation failed. Check output above for details."
    Write-Host "  Install directory may contain partial state: $InstallDir" -ForegroundColor Yellow
    Write-Host "  To retry: re-run setup-windows.ps1" -ForegroundColor White
    Write-Host "  To clean up: Remove-Item -Recurse -Force '$InstallDir'" -ForegroundColor White
    Write-Host ""
    break
}

# =============================================================================
# Helpers
# =============================================================================

function Write-Info   { param($msg) Write-Host "[INFO] " -ForegroundColor Blue -NoNewline; Write-Host $msg }
function Write-Ok     { param($msg) Write-Host "[OK] " -ForegroundColor Green -NoNewline; Write-Host $msg }
function Write-Warn   { param($msg) Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline; Write-Host $msg }
function Write-Err    { param($msg) Write-Host "[ERROR] " -ForegroundColor Red -NoNewline; Write-Host $msg }
function Write-Header { param($msg) Write-Host "`n=== $msg ===`n" -ForegroundColor White }

function Mask-ApiKey {
    param([string]$Key)
    if ($Key.Length -le 12) { return "****" }
    return $Key.Substring(0, 8) + ("*" * ($Key.Length - 12)) + $Key.Substring($Key.Length - 4)
}

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

function Derive-SMBPassword {
    param([Parameter(Mandatory)][string]$JoinCode)

    $enc = [System.Text.Encoding]::UTF8
    $deriv = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        $enc.GetBytes($JoinCode),
        $enc.GetBytes("aiir-smb-v1"),
        600000,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $dk = $deriv.GetBytes(32)
    $deriv.Dispose()
    return [BitConverter]::ToString($dk).Replace("-", "").ToLower().Substring(0, 32)
}

function Set-StaticIP {
    param([string]$IP)

    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    if (-not $adapter) {
        Write-Err "No active network adapter found"
        return $null
    }
    $idx = $adapter.InterfaceIndex
    $currentIP = (Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Select-Object -First 1)

    if (-not $IP) {
        if ($currentIP) { $defaultIP = $currentIP.IPAddress } else { $defaultIP = "" }
        $IP = Read-Host "Enter static IP for this machine [$defaultIP]"
        if (-not $IP) { $IP = $defaultIP }
    }

    # Validate RFC1918
    if ($IP -notmatch '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)') {
        Write-Err "IP must be a private address (10.x, 172.16-31.x, 192.168.x)"
        return $null
    }

    if ($currentIP) { $prefix = $currentIP.PrefixLength } else { $prefix = 24 }
    $gw = (Get-NetRoute -InterfaceIndex $idx -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
           Select-Object -First 1).NextHop
    $dns = (Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses

    try {
        Remove-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -Confirm:$false -ErrorAction Stop
        New-NetIPAddress -InterfaceIndex $idx -IPAddress $IP -PrefixLength $prefix -DefaultGateway $gw -ErrorAction Stop
        if ($dns) { Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $dns }
    } catch {
        Write-Err "Failed to set static IP (requires Administrator): $_"
        Write-Host "  Run this installer as Administrator, or set the IP manually:" -ForegroundColor Yellow
        Write-Host "  netsh interface ipv4 set address `"$($adapter.InterfaceAlias)`" static $IP $prefix $gw" -ForegroundColor Gray
        return $null
    }

    # Write network.yaml
    $aiirDir = Join-Path $env:USERPROFILE ".aiir"
    if (-not (Test-Path $aiirDir)) {
        New-Item -ItemType Directory -Path $aiirDir -Force | Out-Null
    }
    @"
static_ip: $IP
interface: $($adapter.InterfaceAlias)
configured_at: $([DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"))
"@ | Set-Content -Path (Join-Path $aiirDir "network.yaml") -Encoding UTF8

    Write-Ok "Static IP set to $IP"
    return $IP
}

function Validate-Port {
    param([int]$PortNumber, [string]$Label = "Port")
    if ($PortNumber -lt 1 -or $PortNumber -gt 65535) {
        Write-Err "$Label must be between 1 and 65535 (got: $PortNumber)"
        exit 1
    }
}

Validate-Port $Port "Port"
if ($GatewayPort) { Validate-Port $GatewayPort "GatewayPort" }

# =============================================================================
# Uninstall
# =============================================================================

if ($Uninstall) {
    Write-Header "wintools-mcp Uninstall"

    # Resolve install dir from env or default
    if (-not $InstallDir) {
        if (Test-Path "C:\Tools\aiir") { $InstallDir = "C:\Tools\aiir" }
        elseif (Test-Path "$env:USERPROFILE\aiir") { $InstallDir = "$env:USERPROFILE\aiir" }
        else {
            Write-Warn "Could not find wintools-mcp installation directory"
            Write-Host "  Specify with: .\setup-windows.ps1 -Uninstall -InstallDir <path>"
            exit 1
        }
    }
    Write-Info "Install directory: $InstallDir"

    # 1. Remove scheduled task
    $taskName = "AIIR wintools-mcp"
    try {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            if (Read-YesNo "Remove scheduled task '$taskName'?" $true) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                Write-Ok "Scheduled task removed"
            }
        } else {
            Write-Info "No scheduled task found"
        }
    } catch {
        Write-Warn "Could not check/remove scheduled task: $_"
    }

    # 2. Remove firewall rule
    $ruleName = "AIIR wintools-mcp"
    try {
        $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($rule) {
            if (Read-YesNo "Remove firewall rule '$ruleName'?" $true) {
                Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop
                Write-Ok "Firewall rule removed"
            }
        } else {
            Write-Info "No firewall rule found"
        }
    } catch {
        Write-Warn "Could not remove firewall rule: $_"
    }

    # 3. Remove environment variables
    foreach ($varName in @("AIIR_EXAMINER", "AIIR_CASE_DIR", "AIIR_ACTIVE_CASE", "AIIR_SHARE_ROOT", "AIIR_AUDIT_DIR", "WINTOOLS_CASE_ROOT")) {
        $userVal = [Environment]::GetEnvironmentVariable($varName, "User")
        $machVal = [Environment]::GetEnvironmentVariable($varName, "Machine")
        if ($userVal -or $machVal) {
            if (Read-YesNo "Remove environment variable $varName?" $true) {
                if ($userVal) { [Environment]::SetEnvironmentVariable($varName, $null, "User") }
                if ($machVal) {
                    try { [Environment]::SetEnvironmentVariable($varName, $null, "Machine") }
                    catch { Write-Warn "Could not remove Machine-level $varName (run as Administrator)" }
                }
                Write-Ok "Removed $varName"
            }
        }
    }

    # 4. Remove install directory (venv, source, config)
    if (Test-Path $InstallDir) {
        $dirSize = "{0:N1} MB" -f ((Get-ChildItem -Recurse -File $InstallDir -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB)
        if (Read-YesNo "Remove install directory $InstallDir ($dirSize)?" $false) {
            try {
                Remove-Item -Recurse -Force $InstallDir
                Write-Ok "Install directory removed"
            } catch {
                Write-Warn "Could not remove install directory: $_"
            }
        } else {
            Write-Info "Install directory preserved at $InstallDir"
        }
    }

    Write-Host ""
    Write-Ok "Uninstall complete"
    Write-Host "  Note: On the SIFT workstation, also run:" -ForegroundColor Yellow
    Write-Host "    aiir setup client --uninstall    (removes MCP config entries)" -ForegroundColor Gray
    exit 0
}

# =============================================================================
# Update
# =============================================================================

if ($Update) {
    Write-Header "wintools-mcp Update"

    # Resolve install dir
    if (-not $InstallDir) {
        if (Test-Path "C:\Tools\aiir") { $InstallDir = "C:\Tools\aiir" }
        elseif (Test-Path "$env:USERPROFILE\aiir") { $InstallDir = "$env:USERPROFILE\aiir" }
        else {
            Write-Err "Could not find wintools-mcp installation directory"
            exit 1
        }
    }

    $wintoolsDir = Join-Path $InstallDir "wintools-mcp"
    # Install creates .venv inside $wintoolsDir, not $InstallDir/venv
    $venvDir = Join-Path $wintoolsDir ".venv"
    $venvPython = Join-Path $venvDir "Scripts\python.exe"

    if (-not (Test-Path $wintoolsDir)) {
        Write-Err "wintools-mcp source not found at $wintoolsDir"
        exit 1
    }
    if (-not (Test-Path $venvPython)) {
        Write-Err "Python venv not found at $venvDir"
        exit 1
    }

    # 1. Git pull
    Write-Info "Pulling latest changes..."
    Push-Location $wintoolsDir
    try {
        # Check for dirty working tree
        $status = git status --porcelain 2>&1
        if ($status) {
            Write-Warn "Working tree has uncommitted changes:"
            $status | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
            if (-not (Read-YesNo "Continue anyway? (changes may cause merge conflicts)" $false)) {
                Pop-Location
                exit 1
            }
        }

        # Check current branch
        $branch = git rev-parse --abbrev-ref HEAD 2>&1
        Write-Info "Current branch: $branch"

        # Fetch and show what's available
        git fetch origin 2>&1 | Out-Null
        $behind = git rev-list "HEAD..origin/$branch" --count 2>&1
        if ($behind -eq "0") {
            Write-Ok "Already up to date"
        } else {
            Write-Info "$behind commit(s) behind origin/$branch"
            git pull --ff-only 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Err "git pull failed (merge conflict or non-fast-forward). Resolve manually."
                Pop-Location
                exit 1
            }
            Write-Ok "Source updated"
        }
    } catch {
        Write-Err "Git update failed: $_"
        Pop-Location
        exit 1
    }
    Pop-Location

    # 2. Reinstall package
    Write-Info "Reinstalling wintools-mcp..."
    try {
        & $venvPython -m pip install --progress-bar off -e $wintoolsDir 2>&1 | Out-Null
        Write-Ok "Package reinstalled"
    } catch {
        Write-Err "pip install failed: $_"
        exit 1
    }

    # 3. Reinstall FK if present (local copy or from sift-mcp repo)
    $fkDir = Join-Path $InstallDir "forensic-knowledge"
    $githubOrg = "https://github.com/AppliedIR"
    if (Test-Path $fkDir) {
        try {
            & $venvPython -m pip install --progress-bar off -e $fkDir 2>&1 | Out-Null
            Write-Ok "forensic-knowledge reinstalled (local)"
        } catch {
            Write-Warn "FK reinstall failed (non-fatal)"
        }
    } else {
        try {
            & $venvPython -m pip install --progress-bar off --upgrade `
                "forensic-knowledge @ git+${githubOrg}/sift-mcp.git#subdirectory=packages/forensic-knowledge" 2>&1 | Out-Null
            Write-Ok "forensic-knowledge updated (from sift-mcp repo)"
        } catch {
            Write-Warn "FK update failed (non-fatal)"
        }
    }

    # 4. Restart scheduled task
    $taskName = "AIIR wintools-mcp"
    try {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-ScheduledTask -TaskName $taskName
            Write-Ok "Scheduled task restarted"
        } else {
            Write-Info "No scheduled task found -- restart manually if needed"
        }
    } catch {
        Write-Warn "Could not restart scheduled task: $_"
    }

    # 5. Version check
    try {
        $ver = & $venvPython -c "from wintools_mcp import __version__; print(__version__)" 2>&1
        Write-Ok "wintools-mcp $ver"
    } catch { }

    Write-Host ""
    Write-Ok "Update complete"
    exit 0
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

# Python 3.10+
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py -3")) {
    try {
        $ver = & ($cmd.Split(" ")[0]) @($cmd.Split(" ") | Select-Object -Skip 1) -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>&1
        if ($ver) {
            $parts = $ver.Split(".")
            $major = [int]$parts[0]
            $minor = [int]$parts[1]
            if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 10)) {
                $pythonCmd = $cmd
                Write-Ok "Python $ver"
                break
            }
        }
    } catch { }
}

if (-not $pythonCmd) {
    Write-Err "Python 3.10+ not found"
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
        # Check for runtime (works without SDK installed)
        $runtimes = (dotnet --list-runtimes 2>&1)
        if ($LASTEXITCODE -eq 0 -and $runtimes) {
            # Extract highest version from runtime list
            $versions = ($runtimes | Select-String 'Microsoft\.NETCore\.App (\d+\.\d+)' -AllMatches).Matches | ForEach-Object { $_.Groups[1].Value }
            if ($versions) {
                $highest = ($versions | Sort-Object { [version]$_ } -Descending | Select-Object -First 1)
                Write-Ok ".NET Runtime $highest"
                $hasDotnet = $true
            }
        }
        # Fallback: SDK version (dotnet --version works only when SDK is installed)
        if (-not $hasDotnet) {
            $dotnetVer = (dotnet --version 2>&1)
            if ($LASTEXITCODE -eq 0 -and $dotnetVer) {
                Write-Ok ".NET SDK $dotnetVer"
                $hasDotnet = $true
            }
        }
    }
} catch { }
if (-not $hasDotnet) {
    Write-Warn ".NET Runtime not found (needed for Zimmerman tools)"
    Write-Host "  Install from: https://dotnet.microsoft.com/download"
    Write-Host "  Or via winget: winget install Microsoft.DotNet.Runtime.9"
}

# .NET Framework 4.7.2+ (required for PBKDF2-SHA256 credential derivation)
try {
    $null = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    $test = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
        [byte[]]@(1), [byte[]]@(1,2,3,4,5,6,7,8), 1,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $test.Dispose()
    Write-Ok ".NET Framework supports PBKDF2-SHA256"
} catch {
    Write-Err "PBKDF2-SHA256 not available. Requires .NET Framework 4.7.2+ (Windows 10 1803+)"
    Write-Host "  Check your Windows version: winver" -ForegroundColor Yellow
    exit 1
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
    $InstallDir = Read-Prompt "Specify installation directory" $defaultDir
}

Write-Info "Installing to $InstallDir"

if (-not (Test-Path $InstallDir)) {
    try {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    } catch {
        Write-Err "Cannot create directory: $InstallDir"
        exit 1
    }
}

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
            try {
                $pullOutput = git pull --quiet 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Write-Warn "git pull failed (exit $LASTEXITCODE). Using existing code."
                } else {
                    $cloneOk = $true
                }
            } catch {
                Write-Warn "Could not update (network issue?). Using existing code."
            } finally {
                Pop-Location
            }
            # Even if pull failed, existing dir may have usable code
            if (-not $cloneOk -and (Test-Path (Join-Path $wintoolsDir "pyproject.toml"))) {
                Write-Info "Existing source appears usable, continuing with current version"
                $cloneOk = $true
            }
        } else {
            git clone --quiet "$githubOrg/wintools-mcp.git" $wintoolsDir 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "git clone exit code $LASTEXITCODE" }
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

# forensic-knowledge (FK) enrichment — optional
# FK lives inside the sift-mcp monorepo at packages/forensic-knowledge/.
# pip can install it directly from that subdirectory via git+subdirectory syntax.
# Without FK, tool execution still works but responses lack caveats, advisories,
# and corroboration hints.
$fkDir = Join-Path $InstallDir "forensic-knowledge"
$fkInstalled = $false

# Check if already installed in this venv
try {
    $fkTest = & $venvPython -c "import forensic_knowledge; print('ok')" 2>&1
    if ($fkTest -eq "ok") {
        $fkInstalled = $true
    }
} catch { }

# If not installed, try pip install from sift-mcp repo subdirectory
if (-not $fkInstalled) {
    # First check if a local copy exists (from a previous install or manual placement)
    if (Test-Path $fkDir) {
        try {
            & $venvPython -m pip install --progress-bar off -e $fkDir 2>&1 | Out-Null
            $fkTest = & $venvPython -c "import forensic_knowledge; print('ok')" 2>&1
            if ($fkTest -eq "ok") { $fkInstalled = $true }
        } catch { }
    }
    # Otherwise install from sift-mcp GitHub repo subdirectory
    if (-not $fkInstalled -and $networkOk) {
        Write-Info "Installing forensic-knowledge from sift-mcp repository..."
        if ($hasGit) {
            # With git: pip can install directly from the repo subdirectory
            try {
                & $venvPython -m pip install --progress-bar off `
                    "forensic-knowledge @ git+${githubOrg}/sift-mcp.git#subdirectory=packages/forensic-knowledge" 2>&1 | Out-Null
                $fkTest = & $venvPython -c "import forensic_knowledge; print('ok')" 2>&1
                if ($fkTest -eq "ok") { $fkInstalled = $true }
            } catch {
                Write-Warn "Could not install forensic-knowledge: $_"
            }
        } else {
            # Without git: download sift-mcp ZIP, extract FK subdirectory, pip install
            try {
                $siftZipUrl = "$githubOrg/sift-mcp/archive/refs/heads/main.zip"
                $siftZipPath = Join-Path $InstallDir "sift-mcp-fk.zip"
                $siftExtractDir = Join-Path $InstallDir "sift-mcp-main"
                Invoke-WebRequest -Uri $siftZipUrl -OutFile $siftZipPath -UseBasicParsing
                Expand-Archive -Path $siftZipPath -DestinationPath $InstallDir -Force
                $fkSourceDir = Join-Path (Join-Path $siftExtractDir "packages") "forensic-knowledge"
                if (Test-Path $fkSourceDir) {
                    # Copy FK to persistent location so it survives cleanup
                    if (Test-Path $fkDir) { Remove-Item $fkDir -Recurse -Force }
                    Copy-Item $fkSourceDir $fkDir -Recurse
                    & $venvPython -m pip install --progress-bar off -e $fkDir 2>&1 | Out-Null
                    $fkTest = & $venvPython -c "import forensic_knowledge; print('ok')" 2>&1
                    if ($fkTest -eq "ok") { $fkInstalled = $true }
                } else {
                    Write-Warn "FK subdirectory not found in sift-mcp archive"
                }
                # Cleanup temporary files
                Remove-Item $siftZipPath -ErrorAction SilentlyContinue
                Remove-Item $siftExtractDir -Recurse -Force -ErrorAction SilentlyContinue
            } catch {
                Write-Warn "Could not install forensic-knowledge: $_"
                Remove-Item (Join-Path $InstallDir "sift-mcp-fk.zip") -ErrorAction SilentlyContinue
                Remove-Item (Join-Path $InstallDir "sift-mcp-main") -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

if ($fkInstalled) {
    Write-Ok "forensic-knowledge installed (FK enrichment enabled)"
} else {
    Write-Info "forensic-knowledge not available (FK enrichment disabled)"
    Write-Host "  Tool execution works without FK. Responses will lack caveats," -ForegroundColor White
    Write-Host "  advisories, and corroboration hints." -ForegroundColor White
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

$extraToolPaths = @()
if ($scanOutput) {
    Write-Host $($scanOutput -join "`n")

    # Check for missing tools and prompt for additional directories
    $missingLine = $scanOutput | Where-Object { $_ -match "(\d+) missing" }
    if ($missingLine -and -not $NonInteractive) {
        $missingCount = if ($missingLine -match "(\d+) missing") { [int]$Matches[1] } else { 0 }
        if ($missingCount -gt 0) {
            Write-Host ""
            Write-Host "  $missingCount tool(s) not found in default search paths." -ForegroundColor Yellow
            Write-Host "  If your tools are in non-standard locations (e.g., D:\Forensics, E:\Tools),"
            Write-Host "  enter those directories now so wintools-mcp can find them at runtime."
            Write-Host ""
            $extraInput = Read-Host "  Additional tool directories (comma-separated, or Enter to skip)"
            if ($extraInput) {
                $extraToolPaths = $extraInput -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
                $validPaths = @()
                foreach ($p in $extraToolPaths) {
                    if (Test-Path $p -PathType Container) {
                        $validPaths += $p
                        Write-Ok "  Added: $p"
                    } else {
                        Write-Warn "  Not found, skipping: $p"
                    }
                }
                $extraToolPaths = $validPaths

                # Re-scan with extra paths via env var
                if ($extraToolPaths.Count -gt 0) {
                    Write-Host ""
                    Write-Info "Re-scanning with additional paths..."
                    $env:WINTOOLS_TOOL_PATHS = $extraToolPaths -join [IO.Path]::PathSeparator
                    try { $scanOutput = & $venvPython -m wintools_mcp --scan 2>&1 } catch { }
                    if ($scanOutput) { Write-Host $($scanOutput -join "`n") }
                    $env:WINTOOLS_TOOL_PATHS = $null
                }
            }
        }
    }
} else {
    Write-Warn "Tool scan could not run"
}

# Generate TOOLS_OVERVIEW.md
Write-Host ""
Write-Info "Generating tool inventory report..."

$overviewPath = Join-Path $InstallDir "TOOLS_OVERVIEW.md"
# Write Python script to temp file to avoid PS here-string quoting issues with
# nested double-quotes in f-strings (PS 5.1 mangles them when passed via -c)
$overviewScript = Join-Path $env:TEMP "aiir_overview.py"
try {
@'
import sys
from datetime import datetime
from wintools_mcp.catalog import load_catalog
from wintools_mcp.environment import find_tool

catalog = load_catalog()
found = []
missing = []
for name, td in sorted(catalog.items()):
    path = find_tool(td.binary)
    if path:
        found.append((td.name, td.category, td.binary, path))
    else:
        missing.append((td.name, td.category, td.description or ""))

lines = []
lines.append(f"# AIIR Tool Inventory - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
lines.append("")
lines.append(f"Generated by setup-windows.ps1 on {datetime.now().strftime('%Y-%m-%d')}.")
lines.append("wintools-mcp rescans automatically on each discovery call.")
lines.append("")
lines.append(f"## Installed ({len(found)}/{len(found)+len(missing)})")
lines.append("")
if found:
    lines.append("| Tool | Category | Path |")
    lines.append("|------|----------|------|")
    for name, cat, binary, path in found:
        lines.append(f"| {name} | {cat} | {path} |")
else:
    lines.append("No tools found.")
lines.append("")
lines.append(f"## Missing ({len(missing)}/{len(found)+len(missing)})")
lines.append("")
if missing:
    lines.append("| Tool | Category | Description |")
    lines.append("|------|----------|-------------|")
    for name, cat, desc in missing:
        lines.append(f"| {name} | {cat} | {desc} |")
else:
    lines.append("All catalog tools are installed.")
lines.append("")
lines.append("## Notes")
lines.append("")
lines.append("- Install missing tools and restart wintools-mcp (or call scan_tools via MCP)")
lines.append("- wintools-mcp checks tool availability dynamically on each discovery call")
lines.append("- Common tool sources:")
lines.append("  - Zimmerman Suite: https://ericzimmerman.github.io/")
lines.append("  - Hayabusa: https://github.com/Yamato-Security/hayabusa/releases")
lines.append("  - Sysinternals: winget install Microsoft.Sysinternals")
lines.append("")
print("\n".join(lines))
'@ | Set-Content -Path $overviewScript -Encoding UTF8
    $overviewContent = & $venvPython $overviewScript 2>&1
} catch {
    Write-Warn "TOOLS_OVERVIEW.md generation error: $_"
    $overviewContent = $null
} finally {
    Remove-Item $overviewScript -ErrorAction SilentlyContinue
}

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

# Build tool_paths YAML snippet for config.yaml (empty string if no extra paths)
$toolPathsYaml = ""
if ($extraToolPaths.Count -gt 0) {
    $toolPathsYaml = "`ntool_paths:"
    foreach ($p in $extraToolPaths) {
        $escaped = $p.Replace("\", "\\")
        $toolPathsYaml += "`n  - `"$escaped`""
    }
    $toolPathsYaml += "`n"
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
    $caseDir = Read-Prompt "Specify local case directory" $defaultCaseDir

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
    Write-Host "    $caseDir\INC-2026-0001\audit\" -ForegroundColor White
    Write-Host ""
    Write-Host "  Set AIIR_CASE_DIR before starting a case:" -ForegroundColor White
    Write-Host "    set AIIR_CASE_DIR=$caseDir\INC-2026-0001" -ForegroundColor White
    Write-Host ""
    Write-Host "  Place evidence working copies in the case directory." -ForegroundColor White
    Write-Host "  Tool output and audit entries are written to the audit subdirectory." -ForegroundColor White
    Write-Host ""

    # Save standalone config (Machine level so SYSTEM scheduled task can see it)
    try {
        [Environment]::SetEnvironmentVariable("AIIR_CASE_DIR", $caseDir, "Machine")
        [Environment]::SetEnvironmentVariable("WINTOOLS_CASE_ROOT", $caseDir, "Machine")
        $env:AIIR_CASE_DIR = $caseDir
        $env:WINTOOLS_CASE_ROOT = $caseDir
        Write-Ok "Set AIIR_CASE_DIR=$caseDir (machine-level)"
    } catch {
        # Fall back to User level if not running as admin
        try {
            [Environment]::SetEnvironmentVariable("AIIR_CASE_DIR", $caseDir, "User")
            [Environment]::SetEnvironmentVariable("WINTOOLS_CASE_ROOT", $caseDir, "User")
            Write-Warn "Set AIIR_CASE_DIR at User level (run as Administrator for Machine level)"
        } catch {
            Write-Warn "Could not set AIIR_CASE_DIR environment variable"
        }
        $env:AIIR_CASE_DIR = $caseDir
        $env:WINTOOLS_CASE_ROOT = $caseDir
    }

    # Generate API key for standalone mode too
    try {
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = New-Object byte[] 12
        $rng.GetBytes($bytes)
        $wintoolsApiKey = "aiir_wt_" + [BitConverter]::ToString($bytes).Replace("-", "").ToLower()
        $rng.Dispose()
        Write-Ok "Generated API key: $(Mask-ApiKey $wintoolsApiKey)"
    } catch {
        Write-Warn "Could not generate API key. Standalone will run without auth."
    }

    # Write standalone config.yaml
    if (-not (Test-Path $wintoolsConfigPath)) {
        try {
            if ($wintoolsApiKey) {
                @"
# wintools-mcp configuration (generated by setup-windows.ps1)
http_host: "$BindAddress"
http_port: $Port

api_keys:
  ${wintoolsApiKey}:
    examiner: "$Examiner"
    role: "examiner"
$toolPathsYaml
"@ | Set-Content -Path $wintoolsConfigPath -Encoding UTF8
            } else {
                @"
# wintools-mcp configuration (generated by setup-windows.ps1)
http_host: "$BindAddress"
http_port: $Port
$toolPathsYaml
"@ | Set-Content -Path $wintoolsConfigPath -Encoding UTF8
            }
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

    # Determine gateway coordinates
    $gatewayScheme = "http"
    $siftIp = ""
    $siftPort = ""
    $joinCodeValue = ""
    $gatewayReachable = $false

    if ($NonInteractive) {
        $siftIp = $GatewayHost
        $siftPort = "$GatewayPort"
        $joinCodeValue = $JoinCode
    } else {
        $siftIp = Read-Prompt "SIFT workstation IP or hostname (blank to skip)" ""
        if ($siftIp) {
            # Resolve hostname to IP for firewall rules
            if ($siftIp -and $siftIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
                try {
                    $resolved = [System.Net.Dns]::GetHostAddresses($siftIp) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
                    if ($resolved) {
                        Write-Ok "Resolved '$siftIp' to $($resolved.IPAddressToString)"
                        $siftIp = $resolved.IPAddressToString
                    } else {
                        Write-Warn "Could not resolve '$siftIp' to an IPv4 address"
                        $siftIp = Read-Prompt "Enter the SIFT workstation IP address directly" ""
                    }
                } catch {
                    Write-Warn "DNS resolution failed for '$siftIp': $_"
                    $siftIp = Read-Prompt "Enter the SIFT workstation IP address directly" ""
                }
            }
            $siftPort = Read-Prompt "SIFT gateway port" "4508"
        }
    }

    # Prompt for join code BEFORE connectivity check
    # The user needs to run 'aiir setup join-code' on SIFT first,
    # which should configure the gateway for remote access.
    if ($siftIp -and -not $NonInteractive -and -not $joinCodeValue) {
        Write-Host ""
        Write-Host "  On the SIFT workstation, run:" -ForegroundColor White
        Write-Host ""
        Write-Host "    aiir setup join-code" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  This prepares the gateway for remote connections" -ForegroundColor Gray
        Write-Host "  and displays a one-time join code." -ForegroundColor Gray
        Write-Host ""
        $joinCodeValue = Read-Prompt "Enter the join code (blank to skip)" ""
    }

    # Reachability check with diagnostics and retry
    if ($siftIp) {
        $retryGateway = $true
        while ($retryGateway) {
            $retryGateway = $false
            $gatewayReachable = $false

            # Step 1: Ping (network layer)
            Write-Info "Testing network connectivity to $siftIp..."
            $pingOk = Test-Connection -ComputerName $siftIp -Count 1 -Quiet -ErrorAction SilentlyContinue
            if ($pingOk) {
                Write-Ok "Ping to $siftIp succeeded"
            } else {
                Write-Warn "Ping to $siftIp failed"
                Write-Host "  Check:" -ForegroundColor Yellow
                Write-Host "    - Both VMs are on the same network segment" -ForegroundColor White
                Write-Host "    - The SIFT workstation is powered on" -ForegroundColor White
                Write-Host "    - No firewall is blocking ICMP between the two machines" -ForegroundColor White
                if (-not $NonInteractive) {
                    Write-Host ""
                    $retry = Read-Prompt "Fix the issue and press Enter to retry (or 'skip' to continue without gateway)" ""
                    if ($retry -ne "skip") { $retryGateway = $true; continue }
                }
                break
            }

            # Step 2: TCP port check (gateway binding)
            Write-Info "Testing TCP port ${siftPort}..."
            $tcpOk = $false
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $tcp.Connect($siftIp, [int]$siftPort)
                $tcpOk = $true
                $tcp.Close()
            } catch { }

            if (-not $tcpOk) {
                Write-Warn "TCP port $siftPort on $siftIp is not reachable"
                Write-Host ""
                Write-Host "  The gateway may still be bound to localhost." -ForegroundColor White
                Write-Host "  On the SIFT workstation, run:" -ForegroundColor White
                Write-Host ""
                Write-Host "    sed -i 's/host: 127.0.0.1/host: 0.0.0.0/' ~/.aiir/gateway.yaml" -ForegroundColor Cyan
                Write-Host "    systemctl --user restart aiir-gateway" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  Other possibilities:" -ForegroundColor Gray
                Write-Host "    - Gateway not running (aiir service status)" -ForegroundColor Gray
                Write-Host "    - Firewall blocking port $siftPort" -ForegroundColor Gray
                if (-not $NonInteractive) {
                    Write-Host ""
                    $retry = Read-Prompt "Press Enter to retry, or 'skip' to continue without gateway" ""
                    if ($retry -ne "skip") { $retryGateway = $true; continue }
                }
                break
            }

            Write-Ok "TCP port $siftPort is open"

            # Step 3: HTTP health check
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
                Write-Warn "Port is open but HTTP health check failed"
                Write-Host "  The port is accepting connections but not responding to HTTP." -ForegroundColor Yellow
                Write-Host "  Check that the AIIR gateway (not another service) is on port $siftPort." -ForegroundColor White
                if (-not $NonInteractive) {
                    Write-Host ""
                    $retry = Read-Prompt "Press Enter to retry, or 'skip' to continue without gateway" ""
                    if ($retry -ne "skip") { $retryGateway = $true; continue }
                }
            }
        }
    }

    # Join API call
    if ($joinCodeValue -and $gatewayReachable) {
        # Generate API key first (needed for request body)
        try {
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $bytes = New-Object byte[] 12
            $rng.GetBytes($bytes)
            $wintoolsApiKey = "aiir_wt_" + [BitConverter]::ToString($bytes).Replace("-", "").ToLower()
            $rng.Dispose()
        } catch {
            Write-Warn "Could not generate API key for join"
        }

        if ($wintoolsApiKey) {
            $joinBody = @{
                code = $joinCodeValue
                machine_type = "wintools"
                hostname = $env:COMPUTERNAME
                wintools_url = "http://${localIp}:${Port}/mcp"
                wintools_token = $wintoolsApiKey
            } | ConvertTo-Json

            try {
                $joinResponse = Invoke-WebRequest `
                    -Uri "${gatewayScheme}://${siftIp}:${siftPort}/api/v1/setup/join" `
                    -Method POST `
                    -ContentType "application/json" `
                    -Body $joinBody `
                    -TimeoutSec 10 `
                    -UseBasicParsing `
                    -ErrorAction Stop
                $joinData = $joinResponse.Content | ConvertFrom-Json
                $joinSucceeded = $true
                Write-Ok "Registered with SIFT gateway via join API"
                if ($joinData.gateway_token) {
                    Write-Ok "Gateway token received: $(Mask-ApiKey $joinData.gateway_token)"
                }
                if ($joinData.restart_required) {
                    Write-Info "Gateway restart required. Run 'aiir service restart' on SIFT."
                }
            } catch {
                $statusCode = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                if ($statusCode -eq 403) {
                    # Server rejected the request — key was NOT stored. Safe to clear.
                    $wintoolsApiKey = ""
                    Write-Warn "Join failed: invalid, expired, or already-used join code"
                } elseif ($statusCode -eq 429) {
                    $wintoolsApiKey = ""
                    Write-Warn "Join failed: too many attempts. Try again later."
                } else {
                    # Timeout or network error — server MAY have stored the key.
                    # Keep the generated key so config.yaml matches what was sent.
                    Write-Warn "Join failed: $_"
                    Write-Warn "The API key sent to the gateway may or may not have been stored."
                    Write-Host "  The same key will be written to config.yaml." -ForegroundColor Yellow
                    Write-Host "  If the gateway did not receive it, re-register manually." -ForegroundColor Yellow
                }
                Write-Host "  Falling back to manual configuration"
            }
        }
    }

    # Drive mapping — only if join succeeded and SMB fields present
    if ($joinSucceeded -and $joinData.smb_share) {
        $derivedPw = Derive-SMBPassword -JoinCode $joinCodeValue
        $smbHost = $joinData.smb_host
        $smbShare = $joinData.smb_share
        $smbUser = $joinData.smb_user
        $uncPath = "\\$smbHost\$smbShare"

        # Find available drive letter (S: preferred, fall back to T:-Z:)
        $driveLetter = $null
        foreach ($letter in @("S","T","U","V","W","X","Y","Z")) {
            if (-not (Test-Path "${letter}:\")) {
                $driveLetter = $letter
                break
            }
        }
        if (-not $driveLetter) {
            Write-Warn "No available drive letter (S-Z). Map the share manually:"
            Write-Host "  net use <LETTER>: $uncPath /user:$smbUser <password> /persistent:yes"
        } else {
            try {
                # net use is more reliable than New-PSDrive -Persist on PS 5.1
                $netResult = net use "${driveLetter}:" $uncPath /user:$smbUser $derivedPw /persistent:yes 2>&1
                if ($LASTEXITCODE -ne 0) { throw $netResult }

                # Store SMB credentials in config.yaml (read by HTTP server at startup)
                if (Test-Path $wintoolsConfigPath) {
                    $configContent = Get-Content $wintoolsConfigPath -Raw
                    if ($configContent -notmatch "smb_user:") {
                        Add-Content -Path $wintoolsConfigPath -Value "`nsmb_user: $smbUser"
                        Add-Content -Path $wintoolsConfigPath -Value "smb_password: $derivedPw"
                    }
                }

                Write-Ok "Mapped ${driveLetter}: to $uncPath"

                # Write share_root to existing config.yaml
                # $wintoolsConfigPath is defined at line 639 of the original script
                # Use unquoted YAML — backslash only special in double-quoted YAML strings
                if (Test-Path $wintoolsConfigPath) {
                    $configContent = Get-Content $wintoolsConfigPath -Raw
                    if ($configContent -notmatch "share_root:") {
                        Add-Content -Path $wintoolsConfigPath -Value "`nshare_root: $uncPath"
                    }
                }
            } catch {
                Write-Warn "Drive mapping failed: $_"
                Write-Host "  Map manually: net use ${driveLetter}: $uncPath /user:$smbUser <password> /persistent:yes"
            }
        }
    }

    $derivedPw = $null

    # Token generation (gated on join result)
    if (-not $joinSucceeded) {
        if ($NoAuth) {
            Write-Warn "No API key configured -- wintools-mcp is unprotected"
            Write-Host "  Use --NoAuth only for development on isolated networks"
        } elseif (-not $wintoolsApiKey) {
            try {
                $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                $bytes = New-Object byte[] 12
                $rng.GetBytes($bytes)
                $wintoolsApiKey = "aiir_wt_" + [BitConverter]::ToString($bytes).Replace("-", "").ToLower()
                $rng.Dispose()
                Write-Ok "Generated API key: $(Mask-ApiKey $wintoolsApiKey)"
            } catch {
                Write-Warn "Could not generate API key"
            }
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
$toolPathsYaml
"@ | Set-Content -Path $wintoolsConfigPath -Encoding UTF8
        Write-Ok "Wrote config with API key: $wintoolsConfigPath"

        if (-not $joinSucceeded) {
            Write-Host ""
            Write-Host "  Add this snippet to your SIFT workstation's gateway.yaml" -ForegroundColor White
            Write-Host "  File: ~/.aiir/gateway.yaml (under the 'backends:' key)" -ForegroundColor White
            Write-Host ""
            Write-Host "    wintools-mcp:" -ForegroundColor Gray
            Write-Host "      type: http" -ForegroundColor Gray
            Write-Host "      url: `"http://${localIp}:${Port}/mcp`"" -ForegroundColor Gray
            Write-Host "      bearer_token: `"$wintoolsApiKey`"" -ForegroundColor Gray
            Write-Host "      enabled: true" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  After pasting, restart the gateway:" -ForegroundColor White
            Write-Host "    aiir service restart" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Clients then access wintools via the gateway at:" -ForegroundColor White
            Write-Host "    http://SIFT_IP:4508/mcp/wintools-mcp" -ForegroundColor Gray
            Write-Host ""

            # Save snippet to file for reference
            $snippetPath = Join-Path $InstallDir "gateway-snippet.yaml"
            try {
                @"
# Gateway backend snippet for wintools-mcp
# Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')
# Paste into ~/.aiir/gateway.yaml under the 'backends:' key on SIFT
wintools-mcp:
  type: http
  url: "http://${localIp}:${Port}/mcp"
  bearer_token: "$wintoolsApiKey"
  enabled: true
"@ | Set-Content -Path $snippetPath -Encoding UTF8
                Write-Ok "Saved gateway snippet: $snippetPath"
            } catch {
                Write-Warn "Could not save gateway snippet file"
            }
        }
    } else {
        @"
# wintools-mcp configuration (generated by setup-windows.ps1)
http_host: "$BindAddress"
http_port: $Port
$toolPathsYaml
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
            $skipServerStart = $true
        }
    }
} catch { }

if (-not $skipServerStart) {
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
                $serverHealthy = $true
            } catch {
                Write-Warn "wintools-mcp started but health check failed"
            }
        } else {
            Write-Warn "wintools-mcp exited immediately - check configuration"
        }
    } catch {
        Write-Warn "Could not start wintools-mcp"
    }
} else {
    Write-Info "Server start skipped (port conflict)"
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
    # Build startup script with all env vars the SYSTEM task needs
    $startupLines = @(
        "# Start wintools-mcp in HTTP mode",
        "# Environment vars set here because the scheduled task runs as SYSTEM",
        "# which doesn't see User-level environment variables",
        "`$env:AIIR_EXAMINER = `"$Examiner`""
    )
    if ($env:AIIR_CASE_DIR) {
        $startupLines += "`$env:AIIR_CASE_DIR = `"$($env:AIIR_CASE_DIR)`""
    }
    if ($env:AIIR_ACTIVE_CASE) {
        $startupLines += "`$env:AIIR_ACTIVE_CASE = `"$($env:AIIR_ACTIVE_CASE)`""
    }
    $startupLines += "& `"$venvPython`" -m wintools_mcp $scriptArgs"
    ($startupLines -join "`r`n") | Set-Content -Path $startupPath -Encoding UTF8
} catch {
    Write-Warn "Could not write startup script"
}

if ($startChoice -eq "1" -and -not $skipServerStart) {
    # Register scheduled task for auto-start
    $taskName = "AIIR wintools-mcp"

    if ($serverHealthy) {
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
    } else {
        Write-Warn "Server did not pass health check. Skipping scheduled task registration."
        Write-Host "  Fix the issue and register manually:"
        Write-Host "  schtasks /create /tn `"$taskName`" /tr `"powershell.exe -ExecutionPolicy Bypass -File \`"$startupPath\`"`" /sc onstart /ru SYSTEM"
    }

    # Add firewall rule
    try {
        $ruleName = "AIIR wintools-mcp"
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existingRule) {
            if ($siftIp -and $siftIp -ne "THIS_MACHINE_IP") {
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -RemoteAddress $siftIp -ErrorAction Stop | Out-Null
                Write-Ok "Firewall rule added for TCP port $Port (restricted to $siftIp)"
            } else {
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -RemoteAddress 127.0.0.1 -ErrorAction Stop | Out-Null
                Write-Ok "Firewall rule added for TCP port $Port (localhost only)"
                Write-Warn "IMPORTANT: Firewall restricted to localhost. For remote SIFT access, run:"
                Write-Host "  Set-NetFirewallRule -DisplayName `"$ruleName`" -RemoteAddress SIFT_IP_HERE"
            }
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

if ($skipServerStart) {
    Write-Warn "wintools-mcp installed but server not started (port conflict)"
} elseif ($serverHealthy) {
    Write-Ok "wintools-mcp installed and running"
} else {
    Write-Warn "wintools-mcp installed but health check did not pass"
}
Write-Host ""
Write-Host "  Examiner:       $Examiner"
Write-Host "  Install dir:    $InstallDir"
Write-Host "  HTTP server:    http://localhost:$Port"
Write-Host "  Health check:   http://localhost:$Port/health"
Write-Host "  MCP endpoint:   http://localhost:$Port/mcp"
if (Test-Path $overviewPath) {
    Write-Host "  Tool inventory: $overviewPath"
}

if ($wintoolsApiKey) {
    Write-Host "  API key:        $(Mask-ApiKey $wintoolsApiKey)"
    Write-Host "  (full key in config.yaml and gateway-snippet.yaml)" -ForegroundColor Gray
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
    if ($joinSucceeded) {
        Write-Ok "Registered via join API. No manual gateway configuration needed."
        Write-Host ""
    } elseif ($wintoolsApiKey) {
        $snippetPath = Join-Path $InstallDir "gateway-snippet.yaml"
        Write-Host "  Add to your SIFT gateway.yaml:" -ForegroundColor White
        Write-Host "    backends:"
        Write-Host "      wintools-mcp:"
        Write-Host "        type: http"
        Write-Host "        url: `"http://${localIp}:${Port}/mcp`""
        Write-Host "        bearer_token: `"$wintoolsApiKey`""
        Write-Host "        enabled: true"
        Write-Host ""
        if (Test-Path $snippetPath) {
            Write-Host "  Snippet saved to: $snippetPath" -ForegroundColor White
        }
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
Write-Host "          `"type`": `"http`"," -ForegroundColor Gray
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

if ($skipServerStart) {
    Write-Host "  Auto-start: not configured (server not started)" -ForegroundColor Yellow
} elseif ($startChoice -eq "1" -and $serverHealthy) {
    Write-Host "  Auto-start: enabled (scheduled task)" -ForegroundColor Green
} elseif ($startChoice -eq "1") {
    Write-Host "  Auto-start: not configured (health check failed)" -ForegroundColor Yellow
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
if ($startChoice -eq "1" -and $serverHealthy -and -not $skipServerStart) {
    Write-Host "  Note: AIIR_CASE_DIR is set per case and must be updated when" -ForegroundColor Yellow
    Write-Host "  switching cases. If using auto-start (scheduled task), set it" -ForegroundColor Yellow
    Write-Host "  as a Machine-level environment variable:" -ForegroundColor Yellow
    Write-Host "    [Environment]::SetEnvironmentVariable(`"AIIR_CASE_DIR`", `"Z:\INC-2026-0001`", `"Machine`")" -ForegroundColor Gray
    Write-Host "  Or restart wintools-mcp manually after changing cases." -ForegroundColor Yellow
    Write-Host ""
}
Write-Host ""
