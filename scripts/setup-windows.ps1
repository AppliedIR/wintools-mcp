#Requires -Version 5.1
<#
.SYNOPSIS
    Valhuntir Platform Installer for Windows Forensic Workstation

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

    Valhuntir Mode (default):
      Integrates with the full Valhuntir platform on a SIFT workstation.
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
    Installation directory. Default: C:\Tools\vhir or %USERPROFILE%\vhir.

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
    One-time join code from 'vhir setup join-code' on SIFT workstation.
    Enables automated credential exchange instead of manual copy-paste.

.PARAMETER Uninstall
    Remove wintools-mcp: scheduled task, firewall rule, environment variables,
    and optionally the install directory. Prompts for confirmation on each
    component. After uninstalling on Windows, also run
    'vhir setup client --uninstall' on the SIFT workstation.

.PARAMETER Update
    Update wintools-mcp: git pull, pip reinstall, restart scheduled task.
    Fails cleanly on dirty working tree or merge conflicts instead of
    silently proceeding with stale code.

.PARAMETER ContinueWithoutUpdate
    When the install's wintools-mcp folder is a git checkout that git can't
    update (a failed pull, a local change, a checked-out tag), set up the code
    already there instead of stopping. The setup still needs to reach GitHub
    at the start, and PyPI to install the package. Without it, a failed update
    stops the run, unless you answer "y" when asked.

.EXAMPLE
    # Interactive install with full Valhuntir integration
    .\setup-windows.ps1

.EXAMPLE
    # Interactive standalone install (no SIFT needed)
    .\setup-windows.ps1 -Standalone

.EXAMPLE
    # Non-interactive with Valhuntir integration
    .\setup-windows.ps1 -NonInteractive -AcknowledgeSecurityHole

.EXAMPLE
    # Non-interactive standalone with custom directory
    .\setup-windows.ps1 -Standalone -NonInteractive -AcknowledgeSecurityHole -InstallDir "D:\Forensics\vhir"

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
    #   vhir setup client --windows=WIN_IP:4624

.EXAMPLE
    # Deployment: SIFT + Windows (typical team setup)
    #   1. Install Valhuntir on SIFT:  ./sift-install.sh  (with wintools support)
    #   2. Get join code on SIFT: vhir setup join-code
    #   3. Install on Windows:    .\setup-windows.ps1  (enter join code when prompted)
    #   4. Configure client:      vhir setup client --sift=SIFT_IP:4508 --windows=WIN_IP:4624
    .\setup-windows.ps1

.EXAMPLE
    # Non-interactive with automated join
    .\setup-windows.ps1 -NonInteractive -AcknowledgeSecurityHole `
        -GatewayHost 10.0.0.1 -JoinCode "ABCD-EFGH" -Examiner "analyst1"

.EXAMPLE
    # Standalone, in another install directory. The installer downloads
    # wintools-mcp from GitHub and its packages from PyPI, so it needs
    # internet access to both: it can't install in an air-gapped lab.
    .\setup-windows.ps1 -Standalone -InstallDir "E:\vhir"

.EXAMPLE
    # Re-run on a machine whose wintools-mcp checkout can't be pulled (a local
    # change or a tag), setting up the code already there
    .\setup-windows.ps1 -NonInteractive -AcknowledgeSecurityHole -ContinueWithoutUpdate
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
    [switch]$Update,
    [switch]$ContinueWithoutUpdate
)

# The SHA-256 of a script, with CRLF read as LF (a git checkout and the ZIP
# of the same commit differ only there); "" when there is no file
function Get-ScriptHash {
    param([string]$Path)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "" }
    $latin1 = [Text.Encoding]::GetEncoding(28591)
    $text = $latin1.GetString([IO.File]::ReadAllBytes($Path)).Replace("`r`n", "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    return [BitConverter]::ToString($sha.ComputeHash($latin1.GetBytes($text))).Replace("-", "")
}

# Recorded before anything is fetched: an update can change this file, and
# the new one is then run with the same options (Start-SetupScript)
$startParams = @{}
foreach ($k in $PSBoundParameters.Keys) { $startParams[$k] = $PSBoundParameters[$k] }
$selfHash = Get-ScriptHash $PSCommandPath

$ErrorActionPreference = "Stop"

# Enforce TLS 1.2 -- PS 5.1 defaults to SSL3/TLS1.0 which GitHub rejects
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$process = $null
$skipServerStart = $false
$serverHealthy = $false
$joinSucceeded = $false
$smbMapped = $false

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

# Whether $Path is a setup-windows.ps1 other than the running one. A re-run
# (WINTOOLS_SETUP_RERUN) only warns: one re-run, never a loop.
function Test-NewSetupScript {
    param([string]$Path)
    $hash = Get-ScriptHash $Path
    if (-not $hash -or -not $selfHash -or $hash -eq $selfHash) { return $false }
    if ($env:WINTOOLS_SETUP_RERUN) {
        Write-Warn "The update changed setup-windows.ps1 again; carrying on with the one already running"
        return $false
    }
    Write-Info "The update changed setup-windows.ps1: running the new one with the same options"
    return $true
}

function Format-Quoted {
    param([string]$Value)
    return "'" + [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($Value) + "'"
}

# Runs $Script with $Params in a new PowerShell, the same program as this one
# (powershell.exe or pwsh.exe from $PSHOME), and exits with its code. The new
# PowerShell is called as a statement, never assigned, so its output and
# prompts reach the console; WINTOOLS_SETUP_RERUN is set inside it only.
# -RemoveAfter: $Script is a temporary copy, removed once it has run.
function Start-SetupScript {
    param([string]$Script, [hashtable]$Params, [switch]$RemoveAfter)
    $pairs = foreach ($k in ($Params.Keys | Sort-Object)) {
        $v = $Params[$k]
        if ($v -is [System.Management.Automation.SwitchParameter] -or $v -is [bool]) {
            $text = if ([bool]$v) { '$true' } else { '$false' }
        } elseif ($v -is [int]) {
            $text = [string]$v
        } else {
            $text = Format-Quoted ([string]$v)
        }
        (Format-Quoted $k) + " = " + $text
    }
    # A script that ends normally after a failed native command exits 0, as a
    # -File run does; a failure with no exit code (a throw, a parameter the
    # script doesn't take) exits 1
    $command = '$env:WINTOOLS_SETUP_RERUN = ''1''; $p = @{ ' + ($pairs -join "; ") + ' }; & ' +
        (Format-Quoted $Script) + ' @p; if ($?) { exit 0 } elseif ($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 }'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $exe = if ($PSVersionTable.PSEdition -eq "Core") { "pwsh" } else { "powershell" }
    if ([Environment]::OSVersion.Platform -eq "Win32NT") { $exe += ".exe" }
    $ErrorActionPreference = "Continue"
    & (Join-Path $PSHOME $exe) -NoProfile -ExecutionPolicy ([string](Get-ExecutionPolicy)) -OutputFormat Text -EncodedCommand $encoded
    $code = $LASTEXITCODE
    if ($RemoveAfter) { Remove-Item -LiteralPath $Script -Force -ErrorAction SilentlyContinue }
    exit $code
}

# 64-bit only: the cryptography package ships no 32-bit Windows build
function Get-PythonBits {
    param($exe, [string[]]$pre = @())
    $bits = & $exe @pre -c "import struct; print(struct.calcsize('P') * 8)" 2>&1
    return "$bits".Trim()
}
function Assert-Venv64 {
    param($venvPython)
    if ((Get-PythonBits $venvPython) -eq "32") {
        Write-Err 'This wintools-mcp environment uses 32-bit Python. Install 64-bit Python 3.10+, remove `.venv`, and re-run.'
        exit 1
    }
}

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
        $enc.GetBytes("vhir-smb-v1"),
        600000,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $dk = $deriv.GetBytes(32)
    $deriv.Dispose()
    return [BitConverter]::ToString($dk).Replace("-", "").ToLower().Substring(0, 32)
}

# -- The share's drive letter, past a remembered mapping --
# A drive letter's remembered mapping (a persistent one Windows keeps even
# while it can't connect), by its remote path; $null when there is none
function Get-RememberedMapping {
    param([string]$Letter)
    $key = "HKCU:\Network\$Letter"
    if (-not (Test-Path $key)) { return $null }
    try {
        return (Get-ItemProperty -Path $key -Name RemotePath -ErrorAction Stop).RemotePath
    } catch { return $null }
}

# The share root the last install recorded in config.yaml; $null when none
function Get-PreviousShareRoot {
    param([string]$ConfigPath)
    if (-not $ConfigPath -or -not (Test-Path $ConfigPath)) { return $null }
    $m = Select-String -Path $ConfigPath -Pattern '^share_root:\s*(\S+)' | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value }
    return $null
}

# Whether a remembered mapping is Valhuntir's own earlier one: the share root
# the last install recorded, or a Valhuntir share on this SIFT (cases, its
# name before 0.6.4, or vhir-cases)
function Test-OwnEarlierMapping {
    param([string]$Target, [string]$SmbHost, [string]$PreviousShareRoot)
    if (-not $Target) { return $false }
    $t = $Target.Trim().TrimEnd('\').ToLowerInvariant()
    if ($PreviousShareRoot -and $t -eq $PreviousShareRoot.Trim().TrimEnd('\').ToLowerInvariant()) {
        return $true
    }
    $parts = $t.TrimStart('\').Split('\')
    return ($parts.Count -eq 2) -and ($parts[0] -eq "$SmbHost".ToLowerInvariant()) -and
        ($parts[1] -in @("cases", "vhir-cases"))
}

# The letter to map the share on (S: first, then T:-Z:): the first with no
# drive and no remembered mapping, once Valhuntir's own earlier mapping is
# removed from it. Any other remembered mapping is never removed: the search
# moves on to the next letter, and the letters passed over are named. No
# letter at all, or a removal that failed: no letter, and why, with the
# command that clears it (net use would stop at its overwrite prompt).
function Select-ShareLetter {
    param([string]$SmbHost, [string]$PreviousShareRoot)
    $passed = @()
    foreach ($letter in @("S","T","U","V","W","X","Y","Z")) {
        if (Test-Path "${letter}:\") { continue }  # a drive in use: left alone
        $target = Get-RememberedMapping $letter
        if (-not $target) {
            foreach ($p in $passed) { Write-Info "$p; left as it is, using ${letter}:" }
            return @{ Letter = $letter; Why = "" }
        }
        if (Test-OwnEarlierMapping $target $SmbHost $PreviousShareRoot) {
            # net's stderr under Stop would end the installer (PowerShell 5.1):
            # read its exit code instead
            $global:LASTEXITCODE = -1
            $prevEAPNet = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try {
                $null = net use "${letter}:" /delete /y 2>&1
            } catch {
            } finally {
                $ErrorActionPreference = $prevEAPNet
            }
            if ($global:LASTEXITCODE -eq 0) {
                Write-Info "Removed Valhuntir's earlier mapping ${letter}: to $target"
                foreach ($p in $passed) { Write-Info "$p; left as it is, using ${letter}:" }
                return @{ Letter = $letter; Why = "" }
            }
            return @{ Letter = $null; Why = "${letter}: still holds Valhuntir's earlier mapping to $target, which couldn't be removed; remove it (net use ${letter}: /delete /y) and run the installer again" }
        }
        $passed += "${letter}: is remembered as a mapping to $target, which isn't Valhuntir's (to remove it: net use ${letter}: /delete)"
    }
    if ($passed) {
        return @{ Letter = $null; Why = ($passed -join "; ") + "; remove one, or map the share by hand" }
    }
    return @{ Letter = $null; Why = "no available drive letter (S-Z)" }
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
        do {
            $IP = Read-Host "Enter static IP for this machine [$defaultIP]"
            if (-not $IP) { $IP = $defaultIP }
            if ($IP -and $IP -notmatch '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)') {
                Write-Err "IP must be a private address (10.x, 172.16-31.x, 192.168.x)"
                $IP = ""
                continue
            }
            if ($IP) {
                Write-Host ""
                Write-Host "  Static IP: $IP" -ForegroundColor White
                $confirmed = Read-YesNo "Correct?" $true
                if (-not $confirmed) { $IP = "" }
            }
        } while (-not $IP)
    }

    # Validate RFC1918 (for -IP parameter path)
    if ($IP -notmatch '^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)') {
        Write-Err "IP must be a private address (10.x, 172.16-31.x, 192.168.x)"
        return $null
    }

    if ($currentIP) { $prefix = $currentIP.PrefixLength } else { $prefix = 24 }
    $gw = (Get-NetRoute -InterfaceIndex $idx -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
           Select-Object -First 1).NextHop
    $dns = (Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses

    # If IP matches AND is already static, skip
    if ($currentIP -and $currentIP.IPAddress -eq $IP -and $currentIP.PrefixOrigin -eq "Manual") {
        return $IP
    }

    # Use netsh -- single atomic operation, sets static even if IP matches (DHCP -> static)
    $mask = switch ($prefix) { 24 { "255.255.255.0" } 16 { "255.255.0.0" } 8 { "255.0.0.0" } default { "255.255.255.0" } }
    $adapterName = $adapter.InterfaceAlias
    $prevEAPNetsh = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $null = & netsh interface ipv4 set address "$adapterName" static $IP $mask $gw 2>&1
    } finally {
        $ErrorActionPreference = $prevEAPNetsh
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Failed to set static IP (may require Administrator)"
        Write-Host "  Run this installer as Administrator, or set the IP manually:" -ForegroundColor Yellow
        Write-Host "  netsh interface ipv4 set address `"$adapterName`" static $IP $mask $gw" -ForegroundColor Gray
        return $null
    }
    if ($dns) {
        try { $null = Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $dns } catch {}
    }

    # Write network.yaml
    $vhirDir = Join-Path $env:USERPROFILE ".vhir"
    if (-not (Test-Path $vhirDir)) {
        New-Item -ItemType Directory -Path $vhirDir -Force | Out-Null
    }
    @"
static_ip: $IP
interface: $($adapter.InterfaceAlias)
configured_at: $([DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"))
"@ | Set-Content -Path (Join-Path $vhirDir "network.yaml") -Encoding UTF8

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
        if (Test-Path "C:\Tools\vhir") { $InstallDir = "C:\Tools\vhir" }
        elseif (Test-Path "$env:USERPROFILE\vhir") { $InstallDir = "$env:USERPROFILE\vhir" }
        else {
            Write-Warn "Could not find wintools-mcp installation directory"
            Write-Host "  Specify with: .\setup-windows.ps1 -Uninstall -InstallDir <path>"
            exit 1
        }
    }
    Write-Info "Install directory: $InstallDir"

    # 1. Remove scheduled tasks (check all historical names + watchdog)
    $task = $null
    $taskName = $null
    foreach ($name in @("Valhuntir wintools-mcp", "ValiHuntIR wintools-mcp", "AIIR wintools-mcp")) {
        try {
            $t = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
            if ($t) { $task = $t; $taskName = $name; break }
        } catch {}
    }
    try {
        if ($task) {
            if (Read-YesNo "Remove scheduled task '$taskName'?" $true) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                Write-Ok "Scheduled task removed"
            }
        } else {
            Write-Info "No scheduled task found"
        }
        # Remove watchdog task
        $watchdog = Get-ScheduledTask -TaskName "Valhuntir wintools-mcp watchdog" -ErrorAction SilentlyContinue
        if ($watchdog) {
            Unregister-ScheduledTask -TaskName "Valhuntir wintools-mcp watchdog" -Confirm:$false -ErrorAction Stop
            Write-Ok "Watchdog task removed"
        }
    } catch {
        Write-Warn "Could not check/remove scheduled task: $_"
    }

    # 2. Remove firewall rule (check all historical names)
    $rule = $null
    $ruleName = $null
    foreach ($name in @("Valhuntir wintools-mcp", "ValiHuntIR wintools-mcp", "AIIR wintools-mcp")) {
        try {
            $r = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
            if ($r) { $rule = $r; $ruleName = $name; break }
        } catch {}
    }
    try {
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
    foreach ($varName in @("VHIR_EXAMINER", "VHIR_CASE_DIR", "VHIR_ACTIVE_CASE", "VHIR_SHARE_ROOT", "VHIR_AUDIT_DIR", "WINTOOLS_CASE_ROOT")) {
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

    # 4. Kill running wintools process before removing files
    $wintoolsProcs = Get-Process python*, pythonw* -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path -like "*wintools*" }
    if ($wintoolsProcs) {
        $wintoolsProcs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Write-Ok "Stopped running wintools process(es)"
    }

    # 5. Remove install directory (venv, source, config)
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
    Write-Host "    vhir setup client --uninstall    (removes MCP config entries)" -ForegroundColor Gray
    exit 0
}

# =============================================================================
# Update
# =============================================================================

if ($Update) {
    # Require admin — update restarts the scheduled task which runs as SYSTEM
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Err "Update requires Administrator privileges (scheduled task runs as SYSTEM)."
        Write-Host "  Right-click PowerShell -> Run as Administrator, then retry." -ForegroundColor Yellow
        exit 1
    }

    Write-Header "wintools-mcp Update"

    # Resolve install dir. Running from inside an installed repo takes priority
    # (user explicitly invoked THIS copy). Standard paths are fallback.
    $wintoolsDir = $null
    if (-not $InstallDir) {
        $scriptParent = Split-Path $PSScriptRoot -Parent
        if ((Split-Path $PSScriptRoot -Leaf) -eq "scripts" -and
            (Test-Path (Join-Path $scriptParent "pyproject.toml")) -and
            (Test-Path (Join-Path $scriptParent ".venv"))) {
            $wintoolsDir = $scriptParent
            $InstallDir = Split-Path $scriptParent -Parent
        }
        elseif (Test-Path "C:\Tools\vhir") { $InstallDir = "C:\Tools\vhir" }
        elseif (Test-Path "$env:USERPROFILE\vhir") { $InstallDir = "$env:USERPROFILE\vhir" }
        else {
            Write-Err "Could not find wintools-mcp installation. Use -InstallDir to specify."
            exit 1
        }
    }

    if (-not $wintoolsDir) {
        $wintoolsDir = Join-Path $InstallDir "wintools-mcp"
    }

    # Warn if running from a different location than the installed copy
    $scriptSource = Split-Path $PSScriptRoot -Parent
    if ($scriptSource -ne $wintoolsDir) {
        Write-Warn "You are running from: $scriptSource"
        Write-Warn "Installed copy is at: $wintoolsDir"
        Write-Host "  The update will apply to the installed copy." -ForegroundColor Yellow
        Write-Host "  Run future commands from: cd $wintoolsDir" -ForegroundColor Yellow
        Write-Host ""
    }
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
    Assert-Venv64 $venvPython  # the environment pip will run in

    # 1. Update source
    $hasGit = Get-Command git -ErrorAction SilentlyContinue
    if (-not $hasGit) {
        Write-Err "Git is required for updates. Install it with: winget install Git.Git"
        Write-Info "After installing, close and reopen PowerShell, then re-run -Update."
        exit 1
    }

    # Git writes progress/info to stderr. With $ErrorActionPreference = "Stop",
    # PowerShell converts stderr lines to terminating ErrorRecords. Suspend that
    # for the git section and check $LASTEXITCODE explicitly instead.
    $ErrorActionPreference = "Continue"

    Push-Location $wintoolsDir

    # Check for a working git repo (not just .git from a failed conversion)
    $isGitRepo = $false
    if (Test-Path ".git") {
        $null = git rev-parse HEAD 2>&1
        $isGitRepo = ($LASTEXITCODE -eq 0)
    }

    if (-not $isGitRepo) {
        # ZIP-based install or partial conversion. Set up git from scratch.
        Write-Info "No git repo found. Converting to git clone for future updates..."
        $null = git init 2>&1
        # Add remote idempotently (may exist from a failed previous attempt)
        $null = git remote remove origin 2>&1
        $null = git remote add origin "https://github.com/AppliedIR/wintools-mcp.git" 2>&1
        $null = git fetch origin main 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Could not reach GitHub. Check your network connection."
            Pop-Location
            $ErrorActionPreference = "Stop"
            exit 1
        }
        # Reset to latest main. .venv/ is gitignored so it stays intact.
        $null = git reset --hard origin/main 2>&1
        $null = git branch -M main 2>&1
        $null = git branch --set-upstream-to=origin/main main 2>&1
        Write-Ok "Converted to git repo and updated to latest"
    } else {
        # Normal git update
        Write-Info "Pulling latest changes..."
        $status = git status --porcelain 2>&1
        # Filter untracked files (??) -- they never conflict with git pull
        $modified = $status | Where-Object { $_ -notmatch '^\?\?' }
        # A re-run: the setup that started it showed these and had a yes
        if ($modified -and -not $env:WINTOOLS_SETUP_RERUN) {
            Write-Warn "Working tree has uncommitted changes:"
            $modified | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
            if (-not (Read-YesNo "Continue anyway? (changes may cause merge conflicts)" $false)) {
                Pop-Location
                $ErrorActionPreference = "Stop"
                exit 1
            }
        }

        $branch = git rev-parse --abbrev-ref HEAD 2>&1
        Write-Info "Current branch: $branch"

        $null = git fetch origin 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Err "Could not reach GitHub. Check your network connection."
            Pop-Location
            $ErrorActionPreference = "Stop"
            exit 1
        }
        $behind = git rev-list "HEAD..origin/$branch" --count 2>&1
        if ($behind -eq "0") {
            Write-Ok "Already up to date"
        } else {
            Write-Info "$behind commit(s) behind origin/$branch"
            $null = git pull --ff-only 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Err "git pull failed (merge conflict or non-fast-forward). Resolve manually."
                Pop-Location
                $ErrorActionPreference = "Stop"
                exit 1
            }
            Write-Ok "Source updated"
        }
    }

    Pop-Location
    $ErrorActionPreference = "Stop"

    # The installed setup-windows.ps1 does the rest when it isn't this one
    $installedScript = Join-Path (Join-Path $wintoolsDir "scripts") "setup-windows.ps1"
    if (Test-NewSetupScript $installedScript) {
        Start-SetupScript $installedScript $startParams
    }

    # 2. Reinstall package
    Write-Info "Reinstalling wintools-mcp..."
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $null = & $venvPython -m pip install --progress-bar off -e $wintoolsDir 2>&1
        if ($LASTEXITCODE -ne 0) { throw "pip install failed (exit $LASTEXITCODE)" }
        Write-Ok "Package reinstalled"
    } catch {
        Write-Err "pip install failed: $_"
        exit 1
    } finally {
        $ErrorActionPreference = $prevEAP
    }

    # 3. Reinstall FK if present (local copy or from sift-mcp repo)
    $fkDir = Join-Path $InstallDir "forensic-knowledge"
    $githubOrg = "https://github.com/AppliedIR"
    if (Test-Path $fkDir) {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $null = & $venvPython -m pip install --progress-bar off -e $fkDir 2>&1
            if ($LASTEXITCODE -ne 0) { throw "pip install failed (exit $LASTEXITCODE)" }
            $null = & $venvPython -c "import forensic_knowledge" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "forensic-knowledge reinstalled (local)"
            } else {
                Write-Warn "forensic-knowledge pip succeeded but import failed"
            }
        } catch {
            Write-Warn "FK reinstall failed (non-fatal)"
        } finally {
            $ErrorActionPreference = $prevEAP
        }
    } else {
        # Install FK from GitHub archive URL -- no git required
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $null = & $venvPython -m pip install --progress-bar off --no-cache-dir --force-reinstall `
                "forensic-knowledge @ ${githubOrg}/sift-mcp/archive/refs/heads/main.zip#subdirectory=packages/forensic-knowledge" 2>&1
            if ($LASTEXITCODE -ne 0) { throw "FK install failed (exit $LASTEXITCODE)" }
            $null = & $venvPython -c "import forensic_knowledge" 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "forensic-knowledge updated (from sift-mcp repo)"
            } else {
                Write-Warn "forensic-knowledge pip succeeded but import failed"
            }
        } catch {
            Write-Warn "FK update failed (non-fatal): $_"
        } finally {
            $ErrorActionPreference = $prevEAP
        }
    }

    # 4. Kill running wintools process so new code takes effect
    $wintoolsProcs = Get-Process python*, pythonw* -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path -like "*wintools*" }
    if ($wintoolsProcs) {
        $wintoolsProcs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }

    # 5. Restart via scheduled task, or tell user to start manually
    # Check both old and new task names (rebrand: ValiHuntIR/AIIR -> Valhuntir)
    $task = $null
    $taskName = $null
    foreach ($name in @("Valhuntir wintools-mcp", "ValiHuntIR wintools-mcp", "AIIR wintools-mcp")) {
        try {
            $t = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
            if ($t) { $task = $t; $taskName = $name; break }
        } catch {}
    }
    $currentTaskName = "Valhuntir wintools-mcp"
    try {
        if ($task) {
            # If found under old name, re-register under current name
            if ($taskName -ne $currentTaskName) {
                Write-Info "Renaming scheduled task from '$taskName' to '$currentTaskName'..."
                # Capture task action before unregistering
                $oldAction = (Get-ScheduledTask -TaskName $taskName).Actions[0]
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                $action = New-ScheduledTaskAction `
                    -Execute $oldAction.Execute `
                    -Argument $oldAction.Arguments
                $trigger = New-ScheduledTaskTrigger -AtStartup
                $settings = New-ScheduledTaskSettingsSet `
                    -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable `
                    -RestartCount 3 `
                    -RestartInterval (New-TimeSpan -Minutes 1) `
                    -ExecutionTimeLimit ([TimeSpan]::Zero)
                Register-ScheduledTask `
                    -TaskName $currentTaskName `
                    -Action $action `
                    -Trigger $trigger `
                    -Settings $settings `
                    -RunLevel Highest `
                    -User "SYSTEM" `
                    -Description "Valhuntir wintools-mcp forensic tool server" -ErrorAction Stop | Out-Null
                Write-Ok "Scheduled task renamed to '$currentTaskName'"
                $taskName = $currentTaskName
            }
            # Older installs kept the default 3-day time limit, which stops wintools
            try {
                $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
                $existing.Settings.ExecutionTimeLimit = "PT0S"
                Set-ScheduledTask -InputObject $existing -ErrorAction Stop | Out-Null
                Write-Ok "Scheduled task time limit removed"
            } catch {
                Write-Warn "Could not remove the scheduled task's time limit: $_"
            }
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            Write-Ok "Scheduled task restarted"
        } else {
            # No task found -- recreate from start-wintools.ps1 if available
            $startupPath = Join-Path $InstallDir "start-wintools.ps1"
            if (Test-Path $startupPath) {
                $action = New-ScheduledTaskAction `
                    -Execute "powershell.exe" `
                    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$startupPath`""
                $trigger = New-ScheduledTaskTrigger -AtStartup
                $settings = New-ScheduledTaskSettingsSet `
                    -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable `
                    -RestartCount 3 `
                    -RestartInterval (New-TimeSpan -Minutes 1) `
                    -ExecutionTimeLimit ([TimeSpan]::Zero)
                Register-ScheduledTask `
                    -TaskName $currentTaskName `
                    -Action $action `
                    -Trigger $trigger `
                    -Settings $settings `
                    -RunLevel Highest `
                    -User "SYSTEM" `
                    -Description "Valhuntir wintools-mcp forensic tool server" -ErrorAction Stop | Out-Null
                Start-ScheduledTask -TaskName $currentTaskName -ErrorAction Stop
                Write-Ok "Scheduled task recreated: $currentTaskName"
            } elseif ($wintoolsProcs) {
                Write-Warn "Stopped running wintools process but no scheduled task found to restart it"
                Write-Info "Start manually: & $venvPython -m wintools_mcp --host 0.0.0.0 --port $Port"
            }
        }
    } catch {
        Write-Warn "Could not restart scheduled task: $_"
    }

    # 6. Ensure watchdog task exists (may be missing on upgrades from pre-watchdog installs)
    $watchdogTaskName = "Valhuntir wintools-mcp watchdog"
    $watchdogExists = Get-ScheduledTask -TaskName $watchdogTaskName -ErrorAction SilentlyContinue
    if (-not $watchdogExists) {
        # Generate watchdog script if not present
        $watchdogPath = Join-Path $InstallDir "watchdog-wintools.ps1"
        $startupPath = Join-Path $InstallDir "start-wintools.ps1"
        if (-not (Test-Path $watchdogPath) -and (Test-Path $startupPath)) {
            $wintoolsConfigPath = Join-Path $InstallDir "config.yaml"
            $watchdogScheme = "http"
            if (Test-Path $wintoolsConfigPath) {
                $cfg = Get-Content $wintoolsConfigPath -Raw -ErrorAction SilentlyContinue
                if ($cfg -match '(?m)^\s*(tls_|ssl_)?certfile:') {
                    $watchdogScheme = "https"
                }
            }
            $logDir = Join-Path $InstallDir "logs"
            $watchdogLines = @(
                "# Watchdog: restart wintools-mcp if not responding",
                "`$port = $Port",
                "`$scheme = `"$watchdogScheme`"",
                "`$startupScript = `"$startupPath`"",
                "`$logFile = `"$logDir\watchdog.log`"",
                "",
                "if (`$scheme -eq `"https`") {",
                "    if (-not ([System.Management.Automation.PSTypeName]'VhirTrustLocalCert').Type) {",
                "        Add-Type @`"",
                "using System.Net;",
                "using System.Security.Cryptography.X509Certificates;",
                "public class VhirTrustLocalCert : ICertificatePolicy {",
                "    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,",
                "        WebRequest req, int problem) { return true; }",
                "}",
                "`"@",
                "    }",
                "    [System.Net.ServicePointManager]::CertificatePolicy = New-Object VhirTrustLocalCert",
                "}",
                "",
                "try {",
                "    `$response = Invoke-WebRequest -Uri `"`${scheme}://localhost:`${port}/health`" ``",
                "        -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop",
                "    exit 0",
                "} catch {",
                "    `$listening = Get-NetTCPConnection -LocalPort `$port -State Listen -ErrorAction SilentlyContinue",
                "    if (`$listening) { exit 0 }",
                "    `$running = Get-WmiObject Win32_Process -Filter `"Name='powershell.exe'`" |",
                "        Where-Object { `$_.CommandLine -like `"*start-wintools*`" }",
                "    if (`$running) { exit 0 }",
                "    `$ts = Get-Date -Format `"yyyy-MM-dd HH:mm:ss`"",
                "    if (-not (Test-Path `$logFile)) { New-Item -ItemType File -Path `$logFile -Force | Out-Null }",
                "    Add-Content -Path `$logFile -Value `"`$ts -- wintools not responding on port `$port, restarting`"",
                "    Start-Process -FilePath `"powershell.exe`" ``",
                "        -ArgumentList `"-ExecutionPolicy Bypass -WindowStyle Hidden -File ```"`$startupScript```"`" ``",
                "        -WindowStyle Hidden",
                "}"
            )
            try {
                ($watchdogLines -join "`r`n") | Set-Content -Path $watchdogPath -Encoding UTF8
            } catch {
                Write-Warn "Could not write watchdog script"
            }
        }
        # Register watchdog task
        $watchdogPath = Join-Path $InstallDir "watchdog-wintools.ps1"
        if (Test-Path $watchdogPath) {
            try {
                $watchdogAction = New-ScheduledTaskAction `
                    -Execute "powershell.exe" `
                    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$watchdogPath`""
                $watchdogTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
                    -RepetitionInterval (New-TimeSpan -Minutes 5) `
                    -RepetitionDuration (New-TimeSpan -Days 9999)
                $watchdogSettings = New-ScheduledTaskSettingsSet `
                    -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable `
                    -ExecutionTimeLimit ([TimeSpan]::Zero)
                Register-ScheduledTask `
                    -TaskName $watchdogTaskName `
                    -Action $watchdogAction `
                    -Trigger $watchdogTrigger `
                    -Settings $watchdogSettings `
                    -RunLevel Highest `
                    -User "SYSTEM" `
                    -Description "Valhuntir wintools-mcp watchdog -- restarts server if unresponsive" -ErrorAction Stop | Out-Null
                Write-Ok "Watchdog task registered (health check every 5 minutes)"
            } catch {
                Write-Warn "Could not register watchdog task: $_"
            }
        }
    } else {
        # Older installs kept the default 3-day time limit on the watchdog too
        try {
            $watchdogExists.Settings.ExecutionTimeLimit = "PT0S"
            Set-ScheduledTask -InputObject $watchdogExists -ErrorAction Stop | Out-Null
            Write-Ok "Watchdog task time limit removed"
        } catch {
            Write-Warn "Could not remove the watchdog task's time limit: $_"
        }
    }

    # 7. Version check
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
Write-Host "  Valhuntir - Validated Hunting for Incident Response" -ForegroundColor White
Write-Host "  Windows Workstation Installer" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""

if ($Standalone) {
    Write-Host "  Mode: Standalone (local case directory)" -ForegroundColor Cyan
} else {
    Write-Host "  Mode: Valhuntir-integrated (SMB to SIFT workstation)" -ForegroundColor Cyan
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
    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        $ack = Read-Host "  Acknowledgment"
        if ($ack -eq "security_hole") { break }
        if ($attempt -lt 2) {
            Write-Host "  Please type 'security_hole' exactly to proceed." -ForegroundColor Yellow
        }
    }
    if ($ack -ne "security_hole") {
        Write-Err "Installation cancelled."
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
$not64 = $null  # a 3.10+ interpreter that isn't 64-bit
foreach ($cmd in @("python", "python3", "py -3")) {
    try {
        $exe = $cmd.Split(" ")[0]
        $pre = @($cmd.Split(" ") | Select-Object -Skip 1)
        $ver = & $exe @pre -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>&1
        if ($ver) {
            $parts = $ver.Split(".")
            $major = [int]$parts[0]
            $minor = [int]$parts[1]
            if ($major -gt 3 -or ($major -eq 3 -and $minor -ge 10)) {
                $bits = Get-PythonBits $exe $pre
                if ($bits -eq "64") {
                    $pythonCmd = $cmd
                    Write-Ok "Python $ver (64-bit)"
                    break
                }
                if (-not $not64) { $not64 = "Python $ver ($bits-bit, '$cmd')" }
            }
        }
    } catch { }
}

if (-not $pythonCmd) {
    if ($not64) {
        Write-Err "64-bit Python 3.10+ required (found only $not64)"
        Write-Host "  Install the 64-bit (x86-64) installer from: https://www.python.org/downloads/windows/"
    } else {
        Write-Err "Python 3.10+ not found"
        Write-Host "  Install from: https://www.python.org/downloads/"
    }
    Write-Host "  Or via winget: winget install Python.Python.3.12"
    exit 1
}

# pip
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    $null = & ($pythonCmd.Split(" ")[0]) @($pythonCmd.Split(" ") | Select-Object -Skip 1) -m pip --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "pip not found (exit $LASTEXITCODE)" }
    Write-Ok "pip available"
} catch {
    Write-Err "pip not found"
    Write-Host "  Run: $pythonCmd -m ensurepip --upgrade"
    exit 1
} finally {
    $ErrorActionPreference = $prevEAP
}

# git (optional -- ZIP fallback available)
$hasGit = $null -ne (Get-Command git -ErrorAction SilentlyContinue)
if (-not $hasGit) {
    # winget/installer may have added git but PATH isn't refreshed in this session
    $gitFallback = "C:\Program Files\Git\cmd\git.exe"
    if (Test-Path $gitFallback) {
        $env:PATH = "$env:PATH;C:\Program Files\Git\cmd"
        $hasGit = $true
    }
}
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
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $null = & git ls-remote https://github.com/AppliedIR/wintools-mcp.git HEAD 2>&1
        if ($LASTEXITCODE -eq 0) { $networkOk = $true }
    } catch { }
    finally {
        $ErrorActionPreference = $prevEAP
    }
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
    $defaultDir = "C:\Tools\vhir"
    if (-not (Test-Path "C:\Tools")) {
        $defaultDir = "$env:USERPROFILE\vhir"
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

$wintoolsOldDir = "$wintoolsDir.old"

function Get-ChildProcesses {
    # The processes `$Parents` started (a venv's python.exe is a launcher
    # that starts the base interpreter)
    param($Parents)
    $ids = @($Parents | ForEach-Object { $_.Id })
    @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $ids -contains $_.ParentProcessId } |
        ForEach-Object { Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue })
}

function Stop-WintoolsProcesses {
    # The running wintools-mcp's python processes and the ones they started,
    # waited on until they exit; returns whether any was stopped
    $procs = @(Get-Process python*, pythonw* -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path -like "*wintools*" })
    if (-not $procs) { return $false }
    $all = @($procs) + @(Get-ChildProcesses $procs)
    $all | Stop-Process -Force -ErrorAction SilentlyContinue
    $all | Wait-Process -Timeout 30 -ErrorAction SilentlyContinue
    return $true
}

function Stop-WintoolsLoop {
    # A start-wintools.ps1 started by hand restarts the server whenever it
    # exits, so it's stopped first; returns whether one was
    $loops = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -and
                       $_.CommandLine -like "*start-wintools.ps1*" })
    if (-not $loops) { return $false }
    foreach ($l in $loops) { Stop-Process -Id $l.ProcessId -Force -ErrorAction SilentlyContinue }
    foreach ($l in $loops) { Wait-Process -Id $l.ProcessId -Timeout 30 -ErrorAction SilentlyContinue }
    return $true
}

$wintoolsWatchdogTask = "Valhuntir wintools-mcp watchdog"
$script:wintoolsPaused = $null
$script:wintoolsSwap = $null

function Suspend-WintoolsService {
    # Right before the folder is swapped: the scheduled tasks (the server and
    # its watchdog) are disabled, so the watchdog's trigger can't start the
    # server, and stay so until the new environment is built; their running
    # instances are stopped, then a hand-started loop, then the processes, each
    # waited on: a folder whose files are in use can't be renamed.
    # Resume-WintoolsService undoes it.
    $paused = @{ Disabled = @(); Running = @(); Loop = $false; Processes = $false }
    $script:wintoolsPaused = $paused
    foreach ($name in @("Valhuntir wintools-mcp", "ValiHuntIR wintools-mcp", "AIIR wintools-mcp",
                        $wintoolsWatchdogTask)) {
        $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        if (-not $task) { continue }
        if ($task.State -ne "Disabled") {
            try {
                $null = Disable-ScheduledTask -TaskName $name -ErrorAction Stop
                $paused.Disabled += $name
            } catch {
                Write-Warn "Could not disable the scheduled task '$name' for the update: $_"
            }
        }
        if ($task.State -eq "Running") {
            Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
            $paused.Running += $name
        }
    }
    $paused.Loop = Stop-WintoolsLoop
    $paused.Processes = Stop-WintoolsProcesses
}

function Resume-WintoolsService {
    # Re-enables the tasks Suspend-WintoolsService disabled that still exist;
    # with -Restart (the previous wintools-mcp is in place again), also starts
    # the server it stopped
    param([switch]$Restart)
    $paused = $script:wintoolsPaused
    if (-not $paused) { return }
    $script:wintoolsPaused = $null
    foreach ($name in $paused.Disabled) {
        if (-not (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue)) { continue }
        try {
            $null = Enable-ScheduledTask -TaskName $name -ErrorAction Stop
        } catch {
            Write-Warn "Could not re-enable the scheduled task '$name': $_. Enable it in Task Scheduler."
        }
    }
    if (-not $Restart) { return }
    $servers = @($paused.Running | Where-Object { $_ -ne $wintoolsWatchdogTask })
    foreach ($name in $servers) {
        try {
            Start-ScheduledTask -TaskName $name -ErrorAction Stop
            Write-Info "wintools-mcp restarted (scheduled task '$name')"
        } catch {
            Write-Warn "Could not restart the scheduled task '$name': $_"
        }
    }
    if (-not $servers -and ($paused.Loop -or $paused.Processes)) {
        $startup = Join-Path $InstallDir "start-wintools.ps1"
        if (Test-Path $startup) {
            Start-Process -FilePath "powershell.exe" -WindowStyle Hidden `
                -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$startup`""
            Write-Info "wintools-mcp restarted ($startup)"
        } else {
            Write-Warn "wintools-mcp was stopped for the update and isn't running; start it again."
        }
    }
}

function Rename-WithRetry {
    # A rename, tried again for a few seconds: an antivirus scan or a process
    # that is slow to exit can hold a file briefly
    param([string]$Path, [string]$NewName)
    for ($i = 1; ; $i++) {
        try {
            Rename-Item -Path $Path -NewName $NewName -ErrorAction Stop
            return
        } catch {
            if ($i -ge 5) { throw }
            Start-Sleep -Seconds 2
        }
    }
}

function Undo-WintoolsSwap {
    # The update failed before its environment was built: the new tree goes,
    # the previous wintools-mcp comes back from .old, and its server starts again
    $old = $script:wintoolsSwap
    $script:wintoolsSwap = $null
    try {
        if (Test-Path $wintoolsDir) { Remove-Item $wintoolsDir -Recurse -Force -ErrorAction Stop }
        Rename-WithRetry $old (Split-Path $wintoolsDir -Leaf)
    } catch {
        Write-Err "The update failed, and the previous wintools-mcp couldn't be put back: $_"
        if (Test-Path $wintoolsDir) {
            Write-Host "  The new one is still at $wintoolsDir and the previous one at ${old}: keep the one that works as $wintoolsDir, remove the other, and re-run." -ForegroundColor Yellow
        } else {
            Write-Host "  It is at $old; the next run puts it back." -ForegroundColor Yellow
        }
        Resume-WintoolsService
        return
    }
    Write-Warn "The update failed: the previous wintools-mcp is back in $wintoolsDir"
    Resume-WintoolsService -Restart
}

function Complete-WintoolsSwap {
    # The new wintools-mcp's environment is built: the previous one goes
    $old = $script:wintoolsSwap
    $script:wintoolsSwap = $null
    try {
        Remove-Item $old -Recurse -Force -ErrorAction Stop
    } catch {
        Write-Warn "Could not remove the previous wintools-mcp at ${old}: $_. Remove it before the next update."
    }
}

# Helper: download a repo as ZIP (no git required). An existing $DestDir is
# swapped, never deleted: once the new tree is extracted, $BeforeReplace runs,
# $DestDir becomes "$DestDir.old" and the new tree takes its place. Returns
# the old folder's path ("" when there was none).
function Get-RepoAsZip {
    param([string]$RepoName, [string]$DestDir, [scriptblock]$BeforeReplace, [scriptblock]$AfterExtract)
    $zipUrl = "$githubOrg/$RepoName/archive/refs/heads/main.zip"
    $zipPath = Join-Path $InstallDir "$RepoName.zip"
    $extractedDir = Join-Path $InstallDir "$RepoName-main"
    Write-Info "Downloading $RepoName..."
    try {
        Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec 120
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
    if (-not (Test-Path $extractedDir)) {
        throw "Expected directory $extractedDir not found after extraction"
    }
    # $AfterExtract returning true: the download isn't used, nothing is swapped
    if ($AfterExtract -and (& $AfterExtract $extractedDir)) {
        Remove-Item $extractedDir -Recurse -Force -ErrorAction SilentlyContinue
        return ""
    }
    $leaf = Split-Path $DestDir -Leaf
    if (-not (Test-Path $DestDir)) {
        Rename-WithRetry $extractedDir $leaf
        return ""
    }
    if ($BeforeReplace) { & $BeforeReplace }
    $old = "$DestDir.old"
    try {
        Rename-WithRetry $DestDir (Split-Path $old -Leaf)
    } catch {
        Remove-Item $extractedDir -Recurse -Force -ErrorAction SilentlyContinue
        throw "$DestDir is in use, so it was left as it is ($_)"
    }
    try {
        Rename-WithRetry $extractedDir $leaf
    } catch {
        $why = $_
        try {
            Rename-WithRetry $old $leaf
        } catch {
            throw "the new $RepoName couldn't be put in place ($why), and the previous one is left at ${old}: the next run puts it back"
        }
        Remove-Item $extractedDir -Recurse -Force -ErrorAction SilentlyContinue
        throw "the new $RepoName couldn't be put in place, so the previous one was kept ($why)"
    }
    return $old
}

# An update that stopped partway can leave the previous wintools-mcp as .old
if (Test-Path $wintoolsOldDir) {
    if (-not (Test-Path $wintoolsDir)) {
        Rename-WithRetry $wintoolsOldDir (Split-Path $wintoolsDir -Leaf)
        Write-Ok "Put back the wintools-mcp an earlier update left at $wintoolsOldDir"
    } else {
        Write-Err "Both $wintoolsDir and $wintoolsOldDir exist: an earlier update didn't finish"
        Write-Host "  Keep the one that works as $wintoolsDir, remove the other, and re-run." -ForegroundColor Yellow
        exit 1
    }
}

# A new setup-windows.ps1 from the fetch runs with this run's options, the
# acknowledgment and the install directory included, so neither is asked again
$rerunParams = $startParams.Clone()
$rerunParams["AcknowledgeSecurityHole"] = $true
$rerunParams["InstallDir"] = $InstallDir
$script:newSetupScript = $null

# Clone or download wintools-mcp
$cloneOk = $false
$gitFetched = $false  # a clone or pull that worked: the code is current
if ($hasGit) {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        if (Test-Path $wintoolsDir) {
            Write-Info "Directory exists, pulling latest..."
            $pullError = ""
            Push-Location $wintoolsDir
            try {
                $pullOutput = & git pull --quiet 2>&1
                $pullCode = $LASTEXITCODE
                if ($pullCode -ne 0) {
                    $gitSaid = @($pullOutput | ForEach-Object {
                        if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { "$_" }
                    } | Where-Object { "$_".Trim() } | Select-Object -First 8)
                    if ($gitSaid) {
                        $pullError = (@("git pull failed (exit ${pullCode}):") + $gitSaid) -join "`n    "
                    } else {
                        $pullError = "git pull failed (exit $pullCode) and printed nothing"
                    }
                } else {
                    $cloneOk = $true
                    $gitFetched = $true
                }
            } catch {
                $pullError = "git pull didn't run: $_"
            } finally {
                Pop-Location
            }
            # A failed update stops the run: setting up the old code is a choice
            if ($pullError) {
                Write-Err "Couldn't update the wintools-mcp at $wintoolsDir"
                Write-Host "  $pullError"
                $useOld = [bool]$ContinueWithoutUpdate
                if (-not $useOld) {
                    # A host that can't prompt (powershell -NonInteractive) throws: that's a No
                    try { $useOld = Read-YesNo "Set up the wintools-mcp already there, without the update?" $false } catch { $useOld = $false }
                }
                if ($useOld) {
                    Write-Warn "Continuing with the wintools-mcp already at $wintoolsDir, not updated"
                    if (Test-Path (Join-Path $wintoolsDir "pyproject.toml")) { $cloneOk = $true }
                } else {
                    Write-Host "  Fix the problem above and re-run, or re-run with -ContinueWithoutUpdate to set up the code already there." -ForegroundColor Yellow
                    exit 1
                }
            }
        } else {
            $null = & git clone --quiet "$githubOrg/wintools-mcp.git" $wintoolsDir 2>&1
            if ($LASTEXITCODE -ne 0) { throw "git clone failed (exit $LASTEXITCODE)" }
            $cloneOk = $true
            $gitFetched = $true
        }
    } catch {
        Write-Warn "git clone failed, falling back to ZIP download"
    } finally {
        $ErrorActionPreference = $prevEAP
    }
}
if ($gitFetched) {
    $fetchedScript = Join-Path (Join-Path $wintoolsDir "scripts") "setup-windows.ps1"
    if (Test-NewSetupScript $fetchedScript) {
        Start-SetupScript $fetchedScript $rerunParams
    }
}
if (-not $cloneOk) {
    # The download swaps the folder: the previous one is kept as
    # wintools-mcp.old until the new one's environment is built below
    if (Test-Path $wintoolsDir) {
        Write-Info "Directory exists, re-downloading..."
    }
    $handedOver = $false  # to the rollback window below
    try {
        # A download with a new setup-windows.ps1 replaces nothing: a copy of
        # that script runs instead (below), and it downloads again
        $script:wintoolsSwap = Get-RepoAsZip "wintools-mcp" $wintoolsDir -BeforeReplace { Suspend-WintoolsService } -AfterExtract {
            param($tree)
            $new = Join-Path (Join-Path $tree "scripts") "setup-windows.ps1"
            if (-not (Test-NewSetupScript $new)) { return $false }
            $script:newSetupScript = Join-Path ([IO.Path]::GetTempPath()) "wintools-setup-$([guid]::NewGuid()).ps1"
            Copy-Item -LiteralPath $new -Destination $script:newSetupScript
            return $true
        }
        if (-not $script:newSetupScript) { Write-Ok "wintools-mcp downloaded" }
        $handedOver = $true
    } catch {
        Write-Err "Failed to download wintools-mcp: $_"
        exit 1
    } finally {
        # a failure, or a Ctrl+C, before the window
        if (-not $handedOver) {
            if (Test-Path $wintoolsDir) {
                Resume-WintoolsService -Restart  # the previous one is in place: as it was
            } else {
                Resume-WintoolsService
            }
        }
    }
    if ($script:newSetupScript) {
        Start-SetupScript $script:newSetupScript $rerunParams -RemoveAfter
    }
}

# Create venv and install. After a swap, the rollback window: until the
# environment is built (venv and pip), any failure (a Ctrl+C too) puts the
# previous wintools-mcp back and starts it again; after it, the previous one
# goes. Either way the tasks are enabled again as the window closes.
$venvDir = Join-Path $wintoolsDir ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$installed = $false
try {
    if ($script:wintoolsSwap) {  # the examiner's config.yaml (its API key) comes along
        $oldConfig = Join-Path $script:wintoolsSwap "config.yaml"
        if (Test-Path $oldConfig) {
            try {
                Copy-Item $oldConfig $wintoolsConfigPath -Force -ErrorAction Stop
            } catch {
                Write-Err "Could not carry config.yaml over to the new wintools-mcp: $_"
                exit 1
            }
        }
    }

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
    Assert-Venv64 $venvPython  # a .venv kept from an earlier install too

    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $null = & $venvPython -m pip install --progress-bar off --upgrade pip 2>&1 } catch { }
    finally { $ErrorActionPreference = $prevEAP }

    # Install wintools-mcp without FK first (always works)
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $null = & $venvPython -m pip install --progress-bar off -e "$wintoolsDir" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "pip install failed (exit $LASTEXITCODE)" }
    } catch {
        Write-Err "Failed to install wintools-mcp"
        exit 1
    } finally {
        $ErrorActionPreference = $prevEAP
    }
    $installed = $true
} finally {
    if ($script:wintoolsSwap) {
        if ($installed) { Complete-WintoolsSwap } else { Undo-WintoolsSwap }
    }
    Resume-WintoolsService  # the window has closed: the tasks are enabled again
}

# forensic-knowledge (FK) enrichment -- optional
# FK lives inside the sift-mcp monorepo at packages/forensic-knowledge/.
# pip can install it directly from that subdirectory via git+subdirectory syntax.
# Without FK, tool execution still works but responses lack caveats, advisories,
# and corroboration hints.
$fkDir = Join-Path $InstallDir "forensic-knowledge"
$fkInstalled = $false

# Check if already installed in this venv
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    $null = & $venvPython -c "import forensic_knowledge" 2>&1
    if ($LASTEXITCODE -eq 0) {
        $fkInstalled = $true
    }
} catch { }
finally { $ErrorActionPreference = $prevEAP }

# If not installed, try pip install from sift-mcp repo subdirectory
if (-not $fkInstalled) {
    # First check if a local copy exists (from a previous install or manual placement)
    if (Test-Path $fkDir) {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $null = & $venvPython -m pip install --progress-bar off -e $fkDir 2>&1
            if ($LASTEXITCODE -eq 0) {
                $null = & $venvPython -c "import forensic_knowledge" 2>&1
                if ($LASTEXITCODE -eq 0) { $fkInstalled = $true }
            }
        } catch { }
        finally { $ErrorActionPreference = $prevEAP }
    }
    # Otherwise install from sift-mcp GitHub repo subdirectory
    if (-not $fkInstalled -and $networkOk) {
        Write-Info "Installing forensic-knowledge from sift-mcp repository..."
        $prevEAP2 = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $null = & $venvPython -m pip install --progress-bar off --no-cache-dir --force-reinstall `
                "forensic-knowledge @ ${githubOrg}/sift-mcp/archive/refs/heads/main.zip#subdirectory=packages/forensic-knowledge" 2>&1
            if ($LASTEXITCODE -ne 0) { throw "FK install failed (exit $LASTEXITCODE)" }
            $null = & $venvPython -c "import forensic_knowledge" 2>&1
            if ($LASTEXITCODE -eq 0) { $fkInstalled = $true }
        } catch {
            Write-Warn "Could not install forensic-knowledge: $_"
        } finally {
            $ErrorActionPreference = $prevEAP2
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

$examinerDeferred = $false

if (-not $Standalone -and [string]::IsNullOrWhiteSpace($Examiner)) {
    # Valhuntir mode without -Examiner flag: defer prompt to after join so we can
    # default to the SIFT examiner name from the join response.
    $examinerDeferred = $true
} else {
    Write-Header "Phase 3: Examiner Identity"

    Write-Host "Your examiner name identifies your work in audit trails."
    Write-Host "Use a short slug (e.g., steve, jane, analyst1)."
    Write-Host ""

    if ([string]::IsNullOrWhiteSpace($Examiner)) {
        $defaultExaminer = $env:USERNAME.ToLower() -replace "[^a-z0-9-]", "-"
        do {
            $Examiner = Read-Prompt "Examiner name" $defaultExaminer
            $Examiner = $Examiner.ToLower() -replace "[^a-z0-9-]", "-"
            if ([string]::IsNullOrWhiteSpace($Examiner)) { $Examiner = $defaultExaminer }
            Write-Host ""
            Write-Host "  Examiner: $Examiner" -ForegroundColor White
            $confirmed = Read-YesNo "Correct?" $true
        } while (-not $confirmed)
    } else {
        $Examiner = $Examiner.ToLower() -replace "[^a-z0-9-]", "-"
    }
    if ([string]::IsNullOrWhiteSpace($Examiner)) {
        $Examiner = $env:USERNAME.ToLower() -replace "[^a-z0-9-]", "-"
    }

    # Save config
    try {
        $vhirConfigDir = Join-Path $env:USERPROFILE ".vhir"
        if (-not (Test-Path $vhirConfigDir)) {
            New-Item -ItemType Directory -Path $vhirConfigDir -Force | Out-Null
        }
        "examiner: $Examiner" | Set-Content -Path (Join-Path $vhirConfigDir "config.yaml") -Encoding UTF8
        Write-Ok "Saved examiner identity: $Examiner"
    } catch {
        Write-Warn "Could not save examiner config to ~/.vhir/config.yaml"
    }

    # Set env var persistently
    try {
        [Environment]::SetEnvironmentVariable("VHIR_EXAMINER", $Examiner, "User")
        $env:VHIR_EXAMINER = $Examiner
        Write-Ok "Set VHIR_EXAMINER=$Examiner"
    } catch {
        Write-Warn "Could not set VHIR_EXAMINER environment variable"
        $env:VHIR_EXAMINER = $Examiner
    }
}

# =============================================================================
# Tool Inventory
# =============================================================================

Write-Header "Phase 4: Scanning for Forensic Tools"

# Run scan and capture output
try { $scanOutput = & $venvPython -m wintools_mcp --scan 2>&1 } catch { $scanOutput = $null }

$missingCount = 0
$extraToolPaths = @()
if ($scanOutput) {
    Write-Host $($scanOutput -join "`n")

    # Check for missing tools and prompt for additional directories
    $missingLine = $scanOutput | Where-Object { $_ -match "(\d+) missing" }
    if ($missingLine -and -not $NonInteractive) {
        $missingCount = 0
        if ($missingLine -match "(\d+) missing") { $missingCount = [int]$Matches[1] }
        if ($missingCount -gt 0) {
            Write-Host ""
            Write-Host "  $missingCount tool(s) not found in default search paths:" -ForegroundColor Yellow
            $scanOutput | Where-Object { $_ -match "\[MISSING\]\s+(\S+)" } | ForEach-Object {
                if ($_ -match "\[MISSING\]\s+(\S+)") { Write-Host "    - $($Matches[1])" -ForegroundColor Yellow }
            }
            Write-Host ""
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
$overviewScript = Join-Path $env:TEMP "vhir_overview.py"
try {
@'
import sys
from datetime import datetime
from wintools_mcp.catalog import load_catalog
from wintools_mcp.environment import tool_path

catalog = load_catalog()
found = []
missing = []
for name, td in sorted(catalog.items()):
    path = tool_path(td)
    if path:
        found.append((td.name, td.category, td.binary, path))
    else:
        missing.append((td.name, td.category, td.description or ""))

lines = []
lines.append(f"# Valhuntir Tool Inventory - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
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
if (-not $localIp) {
    $localIp = Read-Prompt "Could not detect IP address. Enter this machine's IP" ""
    if (-not $localIp) { $localIp = "THIS_MACHINE_IP" }
}

Write-Header "Phase 5: Case Directory"

$wintoolsApiKey = ""
$wintoolsScheme = "http"

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
    Write-Host "  Set VHIR_CASE_DIR before starting a case:" -ForegroundColor White
    Write-Host "    set VHIR_CASE_DIR=$caseDir\INC-2026-0001" -ForegroundColor White
    Write-Host ""
    Write-Host "  Place evidence working copies in the case directory." -ForegroundColor White
    Write-Host "  Tool output and audit entries are written to the audit subdirectory." -ForegroundColor White
    Write-Host ""

    # Save standalone config (Machine level so SYSTEM scheduled task can see it)
    try {
        [Environment]::SetEnvironmentVariable("VHIR_CASE_DIR", $caseDir, "Machine")
        [Environment]::SetEnvironmentVariable("WINTOOLS_CASE_ROOT", $caseDir, "Machine")
        $env:VHIR_CASE_DIR = $caseDir
        $env:WINTOOLS_CASE_ROOT = $caseDir
        Write-Ok "Set VHIR_CASE_DIR=$caseDir (machine-level)"
    } catch {
        # Fall back to User level if not running as admin
        try {
            [Environment]::SetEnvironmentVariable("VHIR_CASE_DIR", $caseDir, "User")
            [Environment]::SetEnvironmentVariable("WINTOOLS_CASE_ROOT", $caseDir, "User")
            Write-Warn "Set VHIR_CASE_DIR at User level (run as Administrator for Machine level)"
        } catch {
            Write-Warn "Could not set VHIR_CASE_DIR environment variable"
        }
        $env:VHIR_CASE_DIR = $caseDir
        $env:WINTOOLS_CASE_ROOT = $caseDir
    }

    # Generate API key for standalone mode too
    try {
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = New-Object byte[] 12
        $rng.GetBytes($bytes)
        $wintoolsApiKey = "vhir_wt_" + [BitConverter]::ToString($bytes).Replace("-", "").ToLower()
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
    # --- Valhuntir mode: join gateway + SMB to SIFT ---
    Write-Host "  In Valhuntir mode, wintools-mcp joins the SIFT gateway." -ForegroundColor White
    Write-Host "  The case directory is shared via SMB and mapped" -ForegroundColor White
    Write-Host "  automatically during the join process." -ForegroundColor White
    Write-Host ""

    # --- Static IP configuration ---
    Write-Host "--- Network Configuration ---" -ForegroundColor White
    Write-Host ""
    Write-Host "  The SIFT gateway connects to this machine by IP address." -ForegroundColor White
    Write-Host "  A static IP prevents the address from changing after reboot." -ForegroundColor White
    Write-Host ""

    $configureStaticIp = $true
    if ($NonInteractive -and -not $StaticIP) {
        $configureStaticIp = $false
    } elseif (-not $NonInteractive) {
        $configureStaticIp = [bool](Read-YesNo "Configure a static IP for this machine?" $true)
    }

    if ($configureStaticIp) {
        $staticResult = Set-StaticIP -IP $StaticIP
        if ($staticResult) {
            $localIp = $staticResult
            Write-Ok "Using static IP: $localIp"
        } else {
            Write-Warn "Static IP not configured. Using detected IP: $localIp"
        }
    } else {
        Write-Info "Skipping static IP configuration. Using detected IP: $localIp"
    }
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
        # Join code first -- by the time the user has it, SIFT IP is known
        Write-Host "  On the SIFT workstation, run: vhir setup join-code" -ForegroundColor Cyan
        Write-Host ""
        $joinCodeValue = Read-Prompt "Join code from SIFT workstation (blank to skip)" ""

        if ($joinCodeValue) {
            do {
                $siftIp = Read-Prompt "SIFT workstation IP" ""
                if ($siftIp) {
                    # Resolve hostname to IP for firewall rules
                    if ($siftIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
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

                    Write-Host ""
                    Write-Host "  SIFT gateway: ${siftIp}:${siftPort}" -ForegroundColor White
                    $confirmed = Read-YesNo "Correct?" $true
                    if (-not $confirmed) { $siftIp = "" }
                }
            } while ($joinCodeValue -and -not $siftIp)
        }
    }

    # Reachability check with diagnostics and retry
    if ($siftIp) {
        $retryGateway = $true
        while ($retryGateway) {
            $retryGateway = $false
            $gatewayReachable = $false

            # Step 1: Ping (network layer)
            Write-Info "Testing network connectivity to $siftIp..."
            # Just after a static-IP change the network can take a few seconds
            # to settle: retry for about 30 s then
            $pingTries = 1
            if ($staticResult) { $pingTries = 6 }
            $pingOk = $false
            for ($try = 1; $try -le $pingTries -and -not $pingOk; $try++) {
                if ($try -gt 1) { Start-Sleep -Seconds 5 }
                $pingOk = Test-Connection -ComputerName $siftIp -Count 1 -Quiet -ErrorAction SilentlyContinue
            }
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
                Write-Host "    sed -i 's/host: 127.0.0.1/host: 0.0.0.0/' ~/.vhir/gateway.yaml" -ForegroundColor Cyan
                Write-Host "    systemctl --user restart vhir-gateway" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  Other possibilities:" -ForegroundColor Gray
                Write-Host "    - Gateway not running (vhir service status)" -ForegroundColor Gray
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
                Write-Host "  Check that the Valhuntir gateway (not another service) is on port $siftPort." -ForegroundColor White
                if (-not $NonInteractive) {
                    Write-Host ""
                    $retry = Read-Prompt "Press Enter to retry, or 'skip' to continue without gateway" ""
                    if ($retry -ne "skip") { $retryGateway = $true; continue }
                }
            }
        }
    }

    # --- TLS Certificate Generation ---
    # Generate self-signed cert for HTTPS. Cert is pinned on SIFT during join.
    # Must happen BEFORE the join call (cert PEM is sent in the join body).
    $tlsDir = Join-Path $InstallDir "tls"
    New-Item -ItemType Directory -Path $tlsDir -Force | Out-Null
    $keyPath = Join-Path $tlsDir "key.pem"
    $certPath = Join-Path $tlsDir "cert.pem"

    # A cert that doesn't name this address can't be verified by SIFT: keep
    # it aside (never deleted) and make one that does
    if ((Test-Path $certPath) -and $localIp) {
        $sanText = ""
        try {
            $existingCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certPath
            $san = $existingCert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
            if ($san) { $sanText = $san.Format($false) }
        } catch { }
        if ($sanText -notmatch ("IP Address[=:]\s*" + [regex]::Escape($localIp) + "(\D|$)")) {
            $oldTls = Join-Path $InstallDir ("tls-old-" + (Get-Date -Format "yyyyMMddTHHmmss"))
            try {
                New-Item -ItemType Directory -Path $oldTls -Force -ErrorAction Stop | Out-Null
                Move-Item -Path $certPath -Destination $oldTls -ErrorAction Stop
                if (Test-Path $keyPath) { Move-Item -Path $keyPath -Destination $oldTls -ErrorAction Stop }
                Write-Warn "The TLS certificate doesn't name $localIp; kept it in $oldTls and making a new one"
            } catch {
                Write-Warn "The TLS certificate doesn't name $localIp, and it couldn't be moved aside: $_"
            }
        }
    }

    if (-not (Test-Path $certPath)) {
        Write-Info "Generating TLS certificate..."
        try {
            $cert = New-SelfSignedCertificate `
                -Subject "CN=wintools-mcp" `
                -TextExtension @("2.5.29.17={text}DNS=wintools-mcp&IPAddress=$localIp") `
                -CertStoreLocation Cert:\CurrentUser\My `
                -NotBefore (Get-Date).AddDays(-1) `
                -NotAfter (Get-Date).AddYears(10) `
                -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy Exportable
            $thumbprint = $cert.Thumbprint

            # Export PFX then convert to PEM via Python cryptography library
            $pfxPath = Join-Path $tlsDir "temp.pfx"
            Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$thumbprint" `
                -FilePath $pfxPath -Password (New-Object SecureString) -ErrorAction Stop | Out-Null

            & $venvPython -c @"
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from pathlib import Path
pfx = Path(r'$pfxPath').read_bytes()
key, cert, _ = pkcs12.load_key_and_certificates(pfx, b'')
Path(r'$keyPath').write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
Path(r'$certPath').write_bytes(cert.public_bytes(Encoding.PEM))
"@

            Remove-Item $pfxPath -ErrorAction SilentlyContinue
            # Clean up cert store entry (PEM files are the source of truth now)
            Remove-Item "Cert:\CurrentUser\My\$thumbprint" -ErrorAction SilentlyContinue
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $certPath) -or (Get-Item $certPath).Length -eq 0) {
                throw "PEM conversion failed (exit code $LASTEXITCODE)"
            }
            Write-Ok "TLS certificate generated: $certPath"
        } catch {
            Write-Warn "TLS certificate generation failed: $_"
            Write-Host "  wintools-mcp will start without TLS (HTTP mode)" -ForegroundColor Yellow
        }
    } else {
        Write-Info "TLS certificate exists: $certPath"
    }

    # URL scheme depends on whether TLS cert was generated
    $wintoolsScheme = "http"
    if (Test-Path $certPath) { $wintoolsScheme = "https" }

    # Join API call
    if ($joinCodeValue -and $gatewayReachable) {
        # Generate API key first (needed for request body)
        try {
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $bytes = New-Object byte[] 12
            $rng.GetBytes($bytes)
            $wintoolsApiKey = "vhir_wt_" + [BitConverter]::ToString($bytes).Replace("-", "").ToLower()
            $rng.Dispose()
        } catch {
            Write-Warn "Could not generate API key for join"
        }

        if ($wintoolsApiKey) {
            $joinBody = @{
                code = $joinCodeValue
                machine_type = "wintools"
                hostname = $env:COMPUTERNAME
                wintools_url = "${wintoolsScheme}://${localIp}:${Port}/mcp"
                wintools_token = $wintoolsApiKey
            }

            # Send public cert PEM so SIFT can pin it for verification
            if (Test-Path $certPath) {
                $joinBody.wintools_cert = (Get-Content $certPath -Raw).TrimStart([char]0xFEFF)
            }

            $joinBody = $joinBody | ConvertTo-Json

            try {
                $joinResponse = Invoke-WebRequest `
                    -Uri "${gatewayScheme}://${siftIp}:${siftPort}/api/v1/setup/join" `
                    -Method POST `
                    -ContentType "application/json" `
                    -Body $joinBody `
                    -TimeoutSec 30 `
                    -UseBasicParsing `
                    -ErrorAction Stop
                $joinData = $joinResponse.Content | ConvertFrom-Json
                $joinSucceeded = $true
                Write-Ok "Registered with SIFT gateway via join API"
                if ($joinData.gateway_token) {
                    Write-Ok "Gateway token received: $(Mask-ApiKey $joinData.gateway_token)"
                }
            } catch {
                $statusCode = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                if ($statusCode -eq 403) {
                    # Server rejected the request -- key was NOT stored. Safe to clear.
                    $wintoolsApiKey = ""
                    Write-Warn "Join failed: invalid, expired, or already-used join code"
                } elseif ($statusCode -eq 429) {
                    $wintoolsApiKey = ""
                    Write-Warn "Join failed: too many attempts. Try again later."
                } else {
                    # Timeout or network error -- server MAY have stored the key.
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

    # Drive mapping -- only if join succeeded and SMB fields present
    if ($joinSucceeded -and $joinData.smb_share) {
        $derivedPw = Derive-SMBPassword -JoinCode $joinCodeValue
        $smbHost = $joinData.smb_host
        $smbShare = $joinData.smb_share
        $smbUser = $joinData.smb_user
        $uncPath = "\\$smbHost\$smbShare"

        # Always save derived credentials for config.yaml -- regardless of net use result
        $script:smbUserForConfig = $smbUser
        $script:smbPasswordForConfig = $derivedPw
        $script:shareRootForConfig = $uncPath

        # Clean up any existing mapping to this UNC path before re-mapping
        foreach ($letter in @("S","T","U","V","W","X","Y","Z")) {
            if (Test-Path "${letter}:\") {
                try {
                    $existing = net use "${letter}:" 2>&1
                    if ($existing -match [regex]::Escape($uncPath)) {
                        $null = net use "${letter}:" /delete /yes 2>&1
                        Write-Info "Removed stale mapping ${letter}: to $uncPath"
                    }
                } catch { }
            }
        }

        # The drive letter (S: preferred, then T:-Z:), past Valhuntir's own
        # earlier mapping remembered on it (an upgrade from the old share)
        $pick = Select-ShareLetter -SmbHost $smbHost -PreviousShareRoot (Get-PreviousShareRoot $wintoolsConfigPath)
        $driveLetter = $pick.Letter
        if (-not $driveLetter) {
            Write-Warn "Drive mapping failed: $($pick.Why). Map the share manually:"
            Write-Host "  net use <LETTER>: $uncPath /user:$smbUser <password> /persistent:yes"
        } else {
            try {
                # net use is more reliable than New-PSDrive -Persist on PS 5.1
                $netResult = net use "${driveLetter}:" $uncPath /user:$smbUser $derivedPw /persistent:yes 2>&1
                if ($LASTEXITCODE -ne 0) { throw $netResult }

                Write-Ok "Mapped ${driveLetter}: to $uncPath"
                $smbMapped = $true
            } catch {
                Write-Warn "Drive mapping failed: $_"
                Write-Host "  Map manually: net use ${driveLetter}: $uncPath /user:$smbUser <password> /persistent:yes"
            }
        }
    }

    $derivedPw = $null

    # Deferred examiner prompt -- now that join is complete, we know the SIFT examiner
    if ($examinerDeferred) {
        Write-Host ""
        Write-Host "--- Examiner Identity ---" -ForegroundColor White
        Write-Host ""
        Write-Host "Your examiner name identifies your work in audit trails."
        Write-Host "Use a short slug (e.g., steve, jane, analyst1)."
        Write-Host ""

        # Default to SIFT examiner if available, otherwise OS username
        $defaultExaminer = $env:USERNAME.ToLower() -replace "[^a-z0-9-]", "-"
        $siftExaminer = ""
        if ($joinSucceeded -and $joinData.sift_examiner) {
            $siftExaminer = $joinData.sift_examiner
            $defaultExaminer = $siftExaminer
        }

        do {
            $Examiner = Read-Prompt "Examiner name" $defaultExaminer
            $Examiner = $Examiner.ToLower() -replace "[^a-z0-9-]", "-"
            if ([string]::IsNullOrWhiteSpace($Examiner)) { $Examiner = $defaultExaminer }
            Write-Host ""
            Write-Host "  Examiner: $Examiner" -ForegroundColor White
            $confirmed = Read-YesNo "Correct?" $true
        } while (-not $confirmed)

        # Mismatch warning if user overrode the SIFT default
        if ($siftExaminer -and $Examiner -ne $siftExaminer) {
            Write-Warn "Audit entries on this Windows workstation will be stamped as '$Examiner'"
            Write-Host "  while SIFT uses '$siftExaminer'. This creates separate identity" -ForegroundColor Yellow
            Write-Host "  attribution in the shared case directory." -ForegroundColor Yellow
        }

        # Save config
        try {
            $vhirConfigDir = Join-Path $env:USERPROFILE ".vhir"
            if (-not (Test-Path $vhirConfigDir)) {
                New-Item -ItemType Directory -Path $vhirConfigDir -Force | Out-Null
            }
            "examiner: $Examiner" | Set-Content -Path (Join-Path $vhirConfigDir "config.yaml") -Encoding UTF8
            Write-Ok "Saved examiner identity: $Examiner"
        } catch {
            Write-Warn "Could not save examiner config to ~/.vhir/config.yaml"
        }

        # Set env var persistently
        try {
            [Environment]::SetEnvironmentVariable("VHIR_EXAMINER", $Examiner, "User")
            $env:VHIR_EXAMINER = $Examiner
            Write-Ok "Set VHIR_EXAMINER=$Examiner"
        } catch {
            Write-Warn "Could not set VHIR_EXAMINER environment variable"
            $env:VHIR_EXAMINER = $Examiner
        }
    }

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
                $wintoolsApiKey = "vhir_wt_" + [BitConverter]::ToString($bytes).Replace("-", "").ToLower()
                $rng.Dispose()
                Write-Ok "Generated API key: $(Mask-ApiKey $wintoolsApiKey)"
            } catch {
                Write-Warn "Could not generate API key"
            }
        }
    }

    # Build TLS config section (empty string if no cert)
    # No YAML double-quotes around paths: \a in C:\vhir is a YAML escape
    # in double-quoted strings. Unquoted YAML treats backslash as literal.
    $tlsYaml = ""
    if (Test-Path $certPath) {
        $tlsYaml = @"

tls:
  certfile: $certPath
  keyfile: $keyPath
"@
    }

    # Build SMB config section if credentials were captured during drive mapping
    $smbYaml = ""
    if ($script:smbUserForConfig) {
        $smbYaml = @"

smb_user: $($script:smbUserForConfig)
smb_password: $($script:smbPasswordForConfig)
share_root: $($script:shareRootForConfig)
"@
    }

    # Write wintools-mcp config.yaml with API key if provided
    # On re-join: update connection settings (smb_*, api_key) in existing config
    # On re-run without join: preserve existing config
    if (Test-Path $wintoolsConfigPath) {
        if ($joinSucceeded -or $script:smbPasswordForConfig) {
            # Re-join: update connection settings in existing config
            try {
                $content = Get-Content $wintoolsConfigPath -Raw
                $updated = @()

                # Update SMB credentials
                if ($script:smbPasswordForConfig) {
                    if ($content -match 'smb_password:') {
                        $content = $content -replace 'smb_password:[^\r\n]*', "smb_password: $($script:smbPasswordForConfig)"
                    } else {
                        $content = $content.TrimEnd() + "`r`nsmb_password: $($script:smbPasswordForConfig)"
                    }
                    if ($content -match 'smb_user:') {
                        $content = $content -replace 'smb_user:[^\r\n]*', "smb_user: $($script:smbUserForConfig)"
                    } else {
                        $content = $content.TrimEnd() + "`r`nsmb_user: $($script:smbUserForConfig)"
                    }
                    if ($script:shareRootForConfig) {
                        if ($content -match 'share_root:') {
                            $content = $content -replace 'share_root:[^\r\n]*', "share_root: $($script:shareRootForConfig)"
                        } else {
                            $content = $content.TrimEnd() + "`r`nshare_root: $($script:shareRootForConfig)"
                        }
                    }
                    $updated += "smb"
                }

                # Update API key (gateway sends new key on each join)
                if ($wintoolsApiKey) {
                    if ($content -match '(?m)^\s+vhir_wt_') {
                        $content = $content -replace '(?m)^\s+vhir_wt_[^\r\n]*', "  ${wintoolsApiKey}:"
                    } elseif ($content -match 'api_keys:') {
                        # api_keys exists but no vhir_wt_ entry -- append under it
                        $content = $content -replace '(api_keys:[^\r\n]*)', "`$1`r`n  ${wintoolsApiKey}:`r`n    examiner: `"gateway`"`r`n    role: `"examiner`""
                    } else {
                        $content = $content.TrimEnd() + "`r`napi_keys:`r`n  ${wintoolsApiKey}:`r`n    examiner: `"gateway`"`r`n    role: `"examiner`""
                    }
                    $updated += "api_key"
                }

                $content | Set-Content -Path $wintoolsConfigPath -Encoding UTF8
                # Validate key fields survive the regex edit
                $verify = Get-Content $wintoolsConfigPath -Raw
                if ($script:smbPasswordForConfig -and $verify -notmatch 'smb_password:') {
                    Write-Warn "Config validation failed: smb_password missing after update"
                }
                if ($wintoolsApiKey -and $verify -notmatch 'api_keys:') {
                    Write-Warn "Config validation failed: api_keys missing after update"
                }
                Write-Ok "Updated connection settings in config: $($updated -join ', ')"

                # Restart running wintools process so new config takes effect
                if (Stop-WintoolsProcesses) {
                    # Check if scheduled task exists to auto-restart
                    $hasTask = $false
                    foreach ($name in @("Valhuntir wintools-mcp", "ValiHuntIR wintools-mcp", "AIIR wintools-mcp")) {
                        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
                            $hasTask = $true; break
                        }
                    }
                    if ($hasTask) {
                        Write-Info "Stopped running wintools-mcp (will restart via scheduled task or Phase 6)"
                    } else {
                        Write-Warn "Stopped running wintools-mcp but no scheduled task found to auto-restart it"
                        Write-Host "  It will be started in Phase 6, or start manually after setup completes" -ForegroundColor Yellow
                    }
                }
            } catch {
                Write-Warn "Could not update connection settings in config: $_"
            }
        } else {
            Write-Info "Existing config preserved: $wintoolsConfigPath"
            Write-Host "  Delete $wintoolsConfigPath and re-run to regenerate"
        }
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
$toolPathsYaml$tlsYaml$smbYaml
"@ | Set-Content -Path $wintoolsConfigPath -Encoding UTF8
        Write-Ok "Wrote config with API key: $wintoolsConfigPath"

        if (-not $joinSucceeded) {
            Write-Host ""
            Write-Host "  Add this snippet to your SIFT workstation's gateway.yaml" -ForegroundColor White
            Write-Host "  File: ~/.vhir/gateway.yaml (under the 'backends:' key)" -ForegroundColor White
            Write-Host ""
            Write-Host "    wintools-mcp:" -ForegroundColor Gray
            Write-Host "      type: http" -ForegroundColor Gray
            Write-Host "      url: `"${wintoolsScheme}://${localIp}:${Port}/mcp`"" -ForegroundColor Gray
            Write-Host "      bearer_token: `"$wintoolsApiKey`"" -ForegroundColor Gray
            Write-Host "      enabled: true" -ForegroundColor Gray
            if (Test-Path $certPath) {
                Write-Host "      tls_cert: `"~/.vhir/tls/wintools-cert.pem`"" -ForegroundColor Gray
            }
            Write-Host ""
            if (Test-Path $certPath) {
                Write-Host "  Copy the cert to SIFT first:" -ForegroundColor White
                Write-Host "    scp $certPath sift:~/.vhir/tls/wintools-cert.pem" -ForegroundColor Gray
                Write-Host ""
            }
            Write-Host "  After pasting, load it on SIFT (no gateway restart needed):" -ForegroundColor White
            Write-Host "    vhir service restart wintools-mcp" -ForegroundColor Gray
            Write-Host ""
            Write-Host "  Clients then access wintools via the gateway at:" -ForegroundColor White
            Write-Host "    http://SIFT_IP:4508/mcp/wintools-mcp" -ForegroundColor Gray
            Write-Host ""

            # Save snippet to file for reference
            $snippetPath = Join-Path $InstallDir "gateway-snippet.yaml"
            $snippetTlsCert = ""
            if (Test-Path $certPath) {
                $snippetTlsCert = "`n  tls_cert: ~/.vhir/tls/wintools-cert.pem"
            }
            try {
                @"
# Gateway backend snippet for wintools-mcp
# Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')
# Paste into ~/.vhir/gateway.yaml under the 'backends:' key on SIFT
wintools-mcp:
  type: http
  url: "${wintoolsScheme}://${localIp}:${Port}/mcp"
  bearer_token: "$wintoolsApiKey"
  enabled: true$snippetTlsCert
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
$toolPathsYaml$tlsYaml$smbYaml
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
    $existing = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
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
    $env:VHIR_EXAMINER = $Examiner

    try {
        $process = Start-Process -FilePath $venvPython -ArgumentList $startArgs -PassThru -WindowStyle Hidden

        Start-Sleep -Seconds 3

        # Check if it's running
        if (-not $process.HasExited) {
            $healthUrl = "${wintoolsScheme}://localhost:${Port}/health"
            if ($wintoolsScheme -eq "https") {
                # PS 5.1: scriptblock-to-delegate for ServerCertificateValidationCallback
                # is unreliable. Use ICertificatePolicy which PS 5.1 respects consistently.
                if (-not ([System.Management.Automation.PSTypeName]'VhirTrustLocalCert').Type) {
                    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class VhirTrustLocalCert : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
        WebRequest req, int problem) { return true; }
}
"@
                }
                $previousPolicy = [System.Net.ServicePointManager]::CertificatePolicy
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object VhirTrustLocalCert
            }
            try {
                $response = Invoke-WebRequest -Uri $healthUrl -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
                Write-Ok "wintools-mcp running on port $Port ($wintoolsScheme)"
                $serverHealthy = $true
            } catch {
                Write-Warn "wintools-mcp started but health check failed: $_"
            } finally {
                if ($wintoolsScheme -eq "https") {
                    [System.Net.ServicePointManager]::CertificatePolicy = $previousPolicy
                }
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

do {
    $startChoice = Read-Prompt "Choose" "1"
    if ($startChoice -ne "1" -and $startChoice -ne "2") {
        Write-Host "  Please enter 1 or 2" -ForegroundColor Yellow
    }
} while ($startChoice -ne "1" -and $startChoice -ne "2")

# Always generate the startup script (useful either way)
$startupPath = Join-Path $InstallDir "start-wintools.ps1"
$scriptArgs = "--http --host $BindAddress --port $Port"
if (Test-Path $wintoolsConfigPath) {
    $scriptArgs += " --config `"$wintoolsConfigPath`""
}
try {
    # Build startup script -- ST-1 (restart loop), ST-2 (logging), ST-4 (config-based env)
    # Python config.py now reads examiner/case_dir from config.yaml via os.environ.setdefault
    # so the startup script only needs VHIR_EXAMINER as fallback for non-config deployments
    $logDir = Join-Path $InstallDir "logs"
    $startupLines = @(
        "# Start wintools-mcp in HTTP mode with restart loop and logging",
        "# ST-4: Python reads examiner/case from config.yaml -- env vars are fallback only",
        "`$env:VHIR_EXAMINER = `"$Examiner`"",
        "",
        "# ST-2: Startup logging with rotation (keep 3)",
        "`$logDir = `"$logDir`"",
        "if (-not (Test-Path `$logDir)) { New-Item -ItemType Directory -Path `$logDir | Out-Null }",
        "`$logFile = Join-Path `$logDir `"wintools-startup.log`"",
        "if (Test-Path `$logFile) {",
        "    `$rotated = Join-Path `$logDir `"wintools-startup.`$(Get-Date -Format 'yyyyMMdd-HHmmss').log`"",
        "    Move-Item `$logFile `$rotated -ErrorAction SilentlyContinue",
        "    Get-ChildItem `$logDir -Filter `"wintools-startup.*.log`" |",
        "        Sort-Object LastWriteTime -Descending |",
        "        Select-Object -Skip 3 |",
        "        Remove-Item -ErrorAction SilentlyContinue",
        "}",
        "",
        "# ST-1: Restart loop with exponential backoff (5, 10, 20, 40, 60s)",
        "`$maxRestarts = 5",
        "`$restartCount = 0",
        "while (`$restartCount -lt `$maxRestarts) {",
        "    & `"$venvPython`" -m wintools_mcp $scriptArgs *>> `$logFile",
        "    `$exitCode = `$LASTEXITCODE",
        "    if (`$exitCode -eq 0) { break }",
        "    `$restartCount++",
        "    `$wait = [math]::Min(60, 5 * [math]::Pow(2, `$restartCount - 1))",
        "    Start-Sleep -Seconds `$wait",
        "}"
    )
    ($startupLines -join "`r`n") | Set-Content -Path $startupPath -Encoding UTF8
} catch {
    Write-Warn "Could not write startup script"
}

# Generate watchdog script (health check + restart if unresponsive)
$watchdogPath = Join-Path $InstallDir "watchdog-wintools.ps1"
$watchdogScheme = "http"
if (Test-Path $wintoolsConfigPath) {
    $cfg = Get-Content $wintoolsConfigPath -Raw -ErrorAction SilentlyContinue
    if ($cfg -match '(?m)^\s*(tls_|ssl_)?certfile:') {
        $watchdogScheme = "https"
    }
}
try {
    $watchdogLines = @(
        "# Watchdog: restart wintools-mcp if not responding",
        "`$port = $Port",
        "`$scheme = `"$watchdogScheme`"",
        "`$startupScript = `"$startupPath`"",
        "`$logFile = `"$logDir\watchdog.log`"",
        "",
        "# PS 5.1: ICertificatePolicy for self-signed cert bypass (matches installer pattern)",
        "if (`$scheme -eq `"https`") {",
        "    if (-not ([System.Management.Automation.PSTypeName]'VhirTrustLocalCert').Type) {",
        "        Add-Type @`"",
        "using System.Net;",
        "using System.Security.Cryptography.X509Certificates;",
        "public class VhirTrustLocalCert : ICertificatePolicy {",
        "    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,",
        "        WebRequest req, int problem) { return true; }",
        "}",
        "`"@",
        "    }",
        "    [System.Net.ServicePointManager]::CertificatePolicy = New-Object VhirTrustLocalCert",
        "}",
        "",
        "try {",
        "    `$response = Invoke-WebRequest -Uri `"`${scheme}://localhost:`${port}/health`" ``",
        "        -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop",
        "    # Healthy -- do nothing",
        "    exit 0",
        "} catch {",
        "    # Not responding -- check if something is already listening (startup in progress)",
        "    # Get-NetTCPConnection requires NetTCPIP module; always available to SYSTEM account",
        "    `$listening = Get-NetTCPConnection -LocalPort `$port -State Listen -ErrorAction SilentlyContinue",
        "    if (`$listening) {",
        "        # Port is bound but health check failed -- server starting up, give it time",
        "        exit 0",
        "    }",
        "",
        "    # Check if startup script is already running (PS 5.1 compatible via WMI)",
        "    # Get-WmiObject is deprecated in PS 7+ but required on PS 5.1 for CommandLine access",
        "    # Assumes startup script runs via powershell.exe (scheduled task uses powershell.exe)",
        "    `$running = Get-WmiObject Win32_Process -Filter `"Name='powershell.exe'`" |",
        "        Where-Object { `$_.CommandLine -like `"*start-wintools*`" }",
        "    if (`$running) {",
        "        exit 0",
        "    }",
        "",
        "    # Log and restart",
        "    `$ts = Get-Date -Format `"yyyy-MM-dd HH:mm:ss`"",
        "    if (-not (Test-Path `$logFile)) {",
        "        New-Item -ItemType File -Path `$logFile -Force | Out-Null",
        "    }",
        "    Add-Content -Path `$logFile -Value `"`$ts -- wintools not responding on port `$port, restarting`"",
        "",
        "    # Start the startup script (which has its own restart loop)",
        "    Start-Process -FilePath `"powershell.exe`" ``",
        "        -ArgumentList `"-ExecutionPolicy Bypass -WindowStyle Hidden -File ```"`$startupScript```"`" ``",
        "        -WindowStyle Hidden",
        "}"
    )
    ($watchdogLines -join "`r`n") | Set-Content -Path $watchdogPath -Encoding UTF8
} catch {
    Write-Warn "Could not write watchdog script"
}

if ($startChoice -eq "1" -and -not $skipServerStart) {
    # Register scheduled task for auto-start
    $taskName = "Valhuntir wintools-mcp"

    if ($serverHealthy) {
        try {
            # Remove ALL historical task names before registering
            foreach ($name in @("Valhuntir wintools-mcp", "ValiHuntIR wintools-mcp", "AIIR wintools-mcp")) {
                $old = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
                if ($old) {
                    Unregister-ScheduledTask -TaskName $name -Confirm:$false
                    Write-Info "Removed existing scheduled task: $name"
                }
            }

            # Run the startup script (which sets VHIR_EXAMINER and passes --config)
            $action = New-ScheduledTaskAction `
                -Execute "powershell.exe" `
                -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$startupPath`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $settings = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries `
                -StartWhenAvailable `
                -RestartCount 3 `
                -RestartInterval (New-TimeSpan -Minutes 1) `
                -ExecutionTimeLimit ([TimeSpan]::Zero)

            Register-ScheduledTask `
                -TaskName $taskName `
                -Action $action `
                -Trigger $trigger `
                -Settings $settings `
                -RunLevel Highest `
                -User "SYSTEM" `
                -Description "Valhuntir wintools-mcp forensic tool server" -ErrorAction Stop | Out-Null

            Write-Ok "Scheduled task registered: $taskName"
            Write-Ok "Will auto-start at boot"

            # Register watchdog task (health check every 5 minutes)
            $watchdogTaskName = "Valhuntir wintools-mcp watchdog"
            try {
                $old = Get-ScheduledTask -TaskName $watchdogTaskName -ErrorAction SilentlyContinue
                if ($old) { Unregister-ScheduledTask -TaskName $watchdogTaskName -Confirm:$false }

                $watchdogAction = New-ScheduledTaskAction `
                    -Execute "powershell.exe" `
                    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$watchdogPath`""
                $watchdogTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
                    -RepetitionInterval (New-TimeSpan -Minutes 5) `
                    -RepetitionDuration (New-TimeSpan -Days 9999)
                $watchdogSettings = New-ScheduledTaskSettingsSet `
                    -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable `
                    -ExecutionTimeLimit ([TimeSpan]::Zero)

                Register-ScheduledTask `
                    -TaskName $watchdogTaskName `
                    -Action $watchdogAction `
                    -Trigger $watchdogTrigger `
                    -Settings $watchdogSettings `
                    -RunLevel Highest `
                    -User "SYSTEM" `
                    -Description "Valhuntir wintools-mcp watchdog -- restarts server if unresponsive" -ErrorAction Stop | Out-Null

                Write-Ok "Watchdog task registered (health check every 5 minutes)"
            } catch {
                Write-Warn "Could not register watchdog task: $_"
            }
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

    # Add firewall rule -- remove ALL historical names first
    try {
        $ruleName = "Valhuntir wintools-mcp"
        foreach ($name in @("Valhuntir wintools-mcp", "ValiHuntIR wintools-mcp", "AIIR wintools-mcp")) {
            $old = Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
            if ($old) { Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue }
        }
        if ($siftIp -and $siftIp -ne "THIS_MACHINE_IP") {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -RemoteAddress $siftIp -ErrorAction Stop | Out-Null
            Write-Ok "Firewall rule added for TCP port $Port (restricted to $siftIp)"
        } else {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -RemoteAddress 127.0.0.1 -ErrorAction Stop | Out-Null
            Write-Ok "Firewall rule added for TCP port $Port (localhost only)"
            Write-Warn "IMPORTANT: Firewall restricted to localhost. For remote SIFT access, run:"
            Write-Host "  Set-NetFirewallRule -DisplayName `"$ruleName`" -RemoteAddress SIFT_IP_HERE"
        }
    } catch {
        Write-Warn "Could not add firewall rule (run as Administrator)"
        Write-Host "  Manual: netsh advfirewall firewall add rule name=`"Valhuntir wintools-mcp`" dir=in action=allow protocol=TCP localport=$Port"
    }
} else {
    Write-Ok "Generated startup script: $startupPath"
    Write-Host "  Run it to start wintools-mcp: $startupPath"
}

# =============================================================================
# Summary
# =============================================================================

Write-Header "Installation Complete"

# What didn't happen: the summary and the exit code come from these
$notFinished = @()
if (-not $Standalone) {
    if ($joinCodeValue -and -not $joinSucceeded) {
        $notFinished += "the join with SIFT didn't happen"
    }
    if ($joinSucceeded -and -not $smbMapped) {
        if ($joinData.smb_share) {
            $notFinished += "the SMB share isn't mapped"
        } else {
            $notFinished += "SIFT offered no SMB share (run 'vhir setup join-code' on SIFT to set it up)"
        }
    }
}
if ($skipServerStart -or -not $serverHealthy) {
    $notFinished += "wintools-mcp isn't running here"
}
if ($joinSucceeded) {
    # The gateway loads wintools-mcp once it answers: ask its public /health
    $gatewayView = $null
    for ($try = 1; $try -le 12; $try++) {
        try {
            $gatewayView = Invoke-RestMethod -Uri "${gatewayScheme}://${siftIp}:${siftPort}/health" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            if ($gatewayView -is [string]) { $gatewayView = $gatewayView | ConvertFrom-Json }
            if ($gatewayView.backends.'wintools-mcp'.status -eq "ok") { break }
        } catch { }
        if ($try -lt 12) { Start-Sleep -Seconds 5 }
    }
    $wintoolsView = $null
    if ($gatewayView) { $wintoolsView = $gatewayView.backends.'wintools-mcp' }
    if ($wintoolsView -and $wintoolsView.status -eq "ok") {
        Write-Ok "The SIFT gateway reaches wintools-mcp"
    } else {
        $why = "no answer from ${gatewayScheme}://${siftIp}:${siftPort}/health"
        if ($wintoolsView -and $wintoolsView.error) { $why = "$($wintoolsView.error)" }
        elseif ($gatewayView) { $why = "the gateway doesn't list wintools-mcp" }
        Write-Warn "The SIFT gateway can't use wintools-mcp: $why"
        $notFinished += "the SIFT gateway can't use wintools-mcp"
    }
}

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
Write-Host "  Server:         ${wintoolsScheme}://localhost:$Port"
Write-Host "  Health check:   ${wintoolsScheme}://localhost:$Port/health"
Write-Host "  MCP endpoint:   ${wintoolsScheme}://localhost:$Port/mcp"
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
    Write-Host "  Mode:           Valhuntir-integrated (SMB to SIFT)"
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
        Write-Host "        url: `"${wintoolsScheme}://${localIp}:${Port}/mcp`""
        Write-Host "        bearer_token: `"$wintoolsApiKey`""
        Write-Host "        enabled: true"
        if (Test-Path $certPath) {
            Write-Host "        tls_cert: `"~/.vhir/tls/wintools-cert.pem`""
        }
        Write-Host ""
        if (Test-Path $snippetPath) {
            Write-Host "  Snippet saved to: $snippetPath" -ForegroundColor White
        }
    } else {
        Write-Host "  Add to your SIFT gateway.yaml:" -ForegroundColor White
        Write-Host "    backends:"
        Write-Host "      wintools-mcp:"
        Write-Host "        type: http"
        Write-Host "        url: `"${wintoolsScheme}://${localIp}:${Port}/mcp`""
        Write-Host "        enabled: true"
        if (Test-Path $certPath) {
            Write-Host "        tls_cert: `"~/.vhir/tls/wintools-cert.pem`""
        }
    }
    Write-Host ""
    Write-Host "  Once configured, clients access wintools via the gateway at:" -ForegroundColor White
    Write-Host "    http://SIFT_IP:4508/mcp/wintools-mcp" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  No direct connection to the Windows VM needed from client machines." -ForegroundColor White
    Write-Host ""
}

if ($Standalone -or -not $joinSucceeded) {
    # Only show manual LLM config when join didn't handle it automatically
    Write-Host "--- LLM Client Configuration ---" -ForegroundColor White
    Write-Host ""
    Write-Host "  On the analyst machine, run:" -ForegroundColor White
    if ($Standalone) {
        Write-Host "    vhir setup client --windows=${localIp}:${Port}" -ForegroundColor Gray
    } else {
        Write-Host "    vhir setup client --sift=SIFT_IP:4508 --windows=${localIp}:${Port}" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  Or add to .mcp.json manually:" -ForegroundColor White
    Write-Host "    {" -ForegroundColor Gray
    Write-Host "      `"mcpServers`": {" -ForegroundColor Gray
    Write-Host "        `"wintools-mcp`": {" -ForegroundColor Gray
    Write-Host "          `"type`": `"http`"," -ForegroundColor Gray
    if ($wintoolsApiKey) {
        Write-Host "          `"url`": `"${wintoolsScheme}://${localIp}:${Port}/mcp`"," -ForegroundColor Gray
        Write-Host "          `"headers`": {" -ForegroundColor Gray
        Write-Host "            `"Authorization`": `"Bearer $wintoolsApiKey`"" -ForegroundColor Gray
        Write-Host "          }" -ForegroundColor Gray
    } else {
        Write-Host "          `"url`": `"${wintoolsScheme}://${localIp}:${Port}/mcp`"" -ForegroundColor Gray
    }
    Write-Host "        }" -ForegroundColor Gray
    Write-Host "      }" -ForegroundColor Gray
    Write-Host "    }" -ForegroundColor Gray
    Write-Host ""
}

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
    if ($missingCount -gt 0) {
        Write-Host "  1. Install $missingCount missing forensic tool(s)" -ForegroundColor White
        Write-Host "     See: $overviewPath" -ForegroundColor Gray
    }
    Write-Host "  2. Create a case directory:" -ForegroundColor White
    Write-Host "     mkdir $caseDir\INC-2026-0001" -ForegroundColor Gray
    Write-Host "  3. Set the active case:" -ForegroundColor White
    Write-Host "     set VHIR_CASE_DIR=$caseDir\INC-2026-0001" -ForegroundColor Gray
    Write-Host "  4. Configure your LLM client:" -ForegroundColor White
    Write-Host "     vhir setup client --windows=${localIp}:${Port}" -ForegroundColor Gray
    Write-Host "  5. Start investigating" -ForegroundColor White
} elseif ($joinSucceeded) {
    if ($missingCount -gt 0) {
        Write-Host "  1. Install $missingCount missing forensic tool(s)" -ForegroundColor White
        Write-Host "     See: $overviewPath" -ForegroundColor Gray
    }
    Write-Host "  2. Start investigating (from SIFT or any configured LLM client)" -ForegroundColor White
    Write-Host ""
    if ($smbMapped) {
        Write-Host "  SMB share mapped and gateway registered. Case activation" -ForegroundColor Gray
        Write-Host "  is handled automatically when you init/activate a case." -ForegroundColor Gray
    } else {
        Write-Host "  Gateway registered, but the SMB share is NOT mapped (see the warning above)." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  If you need an LLM client on this Windows machine:" -ForegroundColor Gray
    Write-Host "     vhir setup client --sift=${siftIp}:${siftPort} --windows=${localIp}:${Port}" -ForegroundColor Gray
} else {
    if ($missingCount -gt 0) {
        Write-Host "  1. Install $missingCount missing forensic tool(s)" -ForegroundColor White
        Write-Host "     See: $overviewPath" -ForegroundColor Gray
    }
    Write-Host "  2. Complete SIFT gateway registration:" -ForegroundColor White
    Write-Host "     Re-run this installer with a valid join code, or register manually" -ForegroundColor Gray
    Write-Host "  3. Configure your LLM client (on SIFT or analyst machine):" -ForegroundColor White
    Write-Host "     vhir setup client --sift=SIFT_IP:4508 --windows=${localIp}:${Port}" -ForegroundColor Gray
    Write-Host "  4. Start investigating" -ForegroundColor White
}
Write-Host ""
if ($Standalone -and $startChoice -eq "1" -and $serverHealthy -and -not $skipServerStart) {
    Write-Host "  Note: VHIR_CASE_DIR is set per case and must be updated when" -ForegroundColor Yellow
    Write-Host "  switching cases. If using auto-start (scheduled task), set it" -ForegroundColor Yellow
    Write-Host "  as a Machine-level environment variable:" -ForegroundColor Yellow
    Write-Host "    [Environment]::SetEnvironmentVariable(`"VHIR_CASE_DIR`", `"$caseDir\INC-2026-0001`", `"Machine`")" -ForegroundColor Gray
    Write-Host "  Or restart wintools-mcp manually after changing cases." -ForegroundColor Yellow
    Write-Host ""
}
Write-Host ""
if ($notFinished.Count -gt 0) {
    Write-Warn ("Not finished: " + ($notFinished -join "; "))
    exit 2
}
