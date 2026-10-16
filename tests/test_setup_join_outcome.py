"""The installer says what its join and server start actually did.

Each row runs the installer's own lines under PowerShell, with stand-ins for
the Windows-only cmdlets, the network calls and the SIFT gateway's answers.
`sudo` and `systemctl` stand-ins come first on PATH and must never run.
PowerShell 7 on Linux isn't Windows PowerShell 5.1: the certificate's SAN
text differs between them, and both forms are checked.
"""

from __future__ import annotations

import datetime
import ipaddress
import shutil
import socket
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "setup-windows.ps1"
TEXT = SCRIPT.read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="PowerShell isn't installed"
)

HELPERS = r"""
function Ev { param($e) Add-Content -Path $env:EVENTS -Value $e }
function Write-Ok { param($m) Write-Host "OK $m" }
function Write-Info { param($m) Write-Host "INFO $m" }
function Write-Warn { param($m) Write-Host "WARN $m" }
function Write-Err { param($m) Write-Host "ERR $m" }
function Write-Header { param($m) Write-Host "== $m ==" }
function Mask-ApiKey { param($k) "vhir_wt_...." }
function Read-YesNo { param($q, $d) Ev "prompt:$q"; return $d }
function Read-Prompt { param($q, $d) Ev "prompt:$q"; return $d }
function Start-Sleep { param($Seconds, $Milliseconds) Ev "sleep:$Seconds" }
"""
STUB = '#!/bin/sh\necho "$0 $*" >> "{log}"\nexit 1\n'


def _between(start: str, end: str | None, nth: int = 1) -> str:
    i = -1
    for _ in range(nth):
        i = TEXT.index(start, i + 1)
    return TEXT[i:] if end is None else TEXT[i : TEXT.index(end, i)]


def _run(tmp_path, body: str, pre: str = "") -> tuple[int, str, list[str]]:
    events = tmp_path / "events.txt"
    events.write_text("")
    stubs = tmp_path / "bin"
    stubs.mkdir(exist_ok=True)
    calls = tmp_path / "calls.log"
    for name in ("sudo", "systemctl"):
        (stubs / name).write_text(STUB.format(log=calls))
        (stubs / name).chmod(0o755)
    script = tmp_path / "row.ps1"
    script.write_text(HELPERS + pre + "\n" + body + "\n", encoding="utf-8")
    env = {
        "PATH": f"{stubs}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "EVENTS": str(events),
        "POWERSHELL_TELEMETRY_OPTOUT": "1",
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
    }
    p = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    assert not calls.exists(), calls.read_text()
    return p.returncode, p.stdout + p.stderr, events.read_text().splitlines()


# --- the port check -------------------------------------------------------

PORT_PRE = r"""
$Port = 4624
$skipServerStart = $false
function Get-NetTCPConnection { param($LocalPort, $State, $ErrorAction)
    $all = @($env:PORT_STATES -split "," | ForEach-Object {
        [pscustomobject]@{ State = $_; OwningProcess = 0 } })
    if ($State) { $all | Where-Object { $_.State -eq $State } } else { $all } }
function Get-Process { param($Id, $ErrorAction) [pscustomobject]@{ ProcessName = "Idle" } }
"""


@pytest.mark.parametrize(
    "states, skipped",
    [("TimeWait", False), ("TimeWait,Listen", True)],
    ids=["only-time-wait", "a-listener"],
)
def test_the_port_check_counts_only_a_listener(tmp_path, states, skipped):
    pre = PORT_PRE.replace("$env:PORT_STATES", f"'{states}'")
    body = _between("# Check if port is already in use", "if (-not $skipServerStart) {")
    rc, out, _ = _run(tmp_path, body + '\nWrite-Host "SKIP=$skipServerStart"\n', pre)
    assert f"SKIP={skipped}" in out, out


# --- the watchdog's scheme ------------------------------------------------


@pytest.mark.parametrize("nth", [1, 2], ids=["update-path", "install-path"])
@pytest.mark.parametrize(
    "config, scheme",
    [
        ("http_port: 4624\n\ntls:\n  certfile: C:\\vhir\\tls\\cert.pem\n", "https"),
        ("http_port: 4624\ntls_certfile: C:\\vhir\\tls\\cert.pem\n", "https"),
        ("http_port: 4624\n", "http"),
    ],
    ids=["tls-certfile", "older-key", "no-tls"],
)
def test_the_watchdog_probes_https_when_the_config_has_a_cert(
    tmp_path, nth, config, scheme
):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(config)
    block = _between('$watchdogScheme = "http"', "\n}\n", nth) + "\n}\n"
    if nth == 1:  # inside the -Update branch, one level in
        block = _between('$watchdogScheme = "http"', "\n            }\n", nth)
        block += "\n            }\n"
    pre = f"$wintoolsConfigPath = '{cfg}'\n"
    rc, out, _ = _run(tmp_path, block + '\nWrite-Host "SCHEME=$watchdogScheme"\n', pre)
    assert f"SCHEME={scheme}" in out, (block, out)


# --- the certificate ------------------------------------------------------


def _pem_pair(folder: Path, ip: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "wintools-mcp")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("wintools-mcp"), x509.IPAddress(ipaddress.ip_address(ip))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    folder.mkdir(parents=True, exist_ok=True)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    (folder / "cert.pem").write_text(pem)
    (folder / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return pem


def _cert_step(tmp_path, local_ip: str) -> tuple[str, list[str], str]:
    tls = tmp_path / "vhir" / "tls"
    old = _pem_pair(tls, "10.0.1.138")
    pre = (
        f"$InstallDir = '{tmp_path / 'vhir'}'\n$localIp = '{local_ip}'\n"
        "function New-SelfSignedCertificate { Ev 'generate'; throw 'stand-in: stop' }\n"
    )
    body = _between('$tlsDir = Join-Path $InstallDir "tls"', "# URL scheme depends on")
    _, out, events = _run(tmp_path, body, pre)
    return old, events, out


def test_a_cert_that_does_not_name_the_address_is_kept_aside_and_made_again(tmp_path):
    old, events, out = _cert_step(tmp_path, "10.0.1.94")
    assert "generate" in events, out
    kept = list((tmp_path / "vhir").glob("tls-old-*/cert.pem"))
    assert [p.read_text() for p in kept] == [old]
    assert list((tmp_path / "vhir").glob("tls-old-*/key.pem"))
    assert not (tmp_path / "vhir" / "tls" / "cert.pem").exists()


@pytest.mark.parametrize("ip", ["10.0.1.138", "10.0.1.13"], ids=["same", "prefix"])
def test_a_cert_that_names_the_address_is_kept_in_place(tmp_path, ip):
    old, events, out = _cert_step(tmp_path, ip)
    if ip == "10.0.1.138":
        assert "generate" not in events, out
        assert (tmp_path / "vhir" / "tls" / "cert.pem").read_text() == old
        assert not list((tmp_path / "vhir").glob("tls-old-*"))
    else:  # 10.0.1.13 is a prefix of the SAN's address, not the address
        assert "generate" in events, out


@pytest.mark.parametrize(
    "san", ["IP Address=10.0.1.94", "IP Address:10.0.1.94"], ids=["5.1", "7"]
)
def test_the_san_match_reads_both_powershells_text(tmp_path, san):
    line = _between("if ($sanText -notmatch", "{")
    body = f"$sanText = 'DNS Name=wintools-mcp, {san}'\n$localIp = '10.0.1.94'\n"
    body += line + '{ Write-Host "MISMATCH" } else { Write-Host "MATCH" }\n'
    _, out, _ = _run(tmp_path, body)
    assert "MATCH" in out and "MISMATCH" not in out, out


# --- the ping after a static-IP change ------------------------------------


@pytest.mark.parametrize("static", [True, False], ids=["ip-changed", "ip-kept"])
def test_the_first_ping_is_retried_only_after_a_static_ip_change(tmp_path, static):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]
    pre = rf"""
$NonInteractive = $true
$siftIp = '127.0.0.1'; $siftPort = '{port}'
$staticResult = {"'10.0.1.94'" if static else "$null"}
$script:pings = 0
function Test-Connection {{ param($ComputerName, $Count, [switch]$Quiet, $ErrorAction)
    $script:pings++; Ev "ping:$script:pings"; return ($script:pings -gt 2) }}
function Invoke-WebRequest {{ param($Uri, $TimeoutSec, [switch]$UseBasicParsing, $ErrorAction)
    [pscustomobject]@{{ StatusCode = 200 }} }}
"""
    body = _between(
        "# Reachability check with diagnostics and retry",
        "# --- TLS Certificate Generation ---",
    )
    try:
        _, out, events = _run(
            tmp_path, body + '\nWrite-Host "OK=$gatewayReachable"\n', pre
        )
    finally:
        listener.close()
    pings = [e for e in events if e.startswith("ping:")]
    if static:
        assert pings == ["ping:1", "ping:2", "ping:3"] and "OK=True" in out, out
        assert events.count("sleep:5") == 2
    else:
        assert pings == ["ping:1"] and "OK=False" in out, out


# --- the summary and the exit code ----------------------------------------

TAIL = r"""
$Examiner = 'examiner'; $InstallDir = 'C:\vhir'; $Port = 4624; $wintoolsScheme = 'https'
$localIp = '10.0.1.94'; $siftIp = '10.0.1.91'; $siftPort = '4508'
$overviewPath = 'C:\none'; $missingCount = 0; $Standalone = $false
$serverHealthy = $true; $skipServerStart = $false; $NonInteractive = $true
$joinCodeValue = 'ABCD-EFGH'; $gatewayScheme = 'http'; $caseDir = 'C:\cases'
$startChoice = '1'; $certPath = 'C:\vhir\tls\cert.pem'; $startupPath = 'C:\vhir\start.ps1'
$joinSucceeded = $true; $smbMapped = $true
$joinData = [pscustomobject]@{ smb_share = 'vhir-cases' }
"""


def _health(answer: str | None) -> str:
    """The gateway's /health: ``answer`` as its JSON, or no answer at all."""
    if answer is None:
        return (
            "function Invoke-RestMethod { param($Uri, $TimeoutSec, "
            '[switch]$UseBasicParsing, $ErrorAction) Ev "health:$Uri"; '
            "throw 'stand-in: no answer' }\n"
        )
    return (
        "function Invoke-RestMethod { param($Uri, $TimeoutSec, "
        '[switch]$UseBasicParsing, $ErrorAction) Ev "health:$Uri"; '
        f"'{answer}' | ConvertFrom-Json }}\n"
    )


OK = '{"status":"ok","backends":{"wintools-mcp":{"status":"ok","tools":10}}}'
MISMATCH = (
    '{"status":"degraded","backends":{"wintools-mcp":{"status":"error","error":'
    '"wintools-mcp is joined but not loaded: ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED]'
    ' IP address mismatch"}}}'
)


def _summary(tmp_path, extra: str = "", health: str | None = OK):
    body = _between('Write-Header "Installation Complete"', None)
    return _run(tmp_path, body, TAIL + extra + _health(health))


def test_a_finished_install_says_the_gateway_reaches_it_and_exits_0(tmp_path):
    rc, out, events = _summary(tmp_path)
    assert rc == 0, out
    assert "The SIFT gateway reaches wintools-mcp" in out
    assert "Not finished" not in out
    assert "SMB share mapped and gateway registered" in out
    assert events.count("health:http://10.0.1.91:4508/health") == 1


@pytest.mark.parametrize(
    "extra, reason",
    [
        ("$joinSucceeded = $false\n", "the join with SIFT didn't happen"),
        ("$smbMapped = $false\n", "the SMB share isn't mapped"),
        (
            "$joinData = [pscustomobject]@{}; $smbMapped = $false\n",
            "SIFT offered no SMB share",
        ),
        ("$serverHealthy = $false\n", "wintools-mcp isn't running here"),
        ("$skipServerStart = $true\n", "wintools-mcp isn't running here"),
    ],
    ids=["no-join", "share-not-mapped", "no-share-offered", "unhealthy", "not-started"],
)
def test_an_unfinished_install_says_what_and_exits_2(tmp_path, extra, reason):
    rc, out, _ = _summary(tmp_path, extra)
    assert rc == 2, out
    assert "Not finished: " in out and reason in out, out


def test_a_failed_mapping_is_not_reported_as_mapped(tmp_path):
    rc, out, _ = _summary(tmp_path, "$smbMapped = $false\n")
    assert "SMB share mapped and gateway registered" not in out
    assert "the SMB share is NOT mapped" in out
    assert rc == 2


def test_the_gateways_error_for_wintools_is_printed_and_the_run_exits_2(tmp_path):
    rc, out, events = _summary(tmp_path, health=MISMATCH)
    assert rc == 2, out
    assert "The SIFT gateway can't use wintools-mcp" in out
    assert "IP address mismatch" in out
    assert "the SIFT gateway can't use wintools-mcp" in out.split("Not finished: ")[1]
    assert events.count("health:http://10.0.1.91:4508/health") == 12  # about 60 s


def test_a_gateway_that_does_not_answer_is_named_and_the_run_exits_2(tmp_path):
    rc, out, _ = _summary(tmp_path, health=None)
    assert rc == 2, out
    assert "no answer from http://10.0.1.91:4508/health" in out


# --- the manual fallback --------------------------------------------------


def test_the_manual_fallback_names_the_restart_that_loads_it():
    fallback = _between("After pasting", "Clients then access wintools")
    assert "vhir service restart wintools-mcp" in fallback
    assert "restart the gateway" not in fallback
    assert "restart_required" not in TEXT


# --- the first answer after the server starts -----------------------------

START_PRE = r"""
$skipServerStart = $false; $serverHealthy = $false; $startChoice = '1'
$Port = 4624; $BindAddress = '0.0.0.0'; $wintoolsScheme = 'http'; $Examiner = 'examiner'
$venvPython = 'python'; $wintoolsConfigPath = '/nonexistent/config.yaml'
$startupPath = 'C:\vhir\start.ps1'; $watchdogPath = 'C:\vhir\watchdog.ps1'
$global:clock = 0; $global:answerAt = ANSWER_AT; $global:exitAt = EXIT_AT
function Start-Sleep { param($Seconds, $Milliseconds) Ev "sleep:$Seconds"; $global:clock += $Seconds }
function Get-Date { [datetime]::new(2026, 1, 1).AddSeconds($global:clock) }
function Start-Process { param($FilePath, $ArgumentList, [switch]$PassThru, $WindowStyle)
    $p = [pscustomobject]@{}
    $p | Add-Member -MemberType ScriptProperty -Name HasExited -Value {
        ($global:exitAt -ge 0) -and ($global:clock -ge $global:exitAt) }
    $p }
function Invoke-WebRequest { param($Uri, $TimeoutSec, [switch]$UseBasicParsing, $ErrorAction,
    [switch]$SkipCertificateCheck)
    Ev "probe:$global:clock"
    Ev "uri:$Uri skip:$SkipCertificateCheck"
    if ($global:answerAt -ge 0 -and $global:clock -ge $global:answerAt) {
        return [pscustomobject]@{ StatusCode = 200 } }
    throw 'stand-in: connection refused' }
function Get-ScheduledTask { param($TaskName, $ErrorAction) $null }
function New-ScheduledTaskAction { param($Execute, $Argument) 'action' }
function New-ScheduledTaskTrigger { param([switch]$AtStartup, [switch]$Once, $At,
    $RepetitionInterval, $RepetitionDuration) 'trigger' }
function New-ScheduledTaskSettingsSet { param([switch]$AllowStartIfOnBatteries,
    [switch]$DontStopIfGoingOnBatteries, [switch]$StartWhenAvailable, $RestartCount,
    $RestartInterval) 'settings' }
function Register-ScheduledTask { param($TaskName, $Action, $Trigger, $Settings, $RunLevel,
    $User, $Description, $ErrorAction) Ev "register:$TaskName" }
"""


def _start(
    tmp_path, answer_at: int, exit_at: int, scheme: str = "http"
) -> tuple[str, list[int], list[str]]:
    """Start the server, then register the task: -1 means it never answers or never exits."""
    start = _between(
        'if (-not $skipServerStart) {\n    Write-Info "Starting wintools-mcp',
        "# =============================================================================\n"
        "# Auto-Start Configuration",
    )
    register = _between(
        'if ($startChoice -eq "1" -and -not $skipServerStart) {',
        "    # Add firewall rule",
    )
    pre = (
        START_PRE.replace("ANSWER_AT", str(answer_at))
        .replace("EXIT_AT", str(exit_at))
        .replace("$wintoolsScheme = 'http'", f"$wintoolsScheme = '{scheme}'")
    )
    body = start + register + "}\n" + 'Write-Host "HEALTHY=$serverHealthy"\n'
    _, out, events = _run(tmp_path, body, pre)
    probes = [int(e.split(":")[1]) for e in events if e.startswith("probe:")]
    return out, probes, events


def test_a_server_that_answers_after_17_s_is_healthy_and_its_task_registered(tmp_path):
    out, probes, events = _start(tmp_path, answer_at=17, exit_at=-1)
    assert "HEALTHY=True" in out, out
    assert "OK wintools-mcp running on port 4624 (http)" in out
    assert "register:Valhuntir wintools-mcp" in events
    assert probes == [3, 5, 7, 9, 11, 13, 15, 17]
    assert "INFO Waiting for wintools-mcp to answer (15 s)" in out
    assert "health check failed" not in out


def test_powershell_7_checks_an_https_server_without_the_5_1_policy(tmp_path):
    out, probes, events = _start(tmp_path, answer_at=5, exit_at=-1, scheme="https")
    assert "HEALTHY=True" in out, out
    assert "OK wintools-mcp running on port 4624 (https)" in out
    assert "Could not start" not in out
    assert "register:Valhuntir wintools-mcp" in events
    assert probes == [3, 5]
    uris = [e for e in events if e.startswith("uri:")]
    assert uris == ["uri:https://localhost:4624/health skip:True"] * 2, uris


def test_an_http_server_is_checked_as_before(tmp_path):
    out, probes, events = _start(tmp_path, answer_at=3, exit_at=-1)
    assert "HEALTHY=True" in out, out
    assert [e for e in events if e.startswith("uri:")] == [
        "uri:http://localhost:4624/health skip:False"
    ]


def test_a_server_that_never_answers_gets_todays_warning_after_the_deadline(tmp_path):
    out, probes, events = _start(tmp_path, answer_at=-1, exit_at=-1)
    assert "HEALTHY=False" in out, out
    assert (
        "wintools-mcp started but health check failed: stand-in: connection refused"
        in out
    )
    assert (
        "Server did not pass health check. Skipping scheduled task registration." in out
    )
    assert not [e for e in events if e.startswith("register:")]
    assert probes[0] == 3 and 90 <= probes[-1] < 93, probes
    assert all(b - a == 2 for a, b in zip(probes, probes[1:], strict=False)), probes


def test_a_server_that_exits_while_it_is_awaited_stops_the_wait_at_once(tmp_path):
    out, probes, events = _start(tmp_path, answer_at=-1, exit_at=8)
    assert "HEALTHY=False" in out, out
    assert "WARN wintools-mcp exited immediately - check configuration" in out
    assert "health check failed" not in out
    assert not [e for e in events if e.startswith("register:")]
    assert probes == [3, 5, 7, 9], probes
    assert events[-1] != "sleep:2" and events.count("sleep:2") == 3, events
