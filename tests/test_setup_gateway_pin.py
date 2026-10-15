"""The installer joins a gateway that answers over HTTPS with its own CA,
which Windows doesn't trust, by pinning the certificate's SHA-256 that
`vhir setup join-code` printed (-GatewayCertSha256).

Each row runs the installer's own gateway probe, join call and post-join
check under PowerShell against a stand-in gateway on loopback, with a
throwaway self-signed certificate. A pin that matches connects; one that
doesn't is refused before anything is sent, with no fallback to http; with
no pin the installer does what it did before, and a certificate it can't
trust is named. `sudo` and `systemctl` stand-ins come first on PATH and must
never run. Values are synthetic.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import json
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
function Mask-ApiKey { param($k) "vhir_wt_...." }
function Read-YesNo { param($q, $d) Ev "prompt:$q"; return $d }
function Read-Prompt { param($q, $d) Ev "prompt:$q"; return $d }
function Start-Sleep { param($Seconds, $Milliseconds) Ev "sleep:$Seconds" }
function Test-Connection { param($ComputerName, $Count, [switch]$Quiet, $ErrorAction) $true }
function Invoke-WebRequest { param($Uri, $Method, $ContentType, $Body, $TimeoutSec,
        [switch]$UseBasicParsing, $ErrorAction)
    Ev "iwr:$Uri"
    Microsoft.PowerShell.Utility\Invoke-WebRequest @PSBoundParameters }
function Invoke-RestMethod { param($Uri, $TimeoutSec, [switch]$UseBasicParsing, $ErrorAction)
    Ev "irm:$Uri"
    Microsoft.PowerShell.Utility\Invoke-RestMethod @PSBoundParameters }
$ErrorActionPreference = "Stop"
"""
STUB = '#!/bin/sh\necho "$0 $*" >> "{log}"\nexit 1\n'
PIN_HELPERS = ("ConvertTo-GatewayPin", "Invoke-VhirGateway", "Test-TlsTrustFailure")
MISMATCH = "The SIFT gateway's certificate isn't the one join-code printed"


def _between(start: str, end: str) -> str:
    i = TEXT.index(start)
    return TEXT[i : TEXT.index(end, i)]


def _function(name: str) -> str:
    return _between(f"function {name} {{", "\n}\n") + "\n}\n"


def _pin_helpers() -> str:
    """The installer's pin helpers (none before the pin existed)."""
    return "".join(_function(n) for n in PIN_HELPERS if f"function {n} {{" in TEXT)


def _flow() -> str:
    """The installer's gateway probe, join call and post-join check, in order."""
    probe = _between(
        "    # Reachability check with diagnostics and retry",
        "    # --- TLS Certificate Generation ---",
    )
    join = _between("    # Join API call", "    # Drive mapping")
    health = _between(
        "if ($joinSucceeded) {\n    # The gateway loads wintools-mcp",
        "if ($skipServerStart) {\n    Write-Warn",
    )
    return probe + join + health


def _cert(folder: Path) -> tuple[Path, Path, str]:
    """A self-signed cert for 127.0.0.1, its key, and its DER's SHA-256."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "stand-in gateway")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = folder / "gw-cert.pem", folder / "gw-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return cert_path, key_path, hashlib.sha256(der).hexdigest()


HEALTH = {"status": "ok", "backends": {"wintools-mcp": {"status": "ok", "tools": 10}}}
JOINED = {"gateway_token": "vhir_gw_" + "b" * 24}


class Gateway:
    """A stand-in gateway on loopback, over TLS unless ``tls`` is False. It
    records every request it reads: method, path and body."""

    def __init__(self, folder: Path, tls: bool = True, join_status: int = 200):
        self.requests: list[tuple[str, str, str]] = []
        self.fingerprint = ""
        requests = self.requests

        class Handler(BaseHTTPRequestHandler):
            def _answer(self, body: dict, status: int = 200) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802
                requests.append(("GET", self.path, ""))
                self._answer(HEALTH)

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                requests.append(("POST", self.path, self.rfile.read(n).decode()))
                if join_status == 200:
                    self._answer(JOINED)
                else:
                    self._answer({"error": "invalid join code"}, join_status)

            def log_message(self, *args):
                pass

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass  # a refused handshake or a plain-http probe of the TLS port

        self.server = Server(("127.0.0.1", 0), Handler)
        if tls:
            cert, key, self.fingerprint = _cert(folder)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            plain = self.server.get_request

            def get_request():
                sock, addr = plain()
                return ctx.wrap_socket(
                    sock, server_side=True, do_handshake_on_connect=False
                ), addr

            self.server.get_request = get_request
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def _run(
    tmp_path, gw: Gateway, pin: str, extra: str = "", flow: str | None = None
) -> tuple[int, str, list[str]]:
    events = tmp_path / "events.txt"
    events.write_text("")
    stubs = tmp_path / "bin"
    stubs.mkdir(exist_ok=True)
    calls = tmp_path / "calls.log"
    for name in ("sudo", "systemctl"):
        (stubs / name).write_text(STUB.format(log=calls))
        (stubs / name).chmod(0o755)
    pre = (
        f"$siftIp = '127.0.0.1'; $siftPort = '{gw.port}'; $GatewayCertSha256 = '{pin}'\n"
        "$NonInteractive = $true; $staticResult = $null; $gatewayScheme = 'http'\n"
        "$gatewayReachable = $false; $joinSucceeded = $false; $notFinished = @()\n"
        "$joinCodeValue = 'ABCD-EFGH'; $wintoolsScheme = 'https'; $localIp = '10.0.1.94'\n"
        "$Port = 4624; $certPath = '/nonexistent/cert.pem'; $wintoolsApiKey = ''\n"
    )
    post = (
        '\nWrite-Host "REACHABLE=$gatewayReachable JOINED=$joinSucceeded '
        'SCHEME=$gatewayScheme"\n'
    )
    script = tmp_path / "row.ps1"
    script.write_text(
        HELPERS + _pin_helpers() + pre + extra + (flow or _flow()) + post,
        encoding="utf-8",
    )
    env = {
        "PATH": f"{stubs}:/usr/bin:/bin",
        "HOME": str(tmp_path),
        "EVENTS": str(events),
        "POWERSHELL_TELEMETRY_OPTOUT": "1",
        "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
    }
    with gw:
        p = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )
    assert not calls.exists(), calls.read_text()
    return p.returncode, p.stdout + p.stderr, events.read_text().splitlines()


def _colons_upper(fp: str) -> str:
    return ":".join(fp[i : i + 2] for i in range(0, 64, 2)).upper()


@pytest.mark.parametrize("form", ["as-printed", "colons-and-upper-case"])
def test_the_pin_join_code_printed_connects_joins_and_checks_over_https(tmp_path, form):
    gw = Gateway(tmp_path)
    pin = gw.fingerprint if form == "as-printed" else _colons_upper(gw.fingerprint)
    rc, out, events = _run(tmp_path, gw, pin)
    assert rc == 0, out
    assert "REACHABLE=True JOINED=True SCHEME=https" in out, out
    assert f"Connected to SIFT gateway at https://127.0.0.1:{gw.port}" in out
    assert "Registered with SIFT gateway via join API" in out
    assert "The SIFT gateway reaches wintools-mcp" in out
    assert [r[:2] for r in gw.requests] == [
        ("GET", "/health"),
        ("POST", "/api/v1/setup/join"),
        ("GET", "/health"),
    ]
    assert json.loads(gw.requests[1][2])["code"] == "ABCD-EFGH"
    # every call went through the pinned client: none through the cmdlets
    assert not [e for e in events if e.startswith(("iwr:", "irm:"))], events


# Asked interactively, a retry prompt answered "skip" would end the loop too:
# the refusal must end it before any prompt
INTERACTIVE = (
    "$NonInteractive = $false\n"
    'function Read-Prompt { param($q, $d) Ev "prompt:$q"; return "skip" }\n'
)


@pytest.mark.parametrize("mode", ["non-interactive", "interactive"])
def test_a_wrong_pin_is_refused_with_both_fingerprints_and_nothing_is_sent(
    tmp_path, mode
):
    gw = Gateway(tmp_path)
    wrong = "0" * 64
    extra = INTERACTIVE if mode == "interactive" else ""
    rc, out, events = _run(tmp_path, gw, wrong, extra)
    assert rc == 0, out
    assert (
        f"ERR {MISMATCH} (expected {wrong}, got {gw.fingerprint}). "
        "Re-run `vhir setup join-code` on the SIFT and use its command."
    ) in out, out
    assert "REACHABLE=False JOINED=False" in out
    assert gw.requests == []  # not even the health probe
    assert not [e for e in events if e.startswith(("iwr:", "irm:"))], events  # no http
    assert not [e for e in events if e.startswith("prompt:")], events  # no retry


def test_with_no_pin_an_untrusted_certificate_is_named_and_the_one_liner_asked_for(
    tmp_path,
):
    """Today's path: https, then http. Neither works against a CA the machine
    doesn't trust, and the cause is now said."""
    gw = Gateway(tmp_path)
    rc, out, events = _run(tmp_path, gw, "")
    assert rc == 0, out
    assert "REACHABLE=False JOINED=False" in out
    assert [e for e in events if e.startswith("iwr:")] == [
        f"iwr:https://127.0.0.1:{gw.port}/health",
        f"iwr:http://127.0.0.1:{gw.port}/health",
    ]
    assert "Port is open but HTTP health check failed" in out
    assert "a certificate this machine doesn't trust" in out
    assert "re-run with the one-liner 'vhir setup join-code' printed" in out.lower()
    assert gw.requests == []


def test_with_no_pin_an_http_gateway_joins_as_before(tmp_path):
    gw = Gateway(tmp_path, tls=False)
    rc, out, events = _run(tmp_path, gw, "")
    assert rc == 0, out
    assert "REACHABLE=True JOINED=True SCHEME=http" in out, out
    assert [r[:2] for r in gw.requests] == [
        ("GET", "/health"),
        ("POST", "/api/v1/setup/join"),
        ("GET", "/health"),
    ]
    assert "certificate" not in out
    assert events[:2] == [
        f"iwr:https://127.0.0.1:{gw.port}/health",
        f"iwr:http://127.0.0.1:{gw.port}/health",
    ]


@pytest.mark.parametrize(
    "value", ["abc", "g" * 64, "0" * 63, "0" * 65], ids=["short", "not-hex", "63", "65"]
)
def test_a_pin_that_is_not_64_hex_digits_stops_the_installer_at_the_start(
    tmp_path, value
):
    check = _between(
        'if ($GatewayPort) { Validate-Port $GatewayPort "GatewayPort" }',
        "# =============================================================================\n# Uninstall",
    )
    script = tmp_path / "row.ps1"
    script.write_text(
        HELPERS
        + _pin_helpers()
        + _function("Validate-Port")
        + f"$GatewayPort = 4508; $GatewayCertSha256 = '{value}'\n"
        + check
        + '\nWrite-Host "PAST-THE-CHECK"\n',
        encoding="utf-8",
    )
    p = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "EVENTS": "/dev/null"},
    )
    out = p.stdout + p.stderr
    assert p.returncode == 1, out
    assert "PAST-THE-CHECK" not in out
    assert "-GatewayCertSha256 must be the 64 hex digits" in out, out


def test_the_parameter_is_declared_and_in_the_help():
    assert "[string]$GatewayCertSha256 = " in TEXT
    help_text = TEXT[: TEXT.index("[CmdletBinding()]")]
    assert ".PARAMETER GatewayCertSha256" in help_text


def _join_only() -> str:
    return _between("    # Join API call", "    # Drive mapping")


def test_a_certificate_that_changed_after_the_probe_stops_the_join_unsent(tmp_path):
    """The probe matched; by the join call the gateway shows another cert."""
    gw = Gateway(tmp_path)
    wrong = "f" * 64
    rc, out, _ = _run(tmp_path, gw, wrong, "$gatewayReachable = $true\n", _join_only())
    assert rc == 0, out
    assert f"ERR {MISMATCH} (expected {wrong}, got {gw.fingerprint})." in out, out
    assert gw.requests == []
    assert "may or may not have been stored" not in out  # nothing was sent
    assert "JOINED=False" in out


def test_a_refused_join_code_is_named_through_the_pinned_client(tmp_path):
    gw = Gateway(tmp_path, join_status=403)
    rc, out, _ = _run(
        tmp_path, gw, gw.fingerprint, "$gatewayReachable = $true\n", _join_only()
    )
    assert rc == 0, out
    assert "Join failed: invalid, expired, or already-used join code" in out, out
    assert [r[:2] for r in gw.requests] == [("POST", "/api/v1/setup/join")]
    assert "JOINED=False" in out
