# wintools-mcp Setup Guide

## Security Warning

wintools-mcp opens an HTTP endpoint that allows connected LLM clients to execute forensic tools on this system. **This creates attack vectors where malicious actors could run arbitrary code through the MCP interface.**

This system MUST be:
- A **dedicated forensic workstation**, not a personal laptop or production system
- **Isolated behind firewalls** on a trusted network segment with no inbound Internet access
- Free of sensitive data outside the scope of the current investigation
- A system you are willing to rebuild if compromised

Any data on this system may be transmitted to the configured AI provider. Never place original evidence on this system. Only use working copies.

The installer requires you to type `security_hole` before proceeding, or pass `-AcknowledgeSecurityHole` for scripted installations. This is an intentional friction point to ensure the operator understands the risk.

## Prerequisites

- **Python 3.10+** — [python.org/downloads](https://www.python.org/downloads/)
- **Git** — [git-scm.com](https://git-scm.com/)
- **.NET Runtime** — Required for Zimmerman tools. [dotnet.microsoft.com](https://dotnet.microsoft.com/download)

## Automated Install

The recommended approach uses the installer script:

```powershell
git clone https://github.com/AppliedIR/wintools-mcp.git; cd wintools-mcp
.\scripts\setup-windows.ps1
```

The installer runs 7 phases: prerequisites, install, examiner identity, tool scan, case directory setup, MCP server start, and auto-start configuration.

### Installer Modes

**AIIR-integrated (default)** — Full platform integration with a SIFT workstation. Case directory accessed via SMB share. Audit trail, evidence, and tool output written to the shared case directory.

```powershell
.\setup-windows.ps1
```

**Standalone** — Independent operation without a SIFT workstation. Case directory and audit trail stored locally on this machine.

```powershell
.\setup-windows.ps1 -Standalone
```

### Installer Switches

| Switch | Description |
|--------|-------------|
| `-AcknowledgeSecurityHole` | Bypass the interactive security prompt (required for `-NonInteractive`) |
| `-Standalone` | Local case directory instead of SMB to SIFT |
| `-NonInteractive` | No prompts, use defaults for all options |
| `-InstallDir PATH` | Installation directory (default: `C:\Tools\aiir`) |
| `-Examiner NAME` | Examiner slug (default: Windows username) |
| `-Port PORT` | HTTP server port (default: 4624) |
| `-BindAddress ADDR` | HTTP bind address (default: 0.0.0.0) |
| `-StaticIP ADDR` | Static IP for this machine (skips prompt) |
| `-NoAuth` | Skip API key generation (development only) |

### Scripted Examples

```powershell
# Non-interactive AIIR install
.\setup-windows.ps1 -NonInteractive -AcknowledgeSecurityHole

# Non-interactive standalone
.\setup-windows.ps1 -Standalone -NonInteractive -AcknowledgeSecurityHole

# Custom directory, examiner, and port
.\setup-windows.ps1 -InstallDir "D:\Forensics\aiir" -Examiner "steve" -Port 8443 -AcknowledgeSecurityHole
```

## Manual Install

```powershell
git clone https://github.com/AppliedIR/wintools-mcp.git
cd wintools-mcp
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[fk,dev]"
```

The `[fk]` extra installs [forensic-knowledge](https://github.com/AppliedIR/sift-mcp/tree/main/packages/forensic-knowledge) for artifact caveats and corroboration.

## Deployment Architectures

### Architecture 1: Solo Analyst (Standalone)

One Windows VM with forensic tools, wintools-mcp, and the LLM client all on the same machine.

```
+----------------------------------------------+
|  Windows Forensic VM                         |
|                                              |
|  LLM Client (Claude Code, Cursor, etc.)     |
|       |                                      |
|       v                                      |
|  wintools-mcp :4624                          |
|       |                                      |
|  Forensic Tools (Zimmerman, Hayabusa, etc.)  |
|                                              |
|  C:\Tools\aiir\cases\INC-2026-0001\          |
+----------------------------------------------+
```

Setup:
```powershell
.\setup-windows.ps1 -Standalone
# Case dir is local. No SMB needed.
set AIIR_CASE_DIR=C:\Tools\aiir\cases\INC-2026-0001
```

### Architecture 2: SIFT + Windows (Typical)

SIFT workstation for Linux forensics and case management. Windows VM for Windows-specific tools. LLM client on the SIFT machine (or a separate analyst workstation) connects to both.

```
+---------------------------+      +---------------------------+
|  SIFT Workstation         |      |  Windows Forensic VM      |
|                           |      |                           |
|  LLM Client               |----->|  wintools-mcp :4624      |
|  aiir CLI                 |      |  Forensic Tools           |
|  sift-gateway :4508       |      |       |                   |
|  forensic-mcp (stdio)     |      |       | SMB               |
|  sift-mcp (stdio)         |      |       v                   |
|  forensic-rag-mcp (stdio) |      |  \\SIFT\cases (mapped)   |
|                           |      +---------------------------+
|  /cases/INC-2026-0001/    |
+---------------------------+
```

Setup:
```powershell
# On SIFT:
./sift-install.sh

# On Windows:
.\setup-windows.ps1

# Map the SIFT share on Windows:
net use Z: \\192.168.1.10\cases /persistent:yes

# Set case dir:
set AIIR_CASE_DIR=Z:\INC-2026-0001

# Configure LLM client (on SIFT or analyst machine):
aiir setup client --sift=192.168.1.10:4508 --windows=192.168.1.20:4624
```

### Architecture 3: Remote Analyst

LLM client and aiir CLI on a separate analyst workstation. SIFT and Windows VMs run headless.

```
+--------------------+      +--------------------+      +--------------------+
|  Analyst Machine   |      |  SIFT Workstation  |      |  Windows VM        |
|                    |      |                    |      |                    |
|  LLM Client       |----->|  gateway :4508     |      |  wintools :4624    |
|  aiir CLI          |----->|  MCPs (stdio)      |      |  Forensic Tools    |
|                    |  |   |  /cases/           |<-----|  SMB               |
|                    |  |   +--------------------+      +--------------------+
|                    |  |
|                    |  +-->  wintools :4624 (direct)
+--------------------+
```

Setup:
```powershell
# On SIFT:
./sift-install.sh --remote

# On Windows:
.\setup-windows.ps1

# On analyst machine:
pip install aiir
aiir setup client --sift=SIFT_IP:4508 --windows=WIN_IP:4624
```

### Architecture 4: Multi-Examiner Team

Multiple examiners, each with their own SIFT + Windows setup. Each examiner maintains a local case directory. Collaboration uses a merge-based workflow: examiners export contribution bundles and import each other's work.

```
+--------------------+      +--------------------+
|  Examiner: steve   |      |  Examiner: jane    |
|  SIFT + Windows    |      |  SIFT + Windows    |
|  Local case dir    |      |  Local case dir    |
|  findings.json     |      |  findings.json     |
|  timeline.json     |      |  timeline.json     |
|  audit/            |      |  audit/            |
+--------+-----------+      +--------+-----------+
         |                           |
         +--- export/import ---------+
         |   (JSON bundles)          |
         v                           v
```

Each examiner works independently in their own flat case directory. To share findings, use `aiir sync export` to create a contribution bundle and `aiir sync import` to merge another examiner's contributions. This avoids the complexity of shared filesystems and locking.

## Case Directory Setup

### AIIR Mode (SMB to SIFT)

The case directory lives on the SIFT workstation and is shared via Samba.

**On SIFT:**
```bash
# Create and share the cases directory
sudo mkdir -p /cases
sudo chown $USER:forensics /cases

# Option A: Samba (recommended for Windows)
# Add to /etc/samba/smb.conf:
#   [cases]
#       path = /cases
#       browsable = yes
#       writable = yes
#       valid users = @forensics
sudo systemctl restart smbd

# Option B: net usershare (simpler, single user)
sudo net usershare add cases /cases
```

**On Windows:**
```powershell
# Map the share (persistent across reboots)
net use Z: \\SIFT_IP\cases /persistent:yes

# Set the active case
set AIIR_CASE_DIR=Z:\INC-2026-0001
```

When `AIIR_CASE_DIR` is set, wintools-mcp writes audit entries to `audit\wintools-mcp.jsonl` within the case directory. This is the same layout that SIFT MCPs use, creating a unified audit trail.

### Standalone Mode (Local)

In standalone mode, cases are stored locally:

```powershell
# Default location (set during install)
set AIIR_CASE_DIR=C:\Tools\aiir\cases\INC-2026-0001

# Create case structure
mkdir C:\Tools\aiir\cases\INC-2026-0001
```

The audit directory is created automatically when wintools-mcp receives its first tool call with `AIIR_CASE_DIR` set.

## Starting the Server

### HTTP Mode (production, serves to remote clients)

```powershell
python -m wintools_mcp --http --host 0.0.0.0 --port 4624
```

Health check: `http://localhost:4624/health`
MCP endpoint: `http://localhost:4624/mcp`

### Stdio Mode (local LLM client on same machine)

```powershell
python -m wintools_mcp
```

Add to `.mcp.json`:
```json
{
  "mcpServers": {
    "wintools-mcp": {
      "command": "C:\\path\\to\\.venv\\Scripts\\python.exe",
      "args": ["-m", "wintools_mcp"],
      "env": {
        "AIIR_EXAMINER": "steve"
      }
    }
  }
}
```

### Scan-Only Mode (check installed tools)

```powershell
python -m wintools_mcp --scan
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WINTOOLS_TIMEOUT` | `600` | Default command timeout in seconds |
| `WINTOOLS_HOST` | `127.0.0.1` | HTTP server bind address |
| `WINTOOLS_PORT` | `4624` | HTTP server port |
| `WINTOOLS_TOOL_PATHS` | (none) | Additional binary search directories (semicolon-separated) |
| `WINTOOLS_CATALOG_DIR` | (auto) | Override catalog YAML directory |
| `AIIR_CASE_DIR` | (none) | Active case directory for audit trail |
| `AIIR_EXAMINER` | OS user | Examiner identity (lowercase slug) |

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError: wintools_mcp` | Not installed in active venv | Run `pip install -e .` in wintools-mcp directory |
| Tool scan finds 0 tools | Tools not in expected paths | Set `WINTOOLS_TOOL_PATHS` or install tools to `C:\Tools` |
| `ToolNotInCatalogError` | Binary not in catalog YAML | Only cataloged tools can be executed; check `data/catalog/` |
| `DeniedBinaryError` | Blocked binary (cmd, powershell, etc.) | These are unconditionally blocked for security |
| Timeout errors | Tool takes too long | Increase `WINTOOLS_TIMEOUT` or per-tool timeout |
| Missing forensic-knowledge | Installed without `[fk]` extra | Run `pip install -e ".[fk]"` |
| SMB share not accessible | Firewall or credentials | Check `net use` status; verify SIFT Samba config |
| Audit entries not recorded | `AIIR_CASE_DIR` not set | Set `AIIR_CASE_DIR` to active case path |
| Health check fails | Port conflict or bind error | Check if another process uses port 4624 |
