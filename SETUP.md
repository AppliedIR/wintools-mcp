# wintools-mcp Setup Guide

## Prerequisites

- **Python 3.10+** — [python.org/downloads](https://www.python.org/downloads/)
- **Git** — [git-scm.com](https://git-scm.com/)
- **.NET Runtime** — Required for Zimmerman tools. [dotnet.microsoft.com](https://dotnet.microsoft.com/download)

## Step 1: Install

```powershell
git clone https://github.com/AppliedIR/wintools-mcp.git
cd wintools-mcp
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[fk,dev]"
```

The `[fk]` extra installs [forensic-knowledge](https://github.com/AppliedIR/forensic-knowledge) for artifact caveats and corroboration.

## Step 2: Scan for Forensic Tools

```powershell
python -m wintools_mcp --scan
```

This checks common paths for all cataloged tools and reports what's installed vs missing.

### Installing Missing Tools

**Zimmerman Suite** (recommended — all 14 tools):
```powershell
# Via dotnet (individual tools)
dotnet tool install --global MFTECmd
dotnet tool install --global EvtxECmd
dotnet tool install --global PECmd
# ... or download the full suite:
# https://ericzimmerman.github.io/#!index.md
```

**Hayabusa** (Sigma-based EVTX analysis):
```powershell
# Download from GitHub releases
# https://github.com/Yamato-Security/hayabusa/releases
# Extract to C:\Tools\Hayabusa\
```

The tool scan output includes install commands and download URLs for each missing tool.

## Step 3: Configure

### Option A: Stdio Mode (local LLM client on this machine)

Add to your MCP client configuration (`.mcp.json` for Claude Code):

```json
{
  "mcpServers": {
    "wintools-mcp": {
      "command": "C:\\path\\to\\wintools-mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "wintools_mcp"],
      "env": {
        "AIIR_EXAMINER": "steve"
      }
    }
  }
}
```

### Option B: Remote Mode (serve to SIFT gateway)

For multi-machine setups where the LLM runs on a SIFT workstation and tools run on Windows:

1. Start wintools-mcp in HTTP mode (when available)
2. Configure the SIFT gateway to connect to this machine

The `aiir-gateway` config entry:
```yaml
wintools-mcp:
  type: http
  url: "http://windows-workstation:4624/mcp"
  bearer_token: "${WINTOOLS_TOKEN}"
  enabled: true
```

### Connecting to a Case Share

If cases are stored on a shared filesystem (NFS/SMB from SIFT):

```powershell
# Map the share
net use Z: \\sift-workstation\cases

# Set per-case
set AIIR_CASE_DIR=Z:\INC-2026-0001
```

When `AIIR_CASE_DIR` is set, audit entries are written to `examiners\{examiner}\audit\wintools-mcp.jsonl`.

## Step 4: Verify

```powershell
# Check Python module loads
python -c "from wintools_mcp.server import create_server; print('wintools-mcp: ready')"

# Scan for tools
python -m wintools_mcp --scan

# Run a quick test (if MFTECmd is installed)
python -c "
from wintools_mcp.catalog import load_catalog
cat = load_catalog()
print(f'Catalog: {len(cat)} tools loaded')
"
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
