"""Entry point: python -m wintools_mcp"""

import argparse
import sys

from wintools_mcp.config import WintoolsConfig
from wintools_mcp.oplog import setup_logging
from wintools_mcp.server import create_server


def main():
    setup_logging("wintools-mcp")
    parser = argparse.ArgumentParser(description="Windows Forensic MCP Server")
    parser.add_argument(
        "--http", action="store_true", help="Enable REST HTTP server"
    )
    parser.add_argument(
        "--port", type=int, default=4624, help="HTTP port (default: 4624)"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="HTTP bind address"
    )
    parser.add_argument("--config", help="Path to YAML config file")
    parser.add_argument(
        "--stdio",
        action="store_true",
        help="Enable MCP stdio (default when --http not set)",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan for installed tools and exit",
    )
    args = parser.parse_args()

    config = WintoolsConfig.from_env(config_file=args.config)

    if args.scan:
        from wintools_mcp.inventory import print_scan_report

        print(print_scan_report(config.tool_paths or None))
        return

    config.http_host = args.host
    config.http_port = args.port

    if args.http:
        import uvicorn
        from wintools_mcp.http_server import create_http_app

        app = create_http_app(config)
        uvicorn.run(app, host=config.http_host, port=config.http_port)
    else:
        server = create_server(config)
        server.run()


if __name__ == "__main__":
    main()
