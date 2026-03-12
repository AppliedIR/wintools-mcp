"""Entry point: python -m wintools_mcp"""

import argparse

from wintools_mcp.config import get_config
from wintools_mcp.oplog import setup_logging
from wintools_mcp.server import create_server


def main():
    setup_logging("wintools-mcp")
    parser = argparse.ArgumentParser(description="Windows Forensic MCP Server")
    parser.add_argument("--http", action="store_true", help="Enable REST HTTP server")
    parser.add_argument(
        "--port", type=int, default=None, help="HTTP port (default: 4624)"
    )
    parser.add_argument("--host", default=None, help="HTTP bind address")
    parser.add_argument("--config", help="Path to YAML config file")
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan for installed tools and exit",
    )
    args = parser.parse_args()

    config = get_config(config_file=args.config)

    if args.scan:
        from wintools_mcp.inventory import print_scan_report

        print(print_scan_report())
        return

    if args.host is not None:
        config.http_host = args.host
    if args.port is not None:
        config.http_port = args.port

    if args.http:
        import uvicorn

        from wintools_mcp.http_server import create_http_app

        app = create_http_app(config)
        ssl_kwargs = {}
        if config.tls_certfile and config.tls_keyfile:
            ssl_kwargs["ssl_certfile"] = config.tls_certfile
            ssl_kwargs["ssl_keyfile"] = config.tls_keyfile
        uvicorn.run(app, host=config.http_host, port=config.http_port, **ssl_kwargs)
    else:
        server = create_server(config)
        server.run()


if __name__ == "__main__":
    main()
