#!/usr/bin/env python3
import asyncio
import logging
from argparse import ArgumentParser
from mcp_analyzer.config import load_config
from mcp_analyzer.server import scan_server
from mcp_analyzer.report import generate_report
from mcp_analyzer.constants import VERSION

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('scan_debug.log')
    ]
)
logger = logging.getLogger(__name__)

async def _amain():
    parser = ArgumentParser(description="MCP active probe scanner (shows proof)")
    parser.add_argument("--config", "-c", default="test_mcp_config.json", help="Path to MCP config JSON")
    parser.add_argument("--init-timeout", type=float, default=10.0, help="initialize timeout (s)")
    parser.add_argument("--list-timeout", type=float, default=15.0, help="tools/list timeout (s)")
    parser.add_argument("--skip-active-probes", action="store_true", help="Disable active probes (static only)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    print(args)
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")

    servers = load_config(args.config)
    print(servers)

    all_findings = []
    # sequential for stability; could use gather for speed with limits
    for name, conf in servers.items():
        findings = await scan_server(
            server_name=name,
            params=conf,
            init_timeout=args.init_timeout,
            list_timeout=args.list_timeout,
            skip_active=args.skip_active_probes
        )
        all_findings.extend(findings)

    generate_report(all_findings)

def main():
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        print("\n[red]Interrupted by user[/red]")

if __name__ == "__main__":
    main()
