#!/usr/bin/env python3
import asyncio
import json
import logging
import os
import sys
from argparse import ArgumentParser
from mcp_analyzer.config import load_config
from mcp_analyzer.server import scan_server
from mcp_analyzer.report import generate_report
from mcp_analyzer.constants import VERSION, LOG_FILE, OUT_JSON
from mcp_analyzer.findings import Finding

def setup_logging(debug: bool = False):
    """Configure logging with file handler only (no console output)."""
    # Clear any existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Configure the root logger
    log_level = logging.DEBUG if debug else logging.INFO
    root_logger.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # File handler for debug log
    file_handler = logging.FileHandler(LOG_FILE, mode='w')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Add file handler to root logger (no console handler added)
    root_logger.addHandler(file_handler)
    
    # Set specific log levels for noisy libraries
    logging.getLogger('asyncio').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    
    return root_logger

async def _amain():
    parser = ArgumentParser(description="MCP active probe scanner (shows proof)")
    parser.add_argument("--config", "-c", default="test_mcp_config.json", help="Path to MCP config JSON")
    parser.add_argument("--init-timeout", type=float, default=10.0, help="initialize timeout (s)")
    parser.add_argument("--list-timeout", type=float, default=15.0, help="tools/list timeout (s)")
    parser.add_argument("--skip-active-probes", action="store_true", help="Disable active probes (static only)")
    parser.add_argument("--dynamic", action="store_true", help="Enable dynamic fuzzing of identified tools (disabled by default)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    
    # Setup logging based on debug flag
    logger = setup_logging(debug=args.debug)
    logger.info("Starting MCP Analyzer v%s", VERSION)
    logger.debug("Debug logging enabled")

    servers = load_config(args.config)
    #print(servers)

    all_findings = []
    # sequential for stability; could use gather for speed with limits
    for name, conf in servers.items():
        try:
            logger.info(f"\n{'='*50}\nScanning server: {name}\n{'='*50}")
            if args.dynamic:
                logger.info("Dynamic fuzzing is ENABLED - LLM-based fuzzing will be attempted")
            else:
                logger.info("Dynamic fuzzing is DISABLED - only static analysis will be performed")
                
            findings = await scan_server(
                server_name=name,
                params=conf,
                init_timeout=args.init_timeout,
                list_timeout=args.list_timeout,
                skip_active=args.skip_active_probes,
                use_dynamic=args.dynamic
            )
            all_findings.extend(findings)
            logger.info(f"Successfully completed scanning server: {name}")
            
        except (ConnectionError, RuntimeError) as e:
            error_msg = f"Server is not reachable. Check if the server is running and accessible at {conf.get('url', 'the specified URL')}"
            logger.error(f"[!] {error_msg}")
            logger.info("Continuing with next server...")
            # Add a finding to indicate the server scan failed
            all_findings.append(Finding(
                server=name,
                unauthenticated=True,
                tool="connection",
                description=f"Server is not reachable",
                static_risk="info",
                active_risk="none",
                matches=[f"Connection error: {error_msg}"],
                proof=json.dumps({
                    'error_type': 'ConnectionError',
                    'error_message': error_msg,
                    'server': name,
                    'url': conf.get('url', 'not specified')
                })
            ))
        except Exception as e:
            error_msg = str(e)
            logger.error(f"[!] Unexpected error while scanning server {name}: {error_msg}", exc_info=args.debug)
            logger.info("Continuing with next server...")
            # Add a finding to indicate the server scan failed
            all_findings.append(Finding(
                server=name,
                unauthenticated=True,
                tool="scanner",
                description=f"Unexpected error while scanning server: {error_msg}",
                static_risk="suspicious",
                active_risk="critical",
                matches=[f"Unexpected error: {error_msg}"],
                proof=json.dumps({
                    'error_type': e.__class__.__name__,
                    'error_message': error_msg,
                    'server': name,
                    'exception': str(e.__class__.__name__)
                })
            ))

    generate_report(all_findings)

def main():
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        print("\n[red]Interrupted by user[/red]")

if __name__ == "__main__":
    main()
