#!/usr/bin/env python3
import asyncio
import json
import logging
import os
import sys
from argparse import ArgumentParser
from typing import List
from mcp_analyzer.config import load_config
from mcp_analyzer.server import scan_server
from mcp_analyzer.report import generate_report
from mcp_analyzer.constants import VERSION, LOG_FILE, OUT_JSON
from mcp_analyzer.findings import Finding
from dataclasses import asdict

def generate_single_server_report(findings: List[Finding], server_name: str) -> None:
    """Generate and display a report for a single server's findings."""
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    from rich import box
    from dataclasses import asdict
    import json
    
    console = Console()
    
    if not findings:
        console.print(f"[green]No vulnerabilities found for {server_name}![/]")
        return
    
    # Convert findings to dicts for easier manipulation
    findings_dicts = [asdict(f) for f in findings]
    
    # Group findings by server and risk level
    findings_by_server = {}
    for finding in findings_dicts:
        server = finding['server']
        if server not in findings_by_server:
            findings_by_server[server] = {
                'findings': [],
                'risk_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'safe': 0},
                'tools': set()
            }
        findings_by_server[server]['findings'].append(finding)
        
        # Categorize by risk level
        risk = finding['active_risk']
        if risk in ['critical', 'high']:
            findings_by_server[server]['risk_counts']['critical'] += 1
            findings_by_server[server]['risk_counts']['high'] += 1
        elif risk in findings_by_server[server]['risk_counts']:
            findings_by_server[server]['risk_counts'][risk] += 1
        else:
            findings_by_server[server]['risk_counts']['safe'] += 1
        
        # Track unique tools
        findings_by_server[server]['tools'].add(finding['tool'])
    
    # Print report for each server
    for server, data in findings_by_server.items():
        server_findings = data['findings']
        risk_counts = data['risk_counts']
        
        # Server header
        console.rule(f"[bold]Server: {server}[/]")
        
        # Get authentication status and tools/resources from findings
        auth_status = "Unauthenticated"
        tools_list = []
        resources_list = []
        
        for finding in server_findings:
            if finding.get('unauthenticated', True):
                auth_status = "Unauthenticated"
            else:
                auth_status = "Authenticated"
            
            # Collect tools and resources information
            tool_name = finding.get('tool', '')
            if tool_name and tool_name != 'connection' and tool_name != 'scanner':
                if tool_name.startswith('resource:'):
                    # Extract resource name from "resource:name" format
                    resource_name = tool_name.replace('resource:', '', 1)
                    resources_list.append(resource_name)
                else:
                    tools_list.append(tool_name)
        
        # Print authentication status
        if auth_status == "Authenticated":
            console.print(f"  [green]{auth_status}[/green]")
        else:
            console.print(f"  [red]{auth_status}[/red]")
        
        # Print resources (if any)
        if resources_list:
            console.print("  Resources:")
            for resource in resources_list:
                console.print(f"    [green]✅[/green] {resource}")
        else:
            console.print("  [yellow]No resources found[/yellow]")
        
        # Print tools
        if tools_list:
            console.print("  Tools:")
            for tool in tools_list:
                console.print(f"    [green]✅[/green] {tool}")
        else:
            console.print("  [yellow]No tools found[/yellow]")
        
        # Print risk summary
        console.print(f"\n[bold]Risk Summary:[/]")
        console.print(f"  • [bold]Total Tools:[/] {len(data['tools'])}")
        
        if risk_counts['critical'] > 0:
            console.print(f"  • [bold red]Critical/High Risk:[/] {risk_counts['critical']}")
        if risk_counts['medium'] > 0:
            console.print(f"  • [bold yellow]Medium Risk:[/] {risk_counts['medium']}")
        if risk_counts['low'] > 0:
            console.print(f"  • [bold blue]Low Risk:[/] {risk_counts['low']}")
        if risk_counts['safe'] > 0:
            console.print(f"  • [bold green]Safe:[/] {risk_counts['safe']}")
        
        # Group findings by risk level
        findings_by_risk = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'safe': []
        }
        
        for finding in server_findings:
            risk = finding['active_risk']
            if risk in ['critical', 'high']:
                findings_by_risk['critical'].append(finding)
            elif risk in findings_by_risk:
                findings_by_risk[risk].append(finding)
            else:
                findings_by_risk['safe'].append(finding)
        
        # Check if there are any security findings (not safe)
        has_security_issues = any(risk_counts[level] > 0 for level in ['critical', 'high', 'medium', 'low'])
        
        # Only show non-safe findings; omit SAFE sections entirely
        if not has_security_issues:
            console.print("\n[green]✓ No security vulnerabilities found[/]")
            console.print("All tools are safe to use.")
        else:
            # Print detailed findings by risk level (skip 'safe' if no security issues)
            risk_levels = ['critical', 'high', 'medium', 'low']
                
            for risk_level in risk_levels:
                findings = findings_by_risk[risk_level]
                if not findings:
                    continue
                    
                risk_color = {
                    'critical': 'red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'blue',
                }[risk_level]
                
                console.print(f"\n[bold {risk_color}]{risk_level.upper()} FINDINGS[/]")
                console.print("-" * 80)
                
                for i, finding in enumerate(findings, 1):
                    console.print(f"\n[bold]{i}. {finding['tool']}[/]")
                    if finding.get('description'):
                        console.print(f"   [dim]Description:[/] {finding['description']}")
                    
                    console.print(f"   [bold]Risk Level:[/] [{risk_color}]{risk_level.upper()}[/]")
                    
                    if finding.get('matches'):
                        console.print("\n   [bold]Indicators:[/]")
                        for match in finding['matches']:
                            console.print(f"     • {match}")
                    
                    if finding.get('proof'):
                        console.print("\n   [bold]Proof:[/]")
                        console.print(f"   [dim]{'─'*70}[/]")
                        try:
                            proof_data = json.loads(finding['proof'])
                            proof_text = json.dumps(proof_data, indent=2)
                        except:
                            proof_text = str(finding['proof'])
                        
                        proof_lines = proof_text.split('\n')
                        for line in proof_lines:
                            console.print(f"   {line}")
                        console.print(f"   [dim]{'─'*70}[/]")
        
        console.print("\n" + "="*120 + "\n")

def setup_logging(debug: bool = False):
    """Configure logging with both file and console output."""
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
    
    # Console handler for real-time output (disabled to show clean report format)
    # console_handler = logging.StreamHandler()
    # console_handler.setLevel(logging.INFO if not debug else logging.DEBUG)
    # console_handler.setFormatter(formatter)
    
    # Add both handlers to root logger
    root_logger.addHandler(file_handler)
    # root_logger.addHandler(console_handler)  # Disabled to show clean report format
    
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
    parser.add_argument("--static", action="store_true", help="Enable static payload generation (fast, reliable, no external dependencies)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--prompt", action="store_true", help="Enable prompt-injection payloads (disabled by default)")
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
                use_dynamic=args.dynamic,
                use_static=args.static,
                use_prompt=args.prompt
            )
            all_findings.extend(findings)
            logger.info(f"Successfully completed scanning server: {name}")
            
            # Generate and display report for this server immediately
            generate_single_server_report(findings, name)
            
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

    # Final summary - just save results without duplicating console output
    from rich.console import Console
    console = Console()
    console.print(f"\n[bold green]Scan completed![/]")
    console.print(f"[cyan]Results saved to: {os.path.abspath(OUT_JSON)}[/]")
    console.print(f"[cyan]Debug logs: {os.path.abspath(LOG_FILE)}[/]")
    
    # Save results to JSON file
    with open(OUT_JSON, 'w') as f:
        json.dump([asdict(f) for f in all_findings], f, indent=2, default=str)

def main():
    try:
        asyncio.run(_amain())
    except KeyboardInterrupt:
        print("\n[red]Interrupted by user[/red]")

if __name__ == "__main__":
    main()
