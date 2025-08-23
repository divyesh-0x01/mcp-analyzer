from __future__ import annotations
import json
import logging
import os
import re
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import List

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich import box

from mcp_analyzer.findings import Finding
from mcp_analyzer.constants import VERSION

OUT_JSON = "scan_results.json"
LOG_FILE = "scan_debug.log"

console = Console()

logging.basicConfig(
    filename=LOG_FILE,
    filemode="w",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def format_proof(proof: str) -> Text:
    """Format proof text for better display in the console."""
    if not proof or proof == "-":
        return Text("-")
    
    try:
        # Try to parse as JSON for structured data
        proof_data = json.loads(proof)
        if isinstance(proof_data, dict) and 'suspicious_behaviors' in proof_data:
            behaviors = proof_data['suspicious_behaviors']
            if not behaviors:
                return Text("No suspicious behaviors found")
            
            text = Text()
            
            # Process each behavior
            for i, behavior in enumerate(behaviors, 1):
                if i > 1:
                    text.append("\n" + "─" * 80 + "\n\n", style="dim")
                
                payload = behavior.get('payload', {})
                response = behavior.get('response', '')
                reason = behavior.get('reason', '')
                
                # Add behavior header
                text.append(f"Behavior {i}", style="bold cyan")
                if reason:
                    text.append(f" - {reason}\n", style="red")
                else:
                    text.append("\n")
                
                # Add payload info
                if payload:
                    text.append("Payload:\n", style="bold green")
                    if isinstance(payload, dict):
                        for key, value in payload.items():
                            text.append(f"  {key}: ", style="bold")
                            text.append(f"{value}\n")
                    else:
                        text.append(f"  {str(payload)}\n")
                
                # Add response
                if response:
                    text.append("\nResponse:\n", style="bold green")
                    # Preserve newlines and format the response
                    lines = str(response).split('\n')
                    for line in lines:
                        text.append(f"  {line}\n")
            
            return text
            
    except (json.JSONDecodeError, AttributeError, TypeError) as e:
        logging.debug(f"Error formatting proof: {str(e)}")
    
    # Fallback: display raw proof with newlines preserved
    if isinstance(proof, str):
        text = Text()
        lines = proof.split('\n')
        for i, line in enumerate(lines):
            if i > 0:
                text.append("\n")
            text.append(f"  {line}")
        return text
    
    return Text(str(proof))

def save_findings_to_file(findings: List[Finding], filename: str) -> None:
    """Save findings to a JSON file with proper formatting."""
    try:
        with open(filename, 'w') as f:
            json.dump(
                {
                    "version": VERSION,
                    "timestamp": datetime.utcnow().isoformat(),
                    "findings": [asdict(f) for f in findings]
                },
                f,
                indent=2
            )
    except Exception as e:
        logging.exception("Failed to save findings to %s: %s", filename, str(e))

def format_proof_text(proof_text: str) -> str:
    """Format proof text for better readability in the console."""
    if not proof_text or proof_text == "-":
        return "No proof data available"
    
    # First, try to fix any truncated JSON
    fixed_proof = fix_truncated_json(proof_text)
    
    # Try to parse as JSON first
    try:
        proof_data = json.loads(fixed_proof)
        
        # If we have suspicious_behaviors, format them nicely
        if isinstance(proof_data, dict) and 'suspicious_behaviors' in proof_data:
            formatted = []
            for i, behavior in enumerate(proof_data['suspicious_behaviors'], 1):
                formatted.append(f"Behavior {i}:")
                
                # Format payload
                if 'payload' in behavior and behavior['payload']:
                    formatted.append("  Payload:")
                    if isinstance(behavior['payload'], dict):
                        for key, value in behavior['payload'].items():
                            formatted.append(f"    {key}: {value}")
                    else:
                        formatted.append(f"    {behavior['payload']}")
                
                # Format response (don't truncate)
                if 'response' in behavior and behavior['response']:
                    response = str(behavior['response'])
                    formatted.append("  Response:")
                    formatted.append(f"    {response}")
                
                # Add reason if exists
                if 'reason' in behavior and behavior['reason']:
                    formatted.append(f"  Reason: {behavior['reason']}")
                
                # Add separator if not last behavior
                if i < len(proof_data['suspicious_behaviors']):
                    formatted.append("\n" + "-" * 50)
            
            return "\n".join(formatted)
        
        # For other JSON structures, pretty print
        return json.dumps(proof_data, indent=2)
        
    except (json.JSONDecodeError, TypeError, AttributeError) as e:
        # If still not valid JSON, return the original text with a note
        return f"Could not parse proof data (error: {str(e)}). Raw data:\n{proof_text}"

def fix_truncated_json(json_str: str) -> str:
    """Attempt to fix truncated JSON strings by properly closing them."""
    if not json_str or not isinstance(json_str, str):
        return json_str
    
    # Count open and close braces/brackets to see if they're balanced
    open_braces = json_str.count('{')
    close_braces = json_str.count('}')
    open_brackets = json_str.count('[')
    close_brackets = json_str.count(']')
    
    # If we have more open than close, try to close them
    if open_braces > close_braces:
        json_str += '}' * (open_braces - close_braces)
    if open_brackets > close_brackets:
        json_str += ']' * (open_brackets - close_brackets)
    
    # If the string ends with a comma, remove it
    json_str = json_str.rstrip().rstrip(',')
    
    return json_str

def get_complete_proof(finding: dict) -> str:
    """Extract the complete proof data from the finding."""
    if not isinstance(finding, dict):
        return None
    
    # Try to get proof from probe_results first
    if 'probe_results' in finding and finding['probe_results']:
        for probe_type, probe_data in finding['probe_results'].items():
            if not probe_data:
                continue
                
            # Handle direct proof in probe_data
            if 'proof' in probe_data and probe_data['proof']:
                return json.dumps({
                    'tool_name': finding.get('tool', ''),
                    'server': finding.get('server', ''),
                    'probe_type': probe_type,
                    'proof': probe_data['proof'],
                    'classification': 'suspicious_behavior' if finding.get('active_risk') != 'none' else 'normal_behavior'
                }, indent=2)
                
            # Check attempts for response data
            if 'attempts' in probe_data and probe_data['attempts']:
                for attempt in probe_data['attempts']:
                    if 'response' in attempt and attempt['response']:
                        return json.dumps({
                            'tool_name': finding.get('tool', ''),
                            'server': finding.get('server', ''),
                            'probe_type': probe_type,
                            'payload': attempt.get('args', {}),
                            'response': attempt['response'],
                            'classification': 'suspicious_behavior' if finding.get('active_risk') != 'none' else 'normal_behavior'
                        }, indent=2)
                    elif 'proof' in attempt and attempt['proof']:
                        return json.dumps({
                            'tool_name': finding.get('tool', ''),
                            'server': finding.get('server', ''),
                            'probe_type': probe_type,
                            'proof': attempt['proof'],
                            'classification': 'suspicious_behavior' if finding.get('active_risk') != 'none' else 'normal_behavior'
                        }, indent=2)
    
    # Fall back to direct proof field if available
    if 'proof' in finding and finding['proof']:
        if isinstance(finding['proof'], str):
            try:
                # If it's already a JSON string, parse and re-format it
                proof_data = json.loads(finding['proof'])
                return json.dumps({
                    'tool_name': finding.get('tool', ''),
                    'server': finding.get('server', ''),
                    'proof': proof_data,
                    'classification': 'suspicious_behavior' if finding.get('active_risk') != 'none' else 'normal_behavior'
                }, indent=2)
            except json.JSONDecodeError:
                # If not JSON, return as is
                return finding['proof']
        return json.dumps({
            'tool_name': finding.get('tool', ''),
            'server': finding.get('server', ''),
            'proof': finding['proof'],
            'classification': 'suspicious_behavior' if finding.get('active_risk') != 'none' else 'normal_behavior'
        }, indent=2)
    
    return None

def generate_report(all_findings: List[Finding]) -> None:
    """Generate and display a report of findings."""
    # Convert findings to dicts for easier manipulation
    findings_dicts = [asdict(f) for f in all_findings]
    
    # Save full results to JSON
    save_findings_to_file(all_findings, OUT_JSON)
    
    # Create console with appropriate width and settings
    console = Console(record=True, width=150)  # Increased width to 150 characters
    
    if not all_findings:
        console.print("[green]No vulnerabilities found![/]")
        return
    
    # Group findings by server
    findings_by_server = {}
    for finding in findings_dicts:
        server = finding['server']
        if server not in findings_by_server:
            findings_by_server[server] = []
        findings_by_server[server].append(finding)
    
    # Print report for each server
    for server, server_findings in findings_by_server.items():
        console.rule(f"[bold]Server: {server}[/]")
        
        # Print server summary
        total_findings = len(server_findings)
        critical_findings = sum(1 for f in server_findings if f['active_risk'] in ['critical', 'high'])
        medium_findings = sum(1 for f in server_findings if f['active_risk'] == 'medium')
        low_findings = sum(1 for f in server_findings if f['active_risk'] == 'low')
        
        console.print(f"[bold]Total Tools:[/] {total_findings}")
        if critical_findings > 0:
            console.print(f"[bold red]Critical/High Risk Findings:[/] {critical_findings}")
        if medium_findings > 0:
            console.print(f"[bold yellow]Medium Risk Findings:[/] {medium_findings}")
        if low_findings > 0:
            console.print(f"[bold blue]Low Risk Findings:[/] {low_findings}")
        
        # Print tools list
        console.print("\n[bold]Tools:[/]")
        for finding in sorted(server_findings, key=lambda x: (x['active_risk'] != 'none', x['tool'])):
            risk_color = {
                'critical': 'red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'blue',
                'none': 'green'
            }.get(finding['active_risk'], 'white')
            
            risk_text = finding['active_risk'].upper() if finding['active_risk'] != 'none' else 'SAFE'
            console.print(f"  - {finding['tool']} [{risk_color}]{risk_text}[/]")
        
        # Print detailed findings for this server
        console.print("\n[bold]Detailed Findings:[/]")
        for i, finding in enumerate([f for f in server_findings if f['active_risk'] != 'none'], 1):
            console.print(f"\n[bold]{i}. {finding['tool']}[/]")
            console.print(f"   [dim]Description:[/] {finding['description']}")
            
            # Show risk level with color
            risk_color = {
                'critical': 'red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'blue'
            }.get(finding['active_risk'], 'white')
            
            console.print(f"   [bold]Risk Level:[/] [{risk_color}]{finding['active_risk'].upper()}[/]")
            
            # Show proof if available
            complete_proof = get_complete_proof(finding)
            if complete_proof:
                console.print("\n   [bold]Proof:[/]")
                console.print(f"   [dim]{'-'*70}[/]")
                proof_lines = format_proof(complete_proof).split('\n')
                for line in proof_lines:
                    console.print(f"   {line}")
                console.print(f"   [dim]{'-'*70}[/]")
            
            # Show matches if any
            if finding.get('matches'):
                console.print("\n   [bold]Indicators:[/]")
                for match in finding['matches']:
                    console.print(f"     - {match}")
        
        console.print("\n" + "="*80 + "\n")
    
    # Print summary
    console.print(f"\n[bold green]Scan completed![/]")
    console.print(f"[cyan]Detailed results saved to: {os.path.abspath(OUT_JSON)}[/]")
    console.print(f"[cyan]Logs saved to: {os.path.abspath(LOG_FILE)}[/]")
    
    # Print summary
    console.print(f"\n[bold green]Scan completed![/]")
    console.print(f"[cyan]Detailed results saved to: {os.path.abspath(OUT_JSON)}[/]")
    console.print(f"[cyan]Logs saved to: {os.path.abspath(LOG_FILE)}[/]")
