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
    """Generate and display a report of findings with improved formatting and organization."""
    # Convert findings to dicts for easier manipulation
    findings_dicts = [asdict(f) for f in all_findings]
    
    # Save full results to JSON
    save_findings_to_file(all_findings, OUT_JSON)
    
    # Create console with appropriate width and settings
    console = Console(record=True, width=120)
    
    if not all_findings:
        console.print("[green]No vulnerabilities found![/]")
        return
    
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
        
        # Server header with risk summary
        console.rule(f"[bold]Server: {server}[/]")
        
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
        
        # Only show safe findings if there are no security issues
        if not has_security_issues:
            console.print("\n[green]✓ No security vulnerabilities found[/]")
            console.print("All tools are safe to use.")
        else:
            # Print detailed findings by risk level (skip 'safe' if no security issues)
            risk_levels = ['critical', 'high', 'medium', 'low']
            if has_security_issues or risk_counts['safe'] > 0:
                risk_levels.append('safe')
                
            for risk_level in risk_levels:
                findings = findings_by_risk[risk_level]
                if not findings:
                    continue
                    
                risk_color = {
                    'critical': 'red',
                    'high': 'red',
                    'medium': 'yellow',
                    'low': 'blue',
                    'safe': 'green'
                }[risk_level]
                
                console.print(f"\n[bold {risk_color}]{risk_level.upper() if risk_level != 'safe' else 'SAFE'} FINDINGS[/]")
                console.print("-" * 80)
                
                for i, finding in enumerate(findings, 1):
                    console.print(f"\n[bold]{i}. {finding['tool']}[/]")
                    if finding.get('description'):
                        console.print(f"   [dim]Description:[/] {finding['description']}")
                    
                    console.print(f"   [bold]Risk Level:[/] [{risk_color}]{risk_level.upper() if risk_level != 'safe' else 'SAFE'}[/]")
                    
                    if finding.get('matches'):
                        console.print("\n   [bold]Indicators:[/]")
                        for match in finding['matches']:
                            console.print(f"     • {match}")
                    
                    complete_proof = get_complete_proof(finding)
                    if complete_proof:
                        console.print("\n   [bold]Proof:[/]")
                        console.print(f"   [dim]{'─'*70}[/]")
                        proof_lines = format_proof(complete_proof).split('\n')
                        for line in proof_lines:
                            console.print(f"   {line}")
                        console.print(f"   [dim]{'─'*70}[/]")
        
        console.print("\n" + "="*120 + "\n")
    
    # Print summary
    console.print(f"\n[bold green]Scan completed![/]")
    console.print(f"[cyan]Results saved to: {os.path.abspath(OUT_JSON)}[/]")
    console.print(f"[cyan]Debug logs: {os.path.abspath(LOG_FILE)}[/]")
