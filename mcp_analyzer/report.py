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
    # First try to get the complete proof from probe_results.exec.proof
    if (isinstance(finding, dict) and 
        'probe_results' in finding and 
        'exec' in finding['probe_results'] and 
        'proof' in finding['probe_results']['exec'] and 
        finding['probe_results']['exec']['proof']):
        return finding['probe_results']['exec']['proof']
    
    # Fall back to the top-level proof field if available
    if 'proof' in finding and finding['proof']:
        return finding['proof']
    
    return None

def generate_report(all_findings: List[Finding]) -> None:
    """Generate and display a report of findings."""
    # Convert findings to dicts for easier manipulation
    findings_dicts = [asdict(f) for f in all_findings]
    
    # Save full results to JSON
    save_findings_to_file(all_findings, OUT_JSON)
    
    # Create console with appropriate width and settings
    console = Console(record=True, width=150)  # Increased width to 150 characters
    
    # Print report header
    console.print(f"[bold blue]MCP Security Scan - {VERSION}[/]\n")
    
    if not all_findings:
        console.print("[green]No vulnerabilities found![/]")
        return
    
    # Process each finding
    for i, finding_dict in enumerate(findings_dicts, 1):
        # Get the complete proof data
        complete_proof = get_complete_proof(finding_dict)
        
        # Print finding header
        console.print(f"[bold cyan]\n[{'='*50}][/]")
        console.print(f"[bold]Finding {i}: {finding_dict['tool']}[/]")
        console.print(f"[dim]{'-'*60}[/]")
        
        # Print basic info
        console.print(f"[bold]Server:[/] {finding_dict['server']}")
        console.print(f"[bold]Tool:[/] {', '.join(finding_dict['tool']) if isinstance(finding_dict['tool'], list) else finding_dict['tool']}")
        console.print(f"[bold]Unauthenticated:[/] {'[red]YES[/]' if finding_dict['unauthenticated'] else '[green]NO[/]'}")
        console.print(f"[bold]Static Risk:[/] [yellow]{finding_dict['static_risk']}[/]")
        console.print(f"[bold]Active Risk:[/] [{'red' if finding_dict['active_risk'] != 'none' else 'green'}]{finding_dict['active_risk'].upper() if finding_dict['active_risk'] != 'none' else 'NO FINDINGS'}[/]")
        
        # Print proof section if we have proof data
        if complete_proof:
            console.print("\n[bold green]Proof:[/]")
            console.print("\n[bold cyan]Detailed Analysis:[/]")
            proof_text = format_proof_text(complete_proof)
            
            # Split the proof text into lines and print with proper formatting
            for line in proof_text.split('\n'):
                if line.startswith('Behavior'):
                    console.print(f"\n[bold cyan]{line}[/]")
                elif line.strip().startswith('Payload:'):
                    console.print(f"  [bold green]Payload:[/]")
                elif line.strip().startswith('Response:'):
                    console.print(f"  [bold green]Response:[/]")
                    console.print(f"    {line.replace('Response:', '').strip()}")
                elif line.strip().startswith('Reason:'):
                    console.print(f"  [bold red]Reason:[/] {line.replace('Reason:', '').strip()}")
                elif line.strip() == '-' * 50:
                    console.print("  [dim]" + "-" * 50 + "[/]")
                elif line.strip():
                    # Indent other lines for better readability
                    console.print(f"    {line}")
        
        # Add separator between findings
        if i < len(all_findings):
            console.print("\n[bold blue]" + "="*80 + "[/]\n")
    
    # Print summary
    console.print(f"\n[bold green]Scan completed![/]")
    console.print(f"[cyan]Detailed results saved to: {os.path.abspath(OUT_JSON)}[/]")
    console.print(f"[cyan]Logs saved to: {os.path.abspath(LOG_FILE)}[/]")
