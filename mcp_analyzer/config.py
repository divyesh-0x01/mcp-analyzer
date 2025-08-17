from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict
from rich.console import Console

console = Console()

def load_config(path: str) -> Dict[str, Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]Config not found: {path}[/red]")
        raise SystemExit(1)
    try:
        data = json.loads(p.read_text())
    except Exception as e:
        console.print(f"[red]Failed to parse config: {e}[/red]")
        raise SystemExit(1)

    servers: Dict[str, Dict[str, Any]] = {}
    if "mcpServers" in data and isinstance(data["mcpServers"], dict):
        for name, conf in data["mcpServers"].items():
            servers[name] = {
                "command": conf.get("command"),
                "args": conf.get("args", []),
                "env": conf.get("env", {}),
            }
    else:
        console.print("[yellow]No mcpServers key found in config.[/yellow]")
    return servers
