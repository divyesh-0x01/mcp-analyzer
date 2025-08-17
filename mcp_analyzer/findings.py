from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import json
import uuid
import asyncio
import logging

async def call_tool(reader, writer, tool: dict, args: dict) -> dict:
    """
    Send an MCP tool call request over the given reader/writer streams
    and wait for the response. Returns the JSON-decoded result dict.
    """
    request_id = str(uuid.uuid4())
    message = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool["name"],
            "arguments": args,
        },
    }

    # 🔼 Send the request
    data = (json.dumps(message) + "\n").encode()
    writer.write(data)
    await writer.drain()

    # 🔽 Wait for a response
    while True:
        line = await reader.readline()
        if not line:
            break
        try:
            resp = json.loads(line.decode())
        except Exception:
            logging.warning("Non-JSON line from server: %r", line)
            continue

        if resp.get("id") == request_id:
            if "result" in resp:
                return resp["result"]
            if "error" in resp:
                return {"error": resp["error"]}
            return resp
        
__all__ = ["Finding", "call_tool"]

@dataclass
class Finding:
    server: str
    unauthenticated: bool
    tool: str
    description: str
    static_risk: str           # safe / suspicious / dangerous
    active_risk: str = field(default="none")  # none / denied / low / medium / high
    matches: List[str] = field(default_factory=list)
    probe_results: Dict[str, Any] = field(default_factory=dict)
    proof: Optional[str] = None

    def summarize_risk(self) -> str:
        """
        Normalize active risk for reporting.
        """
        if not self.active_risk:
            return "UNKNOWN"
        if self.active_risk == "denied":
            return "DENIED"
        if self.active_risk == "none":
            return "NO FINDINGS"
        return self.active_risk.upper()
