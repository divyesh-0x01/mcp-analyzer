from __future__ import annotations
from typing import Any, Dict, List, Optional
from .rpc import send_jsonrpc, recv_json_until, next_id
from .constants import CALL_METHODS

async def call_tool_rpc(reader, writer, tool_name: str, arguments: Any, timeout: float = 5.0) -> Optional[dict]:
    """
    Try calling tools via several method names and param shapes:
      {name, arguments}, {name, args}, positional [name, arguments], raw arguments
    """
    tries = []

    for m in CALL_METHODS:
        tries.append({"jsonrpc": "2.0", "id": next_id(), "method": m, "params": {"name": tool_name, "arguments": arguments}})
        tries.append({"jsonrpc": "2.0", "id": next_id(), "method": m, "params": {"name": tool_name, "args": arguments}})
        tries.append({"jsonrpc": "2.0", "id": next_id(), "method": m, "params": [tool_name, arguments]})
        tries.append({"jsonrpc": "2.0", "id": next_id(), "method": m, "params": arguments})

    for p in tries:
        await send_jsonrpc(writer, p)
        resp = await recv_json_until(reader, wanted_id=p["id"], timeout=timeout, want_tools=False)
        if resp is not None:
            return resp
    return None
