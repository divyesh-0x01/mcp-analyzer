from __future__ import annotations
from typing import Any, Dict, List, Optional, Union
from .rpc import send_jsonrpc, recv_json_until, next_id
from .constants import CALL_METHODS

# For backward compatibility
async def call_tool_rpc(reader, writer, tool_name: str, arguments: Any, timeout: float = 5.0) -> Optional[dict]:
    """
    Deprecated: Use call_tool_with_client instead.
    Try calling tools via several method names and param shapes:
      {name, arguments}, {name, args}, positional [name, arguments], raw arguments
    """
    logging.warning("call_tool_rpc is deprecated. Use call_tool_with_client instead.")
    
    class SimpleClient:
        def __init__(self, reader, writer):
            self.reader = reader
            self.writer = writer
            
        async def call_tool(self, method: str, params: Union[dict, list]) -> Optional[dict]:
            request_id = next_id()
            await send_jsonrpc(self.writer, {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params
            })
            return await recv_json_until(self.reader, request_id, timeout=5.0)
    
    client = SimpleClient(reader, writer)
    return await call_tool_with_client(client, tool_name, arguments, timeout)

async def call_tool_with_client(
    mcp_client: Any,  # MCPClient or any object with call_tool method
    tool_name: str, 
    arguments: Any, 
    timeout: float = 5.0
) -> Optional[dict]:
    """
    Try calling tools via several method names and param shapes using an MCP client.
    
    Args:
        mcp_client: An object with a call_tool method
        tool_name: Name of the tool to call
        arguments: Arguments to pass to the tool
        timeout: Timeout in seconds (for backward compatibility, may not be used by all clients)
        
    Returns:
        The tool response or None if no valid response was received
    """
    try:
        # Let the MCP client handle the calling pattern
        return await mcp_client.call_tool(tool_name, arguments)
    except Exception as e:
        logging.debug(f"Tool call failed for {tool_name}: {e}")
        return None
