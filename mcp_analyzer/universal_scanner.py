import logging
from typing import Dict, Any, List, Optional, Union

from .adapters.factory import create_adapter
from .adapters.base import MCPAdapter

logger = logging.getLogger(__name__)

class UniversalScanner:
    """Universal scanner that works with both MCP and SSE servers."""
    
    def __init__(self, 
                 server_type: str = 'mcp',
                 **adapter_kwargs):
        """Initialize the universal scanner.
        
        Args:
            server_type: Type of server ('mcp' or 'sse')
            **adapter_kwargs: Additional arguments passed to the adapter
        """
        self.server_type = server_type.lower()
        self.adapter_kwargs = adapter_kwargs
        self.adapter: Optional[MCPAdapter] = None
        self.connected = False
    
    async def connect(self) -> None:
        """Connect to the server using the appropriate adapter."""
        try:
            self.adapter = create_adapter(self.server_type, **self.adapter_kwargs)
            await self.adapter.connect()
            self.connected = True
            logger.info(f"Successfully connected to {self.server_type.upper()} server")
        except Exception as e:
            logger.error(f"Failed to connect to {self.server_type.upper()} server: {e}")
            self.connected = False
            raise
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from the server."""
        if not self.connected or not self.adapter:
            raise RuntimeError("Not connected to server")
            
        try:
            tools = await self.adapter.list_tools()
            logger.info(f"Found {len(tools)} tools")
            return tools
        except Exception as e:
            logger.error(f"Failed to list tools: {e}")
            raise
    
    async def call_tool(self, tool_name: str, **kwargs) -> Any:
        """Call a tool on the server.
        
        Args:
            tool_name: Name of the tool to call
            **kwargs: Arguments to pass to the tool
            
        Returns:
            The result of the tool execution
        """
        if not self.connected or not self.adapter:
            raise RuntimeError("Not connected to server")
            
        try:
            logger.info(f"Calling tool: {tool_name} with args: {kwargs}")
            result = await self.adapter.call_tool(tool_name, kwargs)
            logger.debug(f"Tool {tool_name} result: {result}")
            return result
        except Exception as e:
            logger.error(f"Failed to call tool {tool_name}: {e}")
            raise
    
    async def close(self) -> None:
        """Close the connection to the server."""
        if self.adapter:
            await self.adapter.close()
            self.adapter = None
            self.connected = False
            logger.info("Disconnected from server")
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
