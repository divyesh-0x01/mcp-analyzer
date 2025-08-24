import logging
from typing import Any, Dict, List, Optional

from .base import MCPAdapter

logger = logging.getLogger(__name__)

class MCPLibraryAdapter(MCPAdapter):
    """Adapter for the official MCP client library."""
    
    def __init__(self, transport: str = 'http', 
                 url: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None,
                 verify_ssl: bool = True,
                 timeout: int = 30,
                 **kwargs):
        """Initialize the MCP library adapter.
        
        Args:
            transport: Transport protocol ('http' or 'sse')
            url: Base URL of the MCP server
            headers: Optional headers to include in requests
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            **kwargs: Additional arguments passed to the MCP client
        """
        self.transport = transport
        self.url = url
        self.headers = headers or {}
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.kwargs = kwargs
        self.client = None
        self.logger = logger.getChild('MCPLibraryAdapter')
    
    async def connect(self) -> None:
        """Initialize connection to the MCP server."""
        from mcp_analyzer.mcp_client import MCPClient
        
        self.client = MCPClient(
            transport=self.transport,
            url=self.url,
            headers=self.headers,
            verify_ssl=self.verify_ssl,
            timeout=self.timeout,
            **self.kwargs
        )
        
        # Connect to the server
        await self.client.connect()
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from the MCP server."""
        if not self.client:
            raise RuntimeError("Not connected to server")
            
        try:
            # Use the official client's method to list tools
            tools = await self.client.list_tools()
            
            # Convert to a consistent format
            return [{
                'name': tool.get('name', ''),
                'description': tool.get('description', ''),
                'parameters': tool.get('parameters', {})
            } for tool in tools]
            
        except Exception as e:
            self.logger.error(f"Failed to list tools: {e}", exc_info=True)
            raise
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool on the MCP server."""
        if not self.client:
            raise RuntimeError("Not connected to server")
            
        try:
            return await self.client.call_tool(tool_name, arguments)
        except Exception as e:
            self.logger.error(f"Failed to call tool {tool_name}: {e}", exc_info=True)
            raise
    
    async def close(self) -> None:
        """Close the connection to the server."""
        if self.client:
            await self.client.close()
            self.client = None
