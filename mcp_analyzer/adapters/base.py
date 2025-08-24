from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

class MCPAdapter(ABC):
    """Base class for MCP server adapters."""
    
    @abstractmethod
    async def connect(self) -> None:
        """Initialize connection to the server."""
        pass
    
    @abstractmethod
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from the server.
        
        Returns:
            List of tools with their metadata
        """
        pass
    
    @abstractmethod
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool on the server.
        
        Args:
            tool_name: Name of the tool to call
            arguments: Arguments to pass to the tool
            
        Returns:
            The result of the tool execution
        """
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """Close the connection to the server."""
        pass
