from typing import Dict, Any, Optional, Type

from .base import MCPAdapter
from .mcp_adapter import MCPLibraryAdapter
from .sse_adapter import SSEAdapter

def create_adapter(server_type: str, **kwargs) -> MCPAdapter:
    """Create an appropriate adapter based on server type.
    
    Args:
        server_type: Type of server ('mcp' or 'sse')
        **kwargs: Additional arguments passed to the adapter constructor
        
    Returns:
        An instance of the appropriate adapter
        
    Raises:
        ValueError: If server_type is not supported
    """
    adapters: Dict[str, Type[MCPAdapter]] = {
        'mcp': MCPLibraryAdapter,
        'sse': SSEAdapter
    }
    
    adapter_class = adapters.get(server_type.lower())
    if not adapter_class:
        raise ValueError(f"Unsupported server type: {server_type}. "
                        f"Supported types are: {', '.join(adapters.keys())}")
    
    return adapter_class(**kwargs)
