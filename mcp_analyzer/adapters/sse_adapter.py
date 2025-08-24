import asyncio
import json
import logging
import aiohttp
from typing import Any, Dict, List, Optional

from .base import MCPAdapter

logger = logging.getLogger(__name__)

class SSEAdapter(MCPAdapter):
    """Adapter for the custom SSE server implementation."""
    
    def __init__(self, 
                 url: str,
                 headers: Optional[Dict[str, str]] = None,
                 verify_ssl: bool = True,
                 timeout: int = 30):
        """Initialize the SSE adapter.
        
        Args:
            url: Base URL of the SSE server
            headers: Optional headers to include in requests
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
        """
        self.url = url.rstrip('/')
        self.headers = headers or {}
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = None
        self._request_id = 0
        self.logger = logger.getChild('SSEAdapter')
    
    async def connect(self) -> None:
        """Initialize connection to the SSE server."""
        if not self.session or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={
                    'Accept': 'text/event-stream',
                    'Cache-Control': 'no-cache',
                    **self.headers
                },
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                connector=aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            )
    
    async def _make_sse_request(self, method: str, params: Optional[Dict] = None) -> Dict:
        """Make a request to the SSE server.
        
        Args:
            method: JSON-RPC method name
            params: Optional parameters for the method
            
        Returns:
            Parsed JSON response
        """
        if not self.session:
            raise RuntimeError("Not connected to server")
            
        self._request_id += 1
        request_id = str(self._request_id)
        
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {}
        }
        
        self.logger.debug("Sending request: %s", json.dumps(payload, indent=2))
        
        try:
            # Use POST for SSE with JSON-RPC in the body
            async with self.session.post(
                self.url,
                json=payload,
                headers={"Content-Type": "application/json"}
            ) as response:
                response.raise_for_status()
                
                # Read SSE stream
                buffer = b""
                async for line in response.content:
                    if line.startswith(b'data: '):
                        try:
                            data = json.loads(line[6:].strip())
                            if isinstance(data, dict) and data.get('id') == request_id:
                                return data
                        except json.JSONDecodeError as e:
                            self.logger.warning("Failed to parse SSE data: %s", line)
                            continue
                
                raise RuntimeError("No valid response received from server")
                
        except aiohttp.ClientError as e:
            self.logger.error("HTTP request failed: %s", str(e))
            raise RuntimeError(f"HTTP request failed: {str(e)}")
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from the SSE server."""
        try:
            response = await self._make_sse_request("list_tools")
            
            if 'error' in response:
                raise RuntimeError(f"Server error: {response['error']}")
                
            result = response.get('result', {})
            tools = result.get('tools', [])
            
            # Ensure consistent format
            return [{
                'name': tool.get('name', ''),
                'description': tool.get('description', ''),
                'parameters': tool.get('parameters', {})
            } for tool in tools]
            
        except Exception as e:
            self.logger.error("Failed to list tools: %s", str(e), exc_info=True)
            raise
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool on the SSE server."""
        try:
            response = await self._make_sse_request(tool_name, arguments)
            
            if 'error' in response:
                error = response['error']
                raise RuntimeError(f"Tool error: {error.get('message', 'Unknown error')}")
                
            return response.get('result')
            
        except Exception as e:
            self.logger.error("Failed to call tool %s: %s", tool_name, str(e), exc_info=True)
            raise
    
    async def close(self) -> None:
        """Close the connection to the server."""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None
