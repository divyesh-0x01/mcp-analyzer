import asyncio
import json
import logging
import uuid
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional, List, AsyncGenerator, Callable, Awaitable
from aiohttp import web, web_request

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # More verbose logging for debugging
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('mcp_sse_server_debug.log')
    ]
)
logger = logging.getLogger('mcp_sse_server')

# MCP Protocol Constants
MCP_JSONRPC_VERSION = "2.0"
MCP_PROTOCOL_VERSION = "0.1.0"

@dataclass
class MCPRequest:
    jsonrpc: str
    id: str
    method: str
    params: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPRequest':
        return cls(
            jsonrpc=data.get('jsonrpc', ''),
            id=data.get('id', ''),
            method=data.get('method', ''),
            params=data.get('params', {})
        )

class MCPServerError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"MCP Error {code}: {message}")

# MCP Tool Definitions
TOOLS = [
    {
        "name": "add_numbers",
        "description": "Add two numbers together",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "number", "description": "First number"},
                "b": {"type": "number", "description": "Second number"}
            },
            "required": ["a", "b"]
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "sum": {"type": "number"},
                "operation": {"type": "string"}
            },
            "required": ["sum", "operation"]
        }
    }
]

# Server Capabilities
SERVER_CAPABILITIES = {
    "capabilities": {
        "tools": True,
        "resources": False,
        "authentication": {
            "methods": ["none"]
        },
        "mcpVersion": MCP_PROTOCOL_VERSION
    }
}

class MCPServer:
    def __init__(self):
        self.connections = {}
        self.tools = TOOLS
        self.logger = logging.getLogger('mcp_sse_server')
        self.sessions = {}

    async def handle_initialize(self, request_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP initialization request."""
        self.logger.info(f"Handling initialize request: {request_id}")
        
        # Create a new session
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            'created_at': time.time(),
            'capabilities': SERVER_CAPABILITIES['capabilities'].copy()
        }
        
        return {
            "jsonrpc": MCP_JSONRPC_VERSION,
            "id": request_id,
            "result": {
                "sessionId": session_id,
                **SERVER_CAPABILITIES
            }
        }

    async def handle_list_tools(self, request_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle list_tools request."""
        self.logger.info(f"Listing tools for request: {request_id}")
        
        # Verify session if required
        if 'sessionId' not in params:
            raise MCPServerError(-32602, "Missing required parameter: sessionId")
            
        return {
            "jsonrpc": MCP_JSONRPC_VERSION,
            "id": request_id,
            "result": {
                "tools": self.tools
            }
        }

    async def handle_add_numbers(self, request_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle add_numbers tool call."""
        try:
            # Extract parameters
            a = float(params.get('a', 0))
            b = float(params.get('b', 0))
            
            # Perform the calculation
            result = a + b
            
            self.logger.info(f"Added {a} + {b} = {result} for request: {request_id}")
            
            # Return the result in MCP format
            return {
                "jsonrpc": MCP_JSONRPC_VERSION,
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"{a} + {b} = {result}"
                        }
                    ],
                    "data": {
                        "sum": result,
                        "operation": f"{a} + {b}"
                    }
                }
            }
        except Exception as e:
            self.logger.error(f"Error in add_numbers: {str(e)}", exc_info=True)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }

    async def handle_request(self, request: web_request.Request) -> web.StreamResponse:
        """Handle incoming SSE requests with MCP protocol support."""
        # Create SSE response with proper headers
        response = web.StreamResponse(
            status=200,
            reason='OK',
            headers={
                'Content-Type': 'text/event-stream; charset=utf-8',
                'Cache-Control': 'no-cache',
                'Connection': 'keep-alive',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Access-Control-Allow-Credentials': 'true',
            }
        )
        
        await response.prepare(request)
        
        # Generate a unique ID for this connection
        conn_id = str(uuid.uuid4())
        self.connections[conn_id] = response
        self.logger.info(f"New connection established: {conn_id}")
        
        # Send initial ping to satisfy SSE connection requirements
        await response.write(b'event: ping\ndata: {}\n\n')
        
        try:
            # Process incoming messages
            async for line in request.content:
                try:
                    # Skip empty lines (SSE keep-alive)
                    line = line.strip()
                    if not line:
                        continue
                        
                    self.logger.debug(f"Received raw message: {line}")
                    
                    # Parse the JSON-RPC request
                    try:
                        request_data = json.loads(line)
                        mcp_request = MCPRequest.from_dict(request_data)
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Invalid JSON: {line}")
                        await self._send_error(response, None, -32700, "Parse error: Invalid JSON")
                        continue
                        
                    self.logger.info(f"Processing MCP request: {mcp_request.method} (ID: {mcp_request.id})")
                    
                    # Route the request to the appropriate handler
                    try:
                        if mcp_request.method == 'initialize':
                            result = await self.handle_initialize(mcp_request.id, mcp_request.params or {})
                        elif mcp_request.method == 'list_tools':
                            result = await self.handle_list_tools(mcp_request.id, mcp_request.params or {})
                        elif mcp_request.method == 'add_numbers':
                            result = await self.handle_add_numbers(mcp_request.id, mcp_request.params or {})
                        else:
                            raise MCPServerError(-32601, f"Method not found: {mcp_request.method}")
                            
                        # Send the successful response
                        await self._send_response(response, mcp_request.id, result)
                        
                    except MCPServerError as e:
                        self.logger.error(f"MCP Error: {e}")
                        await self._send_error(response, mcp_request.id, e.code, e.message, e.data)
                    except Exception as e:
                        self.logger.exception(f"Unexpected error handling {mcp_request.method}")
                        await self._send_error(
                            response, 
                            mcp_request.id, 
                            -32603, 
                            f"Internal error: {str(e)}"
                        )
                        
                except Exception as e:
                    self.logger.exception("Error processing message")
                    # Continue processing other messages even if one fails
                    continue
                    
        except asyncio.CancelledError:
            self.logger.info(f"Connection closed by client: {conn_id}")
        except Exception as e:
            self.logger.exception("Fatal error in connection handler")
        finally:
            # Clean up the connection
            self.connections.pop(conn_id, None)
            try:
                await response.write_eof()
            except Exception:
                pass
        
        return response
        
    async def _send_response(self, response: web.StreamResponse, request_id: str, result: Any) -> None:
        """Send a successful JSON-RPC response."""
        response_data = {
            "jsonrpc": MCP_JSONRPC_VERSION,
            "id": request_id,
            **result
        }
        await self._send_sse(response, response_data)
        
    async def _send_error(self, response: web.StreamResponse, request_id: Optional[str], 
                         code: int, message: str, data: Any = None) -> None:
        """Send a JSON-RPC error response."""
        error_data = {
            "code": code,
            "message": message
        }
        if data is not None:
            error_data["data"] = data
            
        response_data = {
            "jsonrpc": MCP_JSONRPC_VERSION,
            "id": request_id,
            "error": error_data
        }
        await self._send_sse(response, response_data)
        
    async def _send_sse(self, response: web.StreamResponse, data: Dict[str, Any]) -> None:
        """Send an SSE message."""
        try:
            message = f"data: {json.dumps(data)}\n\n"
            self.logger.debug(f"Sending SSE: {message.strip()}")
            await response.write(message.encode('utf-8'))
            # Ensure the message is sent immediately
            await response.drain()
        except Exception as e:
            self.logger.error(f"Error sending SSE message: {e}", exc_info=True)
            raise

    async def handle_options(self, request: web_request.Request) -> web.Response:
        """Handle CORS preflight requests with proper MCP headers."""
        return web.Response(
            status=200,
            headers={
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                'Access-Control-Allow-Credentials': 'true',
                'Access-Control-Max-Age': '3600',
            }
        )

def main():
    """Start the MCP-compatible SSE server with enhanced configuration."""
    # Configure application with middleware
    app = web.Application(client_max_size=10*1024*1024)  # 10MB max request size
    server = MCPServer()
    
    # Add routes
    app.router.add_route('*', '/sse', server.handle_request)
    app.router.add_route('OPTIONS', '/sse', server.handle_options)
    
    # Configure server settings
    host = '0.0.0.0'
    port = 9001
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Log startup information
    logger.info("""
    ==================================================
    MCP-Compatible SSE Server
    ==================================================
    Server starting on: http://%s:%d/sse
    Available tools: %s
    ==================================================
    """, host, port, [tool['name'] for tool in server.tools])
    
    # Start the server with enhanced configuration
    web.run_app(
        app,
        host=host,
        port=port,
        access_log_format='%a %t "%r" %s %b "%{Referer}i" "%{User-Agent}i" %Tf',
        handle_signals=True
    )

if __name__ == '__main__':
    main()
