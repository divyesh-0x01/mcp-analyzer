# mcp_analyzer/mcp_client.py
import asyncio
import json
import aiohttp
import uuid
import logging
import base64
from typing import Dict, Any, Optional, List, Union

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MCPClient:
    """Client for interacting with an MCP server using JSON-RPC 2.0 over HTTP."""
    
    def __init__(
        self,
        transport: str,
        reader=None,
        writer=None,
        url: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        """Initialize the MCP client.
        
        Args:
            transport: The transport protocol to use ('http' or 'sse')
            reader: Optional reader for the transport
            writer: Optional writer for the transport
            url: Base URL of the MCP server
            headers: Optional headers to include in requests
            **kwargs: Additional keyword arguments
        """
        self.transport = transport
        self.reader = reader
        self.writer = writer
        self.url = url.rstrip('/') if url else None
        self.headers = headers or {}
        self.session: Optional[aiohttp.ClientSession] = None
        self._request_id = 0
        self.logger = logging.getLogger(f"{__name__}.MCPClient")
        self.logger.setLevel(logging.DEBUG)

    async def _get_request_id(self) -> int:
        """Generate a unique request ID for JSON-RPC."""
        self._request_id += 1
        return self._request_id
        
    async def _make_jsonrpc_request(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make a JSON-RPC 2.0 request to the MCP server.
        
        Args:
            method: The RPC method to call
            params: Optional parameters for the method
            
        Returns:
            The parsed JSON response
            
        Raises:
            RuntimeError: If the session is not initialized
            aiohttp.ClientError: For HTTP request errors
            json.JSONDecodeError: If the response is not valid JSON
        """
        if not self.session:
            raise RuntimeError("Session not initialized. Call connect() first.")
            
        request_id = await self._get_request_id()
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params or {}
        }
        
        self.logger.debug("Sending JSON-RPC request: %s", json.dumps(payload, indent=2))
        
        try:
            async with self.session.post(
                self.url,
                json=payload,
                ssl=False
            ) as response:
                response.raise_for_status()
                result = await response.json()
                self.logger.debug("Received JSON-RPC response: %s", json.dumps(result, indent=2))
                
                if 'error' in result:
                    error = result['error']
                    self.logger.error(
                        "RPC error: %s (code: %s)",
                        error.get('message', 'Unknown error'),
                        error.get('code', -1)
                    )
                
                return result
                
        except aiohttp.ClientError as e:
            self.logger.error("HTTP error: %s", str(e))
            raise
        except json.JSONDecodeError as e:
            self.logger.error("Failed to parse JSON response: %s", str(e))
            raise

    async def connect(self, auth_config: Optional[Dict[str, Any]] = None) -> None:
        """Connect to the MCP server and authenticate if needed.
        
        Args:
            auth_config: Optional authentication configuration
            
        Raises:
            RuntimeError: If the connection or authentication fails
        """
        if self.transport not in ("http", "sse"):
            self.logger.debug("Skipping connect for transport: %s", self.transport)
            return
            
        self.headers = dict(self.headers or {})
        
        self.logger.info("Initializing MCP client with transport: %s", self.transport)
        self.logger.debug("Initial headers: %s", self.headers)
        self.logger.debug("Auth config: %s", auth_config)
        
        # Handle OAuth2 authentication if configured
        if auth_config and auth_config.get('method') == 'login':
            self.logger.info("Initiating OAuth2 authentication flow")
            try:
                await self._handle_oauth_login(auth_config)
                self.logger.info("OAuth2 authentication successful")
            except Exception as e:
                self.logger.error("OAuth2 authentication failed: %s", str(e), exc_info=True)
                raise RuntimeError(f"OAuth2 authentication failed: {str(e)}") from e
        else:
            self.logger.info("No authentication configured, proceeding without auth")
            self.session = aiohttp.ClientSession(headers=self.headers)
            self.logger.debug("Created session with headers: %s", self.headers)
            
        # Test the connection by listing tools
        try:
            if self.transport in ("http", "sse"):
                self.logger.info("Testing connection by listing tools...")
                tools = await self.list_tools()
                self.logger.info("Successfully connected to MCP server. Found %d tools.", len(tools))
                if tools:
                    tool_names = [tool.get('name', 'unknown') for tool in tools]
                    self.logger.debug("Available tools: %s", ", ".join(tool_names))
        except Exception as e:
            self.logger.error("Connection test failed: %s", str(e), exc_info=True)
            if self.session:
                await self.session.close()
                self.session = None
            raise

    async def _handle_oauth_login(self, auth_config: Dict[str, Any]) -> None:
        """Handle OAuth2 login flow.
        
        Args:
            auth_config: OAuth2 configuration
            
        Raises:
            ValueError: If required configuration is missing
            RuntimeError: If authentication fails
        """
        login_url = auth_config.get('url')
        if not login_url:
            error_msg = "No login URL provided in auth config"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        login_payload = auth_config.get('credentials', {})
        use_form_data = auth_config.get('use_form_data', True)
        
        # Prepare headers for token request
        login_headers = {
            'Content-Type': 'application/x-www-form-urlencoded' if use_form_data else 'application/json',
            'Accept': 'application/json'
        }
        
        # Add Basic Auth if configured
        basic_auth = auth_config.get('auth', {})
        if isinstance(basic_auth, dict) and basic_auth.get('type') == 'basic':
            username = basic_auth.get('username', '')
            password = basic_auth.get('password', '')
            if username and password:
                auth_str = f"{username}:{password}"
                auth_bytes = auth_str.encode('ascii')
                base64_auth = base64.b64encode(auth_bytes).decode('ascii')
                login_headers['Authorization'] = f"Basic {base64_auth}"
        
        # Make the token request
        try:
            async with aiohttp.ClientSession() as temp_session:
                self.logger.debug(f"Sending OAuth2 request to {login_url}")
                self.logger.debug(f"Headers: {login_headers}")
                self.logger.debug(f"Payload: {login_payload}")
                
                if use_form_data:
                    data = aiohttp.FormData()
                    for key, value in login_payload.items():
                        data.add_field(key, str(value))
                    response = await temp_session.post(
                        login_url,
                        headers=login_headers,
                        data=data,
                        ssl=False
                    )
                else:
                    response = await temp_session.post(
                        login_url,
                        headers=login_headers,
                        json=login_payload,
                        ssl=False
                    )
                
                response_text = await response.text()
                self.logger.debug(f"OAuth2 response status: {response.status}")
                self.logger.debug(f"OAuth2 response: {response_text}")
                
                response.raise_for_status()
                
                try:
                    token_data = await response.json()
                    self.logger.debug("Successfully parsed token response")
                except Exception as e:
                    self.logger.error("Failed to parse token response: %s", str(e))
                    self.logger.debug("Raw response: %s", response_text)
                    raise ValueError(f"Failed to parse token response: {str(e)}")
                
                # Extract token using token_path
                token_path = auth_config.get('token_path', ['access_token'])
                token = token_data
                for key in token_path:
                    if token is None or not isinstance(token, dict) or key not in token:
                        raise ValueError(f"Failed to extract token from path {token_path}")
                    token = token[key]
                
                if not token:
                    raise ValueError("Empty token received from auth server")
                
                # Add token to headers for subsequent requests
                header_name = auth_config.get('header', 'Authorization')
                prefix = auth_config.get('prefix', 'Bearer').strip()
                if prefix:
                    prefix += ' '
                
                self.headers[header_name] = f"{prefix}{token}"
                self.session = aiohttp.ClientSession(headers=self.headers)
                self.logger.info("Successfully authenticated with OAuth2")
                
        except aiohttp.ClientError as e:
            error_msg = f"HTTP error during OAuth2 authentication: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise RuntimeError(error_msg) from e
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse OAuth2 token response: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise ValueError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error during OAuth2 authentication: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise RuntimeError(error_msg) from e

    async def close(self) -> None:
        """Close the client session."""
        if self.session:
            await self.session.close()
            self.session = None

    async def list_tools(self) -> List[Dict[str, Any]]:
        """List all available tools from the MCP server.
        
        Returns:
            A list of available tools
        """
        try:
            response = await self._make_jsonrpc_request("list_tools")
            if isinstance(response, dict) and 'result' in response:
                return response.get('result', {}).get('tools', [])
            return []
        except Exception as e:
            self.logger.error("Failed to list tools: %s", str(e), exc_info=True)
            return []

    async def call_tool(
        self,
        name: str,
        args: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Call a tool on the MCP server.
        
        Args:
            name: The name of the tool to call (e.g., 'file/read')
            args: Dictionary of arguments to pass to the tool
            
        Returns:
            The result of the tool execution or None if there was an error
        """
        if args is None:
            args = {}
            
        self.logger.debug("Calling tool: %s with args: %s", name, args)
        
        try:
            response = await self._make_jsonrpc_request(name, args)
            
            # Handle JSON-RPC response format
            if isinstance(response, dict):
                if 'result' in response and 'jsonrpc' in response and 'id' in response:
                    self.logger.debug("Valid JSON-RPC response received")
                    return response['result']
                elif 'error' in response:
                    self.logger.error("Error in response: %s", response.get('error'))
                    return None
            
            self.logger.debug("Received non-JSON-RPC response")
            return response
            
        except Exception as e:
            self.logger.error("Error calling tool %s: %s", name, str(e), exc_info=True)
            return None

    async def __aenter__(self):
        """Async context manager entry."""
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
