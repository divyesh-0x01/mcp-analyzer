# mcp_analyzer/mcp_client.py
import asyncio
import json
import logging
import uuid
from typing import Any, Dict, List, Optional

import aiohttp
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

from .findings import Finding

logger = logging.getLogger(__name__)

class MCPClient:
    """Client for connecting to MCP servers using the official MCP library."""
    
    def __init__(self, transport: str = 'http', 
                 reader = None,
                 writer = None,
                 url: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None,
                 verify_ssl: bool = True,
                 timeout: int = 30,
                 **kwargs):
        self.transport = transport
        self.url = url
        self.headers = headers or {}
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        
        # MCP session
        self.session: Optional[ClientSession] = None
        self.initialized = False
        self.server_capabilities = {}
        
        # Store auth info
        self.auth_token = None
        self.auth_config = None
        
        # Store tools and resources
        self.tools = []
        self.resources = []
        
    async def connect(self, auth_config: Optional[Dict[str, Any]] = None) -> None:
        """Connect to the MCP server using the official MCP library."""
        self.logger.info("Connecting to MCP server...")
        
        try:
            # Get the appropriate client based on transport
            if self.transport == 'sse':
                self.logger.info("Using SSE transport")
                client = sse_client(
                    url=self.url,
                    headers=self.headers,
                    timeout=self.timeout
                )
            elif self.transport == 'http':
                self.logger.info("Using HTTP transport")
                client = streamablehttp_client(
                    url=self.url,
                    headers=self.headers
                )
            elif self.transport == 'stdio':
                self.logger.info("Using stdio transport")
                # For stdio, we need command and args
                command = kwargs.get('command', '')
                args = kwargs.get('args', [])
                client = stdio_client(
                    command=command,
                    args=args,
                    env=kwargs.get('env', {})
                )
            else:
                raise ValueError(f"Unsupported transport: {self.transport}")
            
            # Connect using the official MCP library
            async with client as (read, write):
                async with ClientSession(read, write) as session:
                    self.session = session
                    
                    # Initialize the session
                    meta = await session.initialize()
                    self.logger.info("Server initialized with metadata: %s", meta)
                    self.server_capabilities = meta.capabilities.model_dump() if meta.capabilities else {}
                    self.initialized = True
                    
                    # Handle authentication if needed
                    if auth_config:
                        await self._handle_auth(auth_config)
                    
                    # List tools
                    tools = []
                    if hasattr(meta.capabilities, 'tools') and meta.capabilities.tools:
                        try:
                            tools_response = await session.list_tools()
                            tools = tools_response.tools
                            self.logger.info("Found %d tools", len(tools))
                        except Exception as e:
                            self.logger.warning("Failed to list tools: %s", e)
                    
                    # List resources
                    resources = []
                    if hasattr(meta.capabilities, 'resources') and meta.capabilities.resources:
                        try:
                            resources_response = await session.list_resources()
                            resources = resources_response.resources
                            self.logger.info("Found %d resources", len(resources))
                            
                            # Read resource content for prompt injection detection
                            for resource in resources:
                                try:
                                    if hasattr(resource, 'uri') and resource.uri:
                                        resource_content = await session.read_resource(resource.uri)
                                        if hasattr(resource_content, 'contents'):
                                            resource.content = resource_content.contents[0].text if resource_content.contents else ""
                                        elif isinstance(resource_content, str):
                                            resource.content = resource_content
                                        else:
                                            resource.content = str(resource_content)
                                except Exception as e:
                                    self.logger.debug(f"Failed to read resource content for {resource.name}: {str(e)}")
                                    resource.content = ""
                        except Exception as e:
                            self.logger.warning("Failed to list resources: %s", e)
                    
                    # Store the results
                    self.tools = tools
                    self.resources = resources
                    
        except Exception as e:
            self.logger.error("Failed to connect to MCP server: %s", str(e))
            raise RuntimeError(f"Failed to connect to MCP server: {str(e)}")
    
    async def _handle_auth(self, auth_config: Dict[str, Any]) -> None:
        """Handle authentication if needed."""
        # This would be implemented based on the auth_config
        # For now, just log that auth is configured
        self.logger.info("Authentication configured: %s", auth_config.get('type', 'unknown'))
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool using the official MCP library."""
        if not self.session:
            raise RuntimeError("Not connected to server")
        
        try:
            result = await self.session.call_tool(tool_name, arguments)
            return result
        except Exception as e:
            self.logger.error("Failed to call tool %s: %s", tool_name, str(e))
            raise
    
    async def read_resource(self, uri: str) -> Any:
        """Read a resource using the official MCP library."""
        if not self.session:
            raise RuntimeError("Not connected to server")
        
        try:
            result = await self.session.read_resource(uri)
            return result
        except Exception as e:
            self.logger.error("Failed to read resource %s: %s", uri, str(e))
            raise
    
    def get_tools(self) -> List[Dict[str, Any]]:
        """Get the list of tools."""
        return [tool.model_dump() for tool in self.tools] if self.tools else []
    
    def get_resources(self) -> List[Dict[str, Any]]:
        """Get the list of resources."""
        return [resource.model_dump() for resource in self.resources] if self.resources else []
