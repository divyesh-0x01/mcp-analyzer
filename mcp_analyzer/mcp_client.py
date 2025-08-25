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
        
    async def connect(self, auth_config: Optional[Dict[str, Any]] = None, **kwargs) -> None:
        """Connect to the MCP server using the official MCP library."""
        self.logger.info("Connecting to MCP server...")
        
        try:
            # Get the appropriate client based on transport
            if self.transport == 'sse':
                self.logger.info("Using SSE transport")
                self.client = sse_client(
                    url=self.url,
                    headers=self.headers,
                    timeout=self.timeout
                )
            elif self.transport == 'http':
                self.logger.info("Using HTTP transport")
                self.client = streamablehttp_client(
                    url=self.url,
                    headers=self.headers
                )
            elif self.transport == 'stdio':
                self.logger.info("Using stdio transport")
                # For stdio, we need command and args
                command = kwargs.get('command', '')
                args = kwargs.get('args', [])
                self.client = stdio_client(
                    command=command,
                    args=args,
                    env=kwargs.get('env', {})
                )
            else:
                raise ValueError(f"Unsupported transport: {self.transport}")
            
            # Start the client connection
            self.read_write = await self.client.__aenter__()
            read, write = self.read_write
            
            # Create the session
            self.session = ClientSession(read, write)
            await self.session.__aenter__()
            
            # Initialize the session
            meta = await self.session.initialize()
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
                    tools_response = await self.session.list_tools()
                    tools = tools_response.tools
                    self.logger.info("Found %d tools", len(tools))
                except Exception as e:
                    self.logger.warning("Failed to list tools: %s", e)
            
            # List resources
            resources = []
            if hasattr(meta.capabilities, 'resources') and meta.capabilities.resources:
                try:
                    resources_response = await self.session.list_resources()
                    resources = resources_response.resources
                    self.logger.info("Found %d resources", len(resources))
                    
                    # Read resource content for prompt injection detection
                    for resource in resources:
                        try:
                            if hasattr(resource, 'uri') and resource.uri:
                                resource_content = await self.session.read_resource(resource.uri)
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
            # Clean up on error
            await self.close()
            raise RuntimeError(f"Failed to connect to MCP server: {str(e)}")
    
    async def close(self) -> None:
        """Close the MCP client connection."""
        try:
            if self.session:
                await self.session.__aexit__(None, None, None)
                self.session = None
            if hasattr(self, 'read_write'):
                await self.client.__aexit__(None, None, None)
                self.read_write = None
        except Exception as e:
            self.logger.warning("Error during client cleanup: %s", e)
    
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
            # Convert MCP result to dictionary for JSON serialization
            if hasattr(result, 'model_dump'):
                return result.model_dump()
            elif hasattr(result, '__dict__'):
                return result.__dict__
            else:
                return str(result)
        except Exception as e:
            self.logger.error("Failed to call tool %s: %s", tool_name, str(e))
            raise
        
    async def read_resource(self, uri: str) -> Any:
        """Read a resource using the official MCP library."""
        if not self.session:
            raise RuntimeError("Not connected to server")
        
        try:
            result = await self.session.read_resource(uri)
            # Convert MCP result to dictionary for JSON serialization
            if hasattr(result, 'model_dump'):
                return result.model_dump()
            elif hasattr(result, '__dict__'):
                return result.__dict__
            else:
                return str(result)
        except Exception as e:
            self.logger.error("Failed to read resource %s: %s", uri, str(e))
            raise
    
    def get_tools(self) -> List[Dict[str, Any]]:
        """Get the list of tools."""
        if not self.tools:
            return []
        
        tools_list = []
        for tool in self.tools:
            try:
                tool_dict = tool.model_dump()
                # Convert AnyUrl objects to strings to avoid JSON serialization issues
                if 'uri' in tool_dict and tool_dict['uri']:
                    tool_dict['uri'] = str(tool_dict['uri'])
                tools_list.append(tool_dict)
            except Exception as e:
                self.logger.warning(f"Failed to serialize tool {getattr(tool, 'name', 'unknown')}: {str(e)}")
                # Fallback: create a basic dict with available attributes
                tool_dict = {
                    'name': getattr(tool, 'name', 'unknown'),
                    'description': getattr(tool, 'description', ''),
                    'inputSchema': getattr(tool, 'inputSchema', {})
                }
                tools_list.append(tool_dict)
        
        return tools_list
    
    def get_resources(self) -> List[Dict[str, Any]]:
        """Get the list of resources."""
        if not self.resources:
            return []
        
        resources_list = []
        for resource in self.resources:
            try:
                resource_dict = resource.model_dump()
                # Convert AnyUrl objects to strings to avoid JSON serialization issues
                if 'uri' in resource_dict and resource_dict['uri']:
                    resource_dict['uri'] = str(resource_dict['uri'])
                resources_list.append(resource_dict)
            except Exception as e:
                self.logger.warning(f"Failed to serialize resource {getattr(resource, 'name', 'unknown')}: {str(e)}")
                # Fallback: create a basic dict with available attributes
                resource_dict = {
                    'name': getattr(resource, 'name', 'unknown'),
                    'description': getattr(resource, 'description', ''),
                    'uri': str(getattr(resource, 'uri', '')) if getattr(resource, 'uri', None) else ''
                }
                resources_list.append(resource_dict)
        
        return resources_list
