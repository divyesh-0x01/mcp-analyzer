# mcp_analyzer/mcp_client.py
import asyncio
import json
import aiohttp
import uuid

class MCPClient:
    def __init__(self, transport="stdio", reader=None, writer=None, url=None):
        self.transport = transport
        self.reader = reader
        self.writer = writer
        self.url = url
        self.session = None  # for SSE/HTTP

    async def connect(self):
        if self.transport in ("http", "sse"):
            self.session = aiohttp.ClientSession()

    async def close(self):
        if self.session:
            await self.session.close()

    async def call_tool(self, name: str, args: dict):
        request_id = str(uuid.uuid4())
        req = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
        }

        if self.transport == "stdio":
            self.writer.write((json.dumps(req) + "\n").encode())
            await self.writer.drain()
            line = await self.reader.readline()
            return json.loads(line.decode())

        elif self.transport == "http":
            async with self.session.post(self.url, json=req) as resp:
                return await resp.json()

        elif self.transport == "sse":
            # placeholder for later SSE event streaming
            raise NotImplementedError("SSE transport not yet supported")

        else:
            raise ValueError(f"Unsupported transport: {self.transport}")
