import asyncio, json, os, sys
from mcp_analyzer.rpc import send_jsonrpc, recv_json_until, next_id

STDIO_CMD = [
    "npx", "-y", "github:divyesh-0x01/mcp-minimal"
]

async def main():
    proc = await asyncio.create_subprocess_exec(
        *STDIO_CMD,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=os.environ.copy(),
    )
    reader = proc.stdout
    writer = proc.stdin

    req_id = next_id()
    await send_jsonrpc(writer, {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "tools/list",
        "params": {}
    })
    result = await recv_json_until(reader, req_id, timeout=5.0)
    # Normalize tools
    tools = []
    if isinstance(result, dict):
        res = result.get("result", result)
        if isinstance(res, dict) and "tools" in res:
            tools = res.get("tools", [])
        elif isinstance(res, list):
            tools = res

    for t in tools:
        name = t.get("name") or t.get("id") or t.get("tool")
        if name == "add_numbers":
            print(json.dumps(t, indent=2))
            break

    try:
        proc.terminate()
    except ProcessLookupError:
        pass

if __name__ == "__main__":
    asyncio.run(main())


