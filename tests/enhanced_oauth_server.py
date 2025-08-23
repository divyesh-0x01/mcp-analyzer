from aiohttp import web
import json
import jwt
import time
import os

JWT_SECRET = "super-secret-demo-key-change-me"
JWT_ALG = "HS256"
EXPECTED_AUD = "mcp-resource"
TOKEN_EXPIRY = 3600  # 1 hour

def generate_token(client_id: str, scope: str = "mcp.read mcp.write") -> str:
    """Generate a JWT token for the given client."""
    now = int(time.time())
    payload = {
        "iss": "mcp-oauth-server",
        "sub": client_id,
        "aud": EXPECTED_AUD,
        "iat": now,
        "exp": now + TOKEN_EXPIRY,
        "scope": scope,
        "client_id": client_id
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

async def tools_list_get(request):
    """Handle tools list request."""
    return web.json_response({"tools": [
        {"name": "file/read", "description": "Read a file"},
        {"name": "system/exec", "description": "Execute a system command"}
    ]})

async def jsonrpc_handler(request):
    """Handle JSON-RPC requests."""
    try:
        # Log incoming request
        print("\n=== Incoming Request ===")
        print(f"Method: {request.method}")
        print("Headers:", dict(request.headers))
        
        # Parse JSON data
        data = await request.json()
        print("Request Body:", json.dumps(data, indent=2))
        
        method = data.get('method', '')
        request_id = data.get('id')
        
        print(f"\nProcessing method: {method}, ID: {request_id}")
        
        # Check for listTools method (used by some clients)
        if method == 'listTools' or method == 'tools/list':
            return web.json_response({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"tools": [
                    {"name": "file/read", "description": "Read a file"},
                    {"name": "system/exec", "description": "Execute a system command"}
                ]}
            })
            
        # Handle file/read method
        if method == 'file/read':
            # Get the path parameter (trying different parameter names)
            params = data.get('params', {})
            path = params.get('path') or params.get('file') or params.get('filename', '')
            
            # Simulate reading a file
            if path == '/etc/passwd':
                content = """root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin"""
                return web.json_response({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": content
                })
            else:
                return web.json_response({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": f"File not found: {path}"}
                })
                
        # Handle system/exec method
        elif method == 'system/exec':
            # Get the command parameter (trying different parameter names)
            params = data.get('params', {})
            command = params.get('command') or params.get('cmd') or params.get('exec', '')
            
            # Simulate command execution
            if 'id' in command.lower() or 'whoami' in command.lower():
                output = "uid=1000(user) gid=1000(user) groups=1000(user)"
            else:
                output = f"Executed: {command}\nExit code: 0"
                
            return web.json_response({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": output
            })
            
        # Unknown method
        else:
            return web.json_response({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            })
    except Exception as e:
        return web.json_response({
            "jsonrpc": "2.0",
            "id": data.get('id') if 'data' in locals() else None,
            "error": {"code": -32603, "message": str(e)}
        })

async def token_handler(request: web.Request) -> web.Response:
    """Handle OAuth2 token requests."""
    try:
        # Check for basic auth
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return web.Response(
                status=401,
                text=json.dumps({"error": "invalid_client", "error_description": "Client authentication failed"}),
                content_type="application/json",
                headers={"WWW-Authenticate": 'Basic realm="MCPServer"'}
            )
        
        # Verify credentials (demo:client-secret)
        import base64
        auth_decoded = base64.b64decode(auth[6:]).decode("utf-8")
        username, password = auth_decoded.split(":", 1)
        
        if username != "demo-client" or password != "demo-secret":
            return web.Response(
                status=401,
                text=json.dumps({"error": "invalid_client", "error_description": "Invalid client credentials"}),
                content_type="application/json"
            )
        
        # Generate token
        token = generate_token(username)
        
        return web.json_response({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": TOKEN_EXPIRY,
            "scope": "mcp.read mcp.write"
        }, status=200)
    
    except Exception as e:
        return web.Response(
            status=400,
            text=json.dumps({"error": "invalid_request", "error_description": str(e)}),
            content_type="application/json"
        )

def log_request(request, data=None):
    """Log request details to a file."""
    with open('server_debug.log', 'a') as f:
        f.write(f"\n=== {time.ctime()} ===\n")
        f.write(f"{request.method} {request.path} {request.version}\n")
        f.write("Headers:\n")
        for k, v in request.headers.items():
            f.write(f"  {k}: {v}\n")
        if data:
            f.write("\nBody:\n")
            f.write(json.dumps(data, indent=2) + "\n")

def create_app():
    # Clear previous log file
    with open('server_debug.log', 'w') as f:
        f.write("MCP Test Server Debug Log\n" + "="*50 + "\n")
    
    app = web.Application()
    
    # Add middleware to log all requests
    @web.middleware
    async def log_middleware(request, handler):
        try:
            if request.body_exists:
                data = await request.json()
                log_request(request, data)
            else:
                log_request(request)
        except Exception as e:
            log_request(request, {"error": f"Failed to log request: {str(e)}"})
        return await handler(request)
    
    app.middlewares.append(log_middleware)
    
    # Add routes
    app.router.add_post("/token", token_handler)
    app.router.add_get("/tools/list", tools_list_get)
    app.router.add_post("/", jsonrpc_handler)
    
    # Add a catch-all route for debugging
    async def catch_all(request):
        return web.Response(text=f"Path not found: {request.path}", status=404)
    
    app.router.add_route('*', '/{tail:.*}', catch_all)
    
    return app

if __name__ == "__main__":
    app = create_app()
    print("Starting enhanced MCP OAuth server on http://localhost:9000")
    print("Available endpoints:")
    print("  GET  /tools/list - List available tools")
    print("  POST /token - Get OAuth token (Basic auth: demo-client:demo-secret)")
    print("  POST / - JSON-RPC endpoint")
    print("\nExample JSON-RPC request:")
    print('''{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "file/read",
  "params": {"path": "/etc/passwd"}
}''')
    web.run_app(app, host="0.0.0.0", port=9000)
