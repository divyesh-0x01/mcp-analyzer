# Add these imports at the top
import datetime
from aiohttp import web
import jwt
import json
import time
from typing import Dict, Any

# Add these constants at the top
JWT_SECRET = "super-secret-demo-key-change-me"
JWT_ALG = "HS256"
EXPECTED_AUD = "mcp-resource"
TOKEN_EXPIRY = 3600  # 1 hour

# Add this function to handle token generation
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

# Add tools list handler
async def tools_list_get(request):
    """Handle tools list request."""
    return web.json_response({"tools": [
        {"name": "file/read", "description": "Read a file"},
        {"name": "system/exec", "description": "Execute a system command"}
    ]})

# Add JSON-RPC handler
async def jsonrpc_handler(request):
    """Handle JSON-RPC requests."""
    try:
        data = await request.json()
        return web.json_response({"jsonrpc": "2.0", "id": data.get('id'), "result": {"tools": [
            {"name": "file/read", "description": "Read a file"},
            {"name": "system/exec", "description": "Execute a system command"}
        ]}})
    except Exception as e:
        return web.json_response({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(e)}})

# Add this handler for the /token endpoint
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
        })
    
    except Exception as e:
        return web.Response(
            status=400,
            text=json.dumps({"error": "invalid_request", "error_description": str(e)}),
            content_type="application/json"
        )

# Update the create_app function
def create_app():
    app = web.Application()
    app.router.add_post("/token", token_handler)
    app.router.add_get("/tools/list", tools_list_get)
    app.router.add_post("/", jsonrpc_handler)
    app.router.add_post("/tools/list", lambda r: web.json_response({"tools": TOOLS}))
    return app

if __name__ == "__main__":
    app = create_app()
    print("Starting MCP OAuth server on http://localhost:9000")
    web.run_app(app, host="0.0.0.0", port=9000)