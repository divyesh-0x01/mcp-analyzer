from aiohttp import web
import asyncio
import json
import logging
import uuid
from urllib.parse import parse_qs

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('sse_server')

# In-memory storage for tools
tools = [
    {"name": "get_user_info", "description": "Get information about a user"},
    {"name": "list_users", "description": "List all available users"},
    {"name": "get_server_status", "description": "Get current server status"}
]

# Dictionary to store active SSE connections
active_connections = {}

# Simulated user database
USERS = {
    "user1": "Regular user with basic access",
    "user2": "Project manager with elevated access",
    "admin": "System administrator with full access"
}

# Simulated notes database
NOTES = {
    "user1": "Meeting notes from yesterday's call",
    "user2": "Remember to finish the project proposal",
    "admin": "Reminder: Update all system passwords next week"
}

# System credentials
CREDENTIALS = """
SYSTEM CREDENTIALS
------------------
Admin Username: admin_user
Admin Password: super_secret_password123
API Key: sk-a1b2c3d4e5f6g7h8i9j0
Database Connection String: postgresql://dbuser:dbpass@localhost/production
"""

async def handle_list_tools(request_id):
    """Handle list_tools JSON-RPC request."""
    logger.info(f"[DEBUG] Handling list_tools request (ID: {request_id})")
    logger.info(f"[DEBUG] Available tools: {tools}")
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "tools": tools
        }
    }

async def handle_echo(request_id, params):
    """Handle echo command for testing."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "message": f"Echo: {params.get('message', '')}"
        }
    }

async def handle_get_user_info(request_id, params):
    """Handle get_user_info tool call."""
    username = params.get('username', '')
    if username in USERS:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "information": f"User information for {username}: {USERS[username]}"
            }
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": 404,
                "message": f"User not found: {username}"
            }
        }

async def handle_list_users(request_id):
    """Handle list_users tool call."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "users": list(USERS.keys())
        }
    }

async def handle_get_server_status(request_id):
    """Handle get_server_status tool call."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "status": "running",
            "version": "1.0.0",
            "uptime": "1h 23m"
        }
    }

async def handle_get_credentials():
    """Handle internal credentials request."""
    return CREDENTIALS

async def handle_get_user_notes(user_id):
    """Handle get_user_notes request."""
    if user_id in NOTES:
        return f"Notes for {user_id}: {NOTES[user_id]}"
    else:
        return f"No notes found for user: {user_id}"

async def sse_handler(request):
    """Handle SSE connections and process JSON-RPC requests."""
    # Parse query parameters
    query = request.query
    request_data = None
    
    # Check for JSON-RPC request in query parameters
    if 'request' in query:
        try:
            request_data = json.loads(query['request'])
            logger.info(f"Received JSON-RPC request: {request_data}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in request: {e}")
            return web.json_response({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error: Invalid JSON"}
            }, status=400)
    
    # Set up SSE response
    response = web.StreamResponse()
    response.headers['Content-Type'] = 'text/event-stream'
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['Access-Control-Allow-Origin'] = '*'
    await response.prepare(request)
    
    # Generate a unique ID for this connection
    client_id = str(uuid.uuid4())
    active_connections[client_id] = response
    logger.info(f"New SSE connection: {client_id}")
    
    try:
        # If we have a request, process it
        if request_data:
            await process_jsonrpc_request(response, request_data)
        
        # Keep the connection open
        while True:
            await asyncio.sleep(10)  # Keep connection alive
            await response.write(f"data: {{\"type\":\"ping\"}}\n\n".encode('utf-8'))
            await response.drain()
    except (asyncio.CancelledError, ConnectionResetError):
        logger.info(f"SSE connection closed: {client_id}")
    except Exception as e:
        logger.error(f"Error in SSE handler: {e}")
    finally:
        # Clean up
        active_connections.pop(client_id, None)
        await response.write_eof()
    
    return response

async def process_jsonrpc_request(stream, request_data):
    """Process a JSON-RPC request and send the response."""
    logger.info(f"[DEBUG] Received request: {json.dumps(request_data, indent=2)}")
    try:
        # Extract request ID and method
        request_id = request_data.get('id')
        method = request_data.get('method')
        params = request_data.get('params', {})
        logger.info(f"[DEBUG] Processing method: {method} (ID: {request_id})")
        logger.info(f"[DEBUG] Params: {params}")
        
        # Route the request to the appropriate handler
        if method == 'list_tools':
            response = await handle_list_tools(request_id)
            logger.info(f"[DEBUG] List tools response: {json.dumps(response, indent=2)}")
        elif method == 'echo':
            response = await handle_echo(request_id, params)
        elif method == 'get_user_info':
            response = await handle_get_user_info(request_id, params)
        elif method == 'list_users':
            response = await handle_list_users(request_id)
        elif method == 'get_server_status':
            response = await handle_get_server_status(request_id)
        else:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
        
        # Send the response
        logger.info(f"[DEBUG] Sending response: {json.dumps(response, indent=2)}")
        response_str = f"data: {json.dumps(response)}\n\n"
        await stream.write(response_str.encode('utf-8'))
        await stream.drain()
        logger.info("[DEBUG] Response sent successfully")
        
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        error_response = {
            "jsonrpc": "2.0",
            "id": request_data.get('id') if isinstance(request_data, dict) else None,
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        }
        await stream.write(f"data: {json.dumps(error_response)}\n\n".encode('utf-8'))
        await stream.drain()

# Set up CORS middleware
@web.middleware
async def cors_middleware(request, handler):
    response = await handler(request)
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

# Create application with CORS middleware
app = web.Application(middlewares=[cors_middleware])
app.router.add_get('/sse', sse_handler)
app.router.add_options('/sse', lambda _: web.Response(status=204))

# Add API endpoints
app.router.add_get('/api/credentials', lambda _: web.Response(text=CREDENTIALS))
app.router.add_get('/api/notes/{user_id}', lambda request: 
    web.Response(text=asyncio.get_event_loop().run_until_complete(
        handle_get_user_notes(request.match_info['user_id'])
    ))
)

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Start the server
    web.run_app(app, host='0.0.0.0', port=9001)
