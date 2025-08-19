from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import jwt
from datetime import datetime, timedelta
import secrets
import uuid

class JSONRPCError(Exception):
    def __init__(self, code, message, data=None):
        self.code = code
        self.message = message
        self.data = data

    def to_dict(self):
        error = {
            'code': self.code,
            'message': self.message
        }
        if self.data is not None:
            error['data'] = self.data
        return error

# Simple in-memory storage for tokens
TOKENS = {}

# Secret key for JWT
SECRET_KEY = secrets.token_hex(32)

class AuthRequestHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    def do_OPTIONS(self):
        self._set_headers(200)
    
    def do_POST(self):
        if self.path == '/login':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data)
                username = data.get('username')
                password = data.get('password')
                
                # Simple hardcoded credentials for testing
                if username == 'admin' and password == 'admin123':
                    # Generate JWT token
                    token = jwt.encode({
                        'username': username,
                        'exp': datetime.utcnow() + timedelta(hours=1)
                    }, SECRET_KEY, algorithm='HS256')
                    
                    # Store token
                    TOKENS[token] = username
                    
                    self._set_headers(200)
                    response = {
                        'status': 'success',
                        'token': token,
                        'expires_in': 3600
                    }
                    self.wfile.write(json.dumps(response).encode())
                else:
                    self._set_headers(401)
                    self.wfile.write(json.dumps({
                        'status': 'error',
                        'message': 'Invalid credentials'
                    }).encode())
            except Exception as e:
                self._set_headers(400)
                self.wfile.write(json.dumps({
                    'status': 'error',
                    'message': str(e)
                }).encode())
        else:
            self._set_headers(404)
            self.wfile.write(json.dumps({
                'status': 'error',
                'message': 'Not found'
            }).encode())
    
    def _handle_jsonrpc(self, data):
        try:
            print(f"\n=== Incoming Request ===")
            print(f"Headers: {dict(self.headers)}")
            print(f"Data: {data}")
            
            if not isinstance(data, dict):
                print("Error: Invalid JSON-RPC format")
                raise JSONRPCError(-32700, 'Parse error')
                
            method = data.get('method')
            request_id = data.get('id', str(uuid.uuid4()))
            
            # Check for authentication on all methods except initialize
            if method != 'initialize':
                auth_header = self.headers.get('Authorization')
                print(f"Auth Header: {auth_header}")
                
                if not auth_header or not auth_header.startswith('Bearer '):
                    print("Error: Missing or invalid Authorization header")
                    raise JSONRPCError(-32001, 'Unauthorized')
                
                token = auth_header.split(' ')[1]
                print(f"Token: {token}")
                print(f"Valid tokens: {list(TOKENS.keys())}")
                
                if token not in TOKENS:
                    print("Error: Invalid or expired token")
                    raise JSONRPCError(-32001, 'Invalid or expired token')
            
            if method == 'initialize':
                return {
                    'jsonrpc': '2.0',
                    'id': request_id,
                    'result': {
                        'serverInfo': {
                            'name': 'Test Auth Server',
                            'version': '1.0'
                        },
                        'capabilities': {}
                    }
                }
            elif method in ['tools/list', 'list_tools', 'tools.list', 'listTools']:
                print(f"[SERVER] Handling {method} request with ID: {request_id}")
                
                # Define the tools with proper schema
                tools = [
                    {
                        'name': 'file/read',
                        'description': 'Read a file from the server',
                        'parameters': {
                            'type': 'object',
                            'properties': {
                                'path': {'type': 'string'},
                                'encoding': {'type': 'string', 'default': 'utf-8'}
                            },
                            'required': ['path']
                        }
                    },
                    {
                        'name': 'system/exec',
                        'description': 'Execute a system command',
                        'parameters': {
                            'type': 'object',
                            'properties': {
                                'command': {'type': 'string'},
                                'args': {
                                    'type': 'array',
                                    'items': {'type': 'string'},
                                    'default': []
                                }
                            },
                            'required': ['command']
                        }
                    }
                ]
                
                # Return the response in the expected format
                response = {
                    'jsonrpc': '2.0',
                    'id': request_id,
                    'result': {
                        'tools': tools
                    }
                }
                print(f"[SERVER] Sending tools list response: {json.dumps(response, indent=2)}")
                return response
            else:
                raise JSONRPCError(-32601, 'Method not found')
                
        except JSONRPCError as e:
            return {
                'jsonrpc': '2.0',
                'id': data.get('id', None) if isinstance(data, dict) else None,
                'error': e.to_dict()
            }
        except Exception as e:
            return {
                'jsonrpc': '2.0',
                'id': data.get('id', None) if isinstance(data, dict) else None,
                'error': {
                    'code': -32603,
                    'message': 'Internal error',
                    'data': str(e)
                }
            }
    
    def do_GET(self):
        if self.path == '/tools/list':
            # This is for direct testing without MCP protocol
            auth_header = self.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                self._set_headers(401)
                self.wfile.write(json.dumps({
                    'status': 'error',
                    'message': 'Missing or invalid authorization token'
                }).encode())
                return
            
            token = auth_header.split(' ')[1]
            if token not in TOKENS:
                self._set_headers(401)
                self.wfile.write(json.dumps({
                    'status': 'error',
                    'message': 'Invalid or expired token'
                }).encode())
                return
            
            tools = [
                {
                    'name': 'file/read',
                    'description': 'Read a file from the server',
                    'parameters': {
                        'type': 'object',
                        'properties': {
                            'path': {'type': 'string'},
                            'encoding': {'type': 'string', 'default': 'utf-8'}
                        },
                        'required': ['path']
                    }
                },
                {
                    'name': 'system/exec',
                    'description': 'Execute a system command',
                    'parameters': {
                        'type': 'object',
                        'properties': {
                            'command': {'type': 'string'},
                            'args': {'type': 'array', 'items': {'type': 'string'}}
                        },
                        'required': ['command']
                    }
                }
            ]
            self._set_headers(200)
            self.wfile.write(json.dumps({'tools': tools}).encode())
            
    def do_POST(self):
        
        if self.path == '/login':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                data = json.loads(post_data)
                username = data.get('username')
                password = data.get('password')
                
                # Simple hardcoded credentials for testing
                if username == 'admin' and password == 'admin123':
                    # Generate JWT token
                    token = jwt.encode({
                        'username': username,
                        'exp': datetime.utcnow() + timedelta(hours=1)
                    }, SECRET_KEY, algorithm='HS256')
                    
                    # Store token
                    TOKENS[token] = username
                    
                    self._set_headers(200)
                    response = {
                        'status': 'success',
                        'token': token,
                        'expires_in': 3600
                    }
                    self.wfile.write(json.dumps(response).encode())
                else:
                    self._set_headers(401)
                    self.wfile.write(json.dumps({
                        'status': 'error',
                        'message': 'Invalid credentials'
                    }).encode())
            except Exception as e:
                self._set_headers(400)
                self.wfile.write(json.dumps({
                    'status': 'error',
                    'message': str(e)
                }).encode())
        else:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                try:
                    post_data = self.rfile.read(content_length)
                    data = json.loads(post_data)
                    response = self._handle_jsonrpc(data)
                    self._set_headers(200)
                    self.wfile.write(json.dumps(response).encode())
                except json.JSONDecodeError:
                    self._set_headers(400)
                    self.wfile.write(json.dumps({
                        'jsonrpc': '2.0',
                        'error': {
                            'code': -32700,
                            'message': 'Parse error'
                        }
                    }).encode())
            else:
                self._set_headers(400)
                self.wfile.write(json.dumps({
                    'jsonrpc': '2.0',
                    'error': {
                        'code': -32600,
                        'message': 'Invalid Request'
                    }
                }).encode())

def run(server_class=HTTPServer, handler_class=AuthRequestHandler, port=8080):
    import socket
    import sys
    
    server_address = ('', port)
    
    # Try to bind to the port, handle if it's already in use
    max_retries = 5
    for attempt in range(max_retries):
        current_port = port + attempt
        server_address = ('', current_port)
        try:
            httpd = server_class(server_address, handler_class)
            print(f"Starting auth server on port {current_port}...")
            print(f"Login URL: http://localhost:{current_port}/login")
            print(f"MCP endpoint: http://localhost:{current_port}")
            httpd.serve_forever()
            break
        except OSError as e:
            if "Address already in use" in str(e):
                print(f"Port {current_port} is in use, trying next port...")
                if attempt == max_retries - 1:
                    print(f"Failed to start server after {max_retries} attempts. Please check for other running instances.")
                    sys.exit(1)
                continue
            else:
                print(f"Error starting server: {e}")
                sys.exit(1)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run the test auth server')
    parser.add_argument('--port', type=int, default=8080, help='Port to run the server on')
    args = parser.parse_args()
    run(port=args.port)
