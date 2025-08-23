from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class SimpleToolsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/tools/list':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            with open('tests/tools_list.json', 'r') as f:
                self.wfile.write(f.read().encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')

def run(server_class=HTTPServer, handler_class=SimpleToolsHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    run()
