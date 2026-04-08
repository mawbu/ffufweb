from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

class TestServerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Baseline normal response
        if self.path in ['/', '/home', '/about', '/contact']:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Welcome to the site</h1><p>Normal page content.</p></body></html>")
            return
            
        # Vulnerability 1: API Key / Secret disclosure
        if self.path == '/api/config':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"version": "1.0", "api_key": "AKIA123X56789YYZ"}')
            return

        # Vulnerability 2: Stack Trace (Exception)
        if self.path == '/test_error':
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Traceback (most recent call last):\n  File "server.py", line 42, in process_data\n    data = 1 / 0\nZeroDivisionError: division by zero')
            return

        # Vulnerability 3: Debug file with password
        if self.path == '/.env' or self.path == '/config.inc':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASSWORD=supersecret')
            return

        # Catch-all: Normal 404
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>404 Not Found</h1></body></html>")

    def log_message(self, format, *args):
        # Tắt bớt log quá ồn
        pass

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9090
    server = HTTPServer(('127.0.0.1', port), TestServerHandler)
    print(f"Test server running on port {port}...")
    server.serve_forever()
