import http.server
import socketserver
import json
import os

PORT = 3000
ROOT = os.path.join(os.path.dirname(__file__), 'public')
ALERTS_FILE = os.path.join(os.path.dirname(__file__), 'data', 'alerts.json')

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def do_GET(self):
        if self.path.startswith('/api/alerts'):
            try:
                with open(ALERTS_FILE, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
        else:
            return super().do_GET()

if __name__ == '__main__':
    with socketserver.TCPServer(('', PORT), Handler) as httpd:
        print(f"Serving dashboard at http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print('Server stopped')
