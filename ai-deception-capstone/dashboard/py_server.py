import http.server
import socketserver
import os

PORT = 5000
# Change directory to where your dashboard files are located
# If your index.html is in a folder named 'dashboard', use that:
WEB_DIR = os.path.join(os.path.dirname(__file__), 'dashboard')

if os.path.exists(WEB_DIR):
    os.chdir(WEB_DIR)

Handler = http.server.SimpleHTTPRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Serving AI Deception Dashboard at http://localhost:{PORT}")
    httpd.serve_forever()