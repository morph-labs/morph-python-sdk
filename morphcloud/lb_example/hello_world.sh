#!/bin/bash
# setup_hello_service.sh
# This script sets up a minimal "Hello World" HTTP service on port 9007.
# The service replies to any POST request with a JSON payload: {"message": "Hello World"}
#
# Intended for use on a morphvm-minimal image.
#
# Usage:
#   chmod +x setup_hello_service.sh
#   ./setup_hello_service.sh

# Ensure Python 3 is installed.
if ! command -v python3 &> /dev/null; then
    echo "python3 is required but not installed. Trying to install."
    apt update --yes && apt install python3.11 --yes && apt install python3.11-venv --yes
  exit 1
fi

# Create a directory to hold the service script and logs.
SERVICE_DIR="/opt/hello_service"
mkdir -p "${SERVICE_DIR}"

# Write the Python HTTP service code.
cat > "${SERVICE_DIR}/hello_service.py" << 'EOF'
#!/usr/bin/env python3
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class HelloHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read incoming request data (if any)
        content_length = int(self.headers.get('Content-Length', 0))
        _ = self.rfile.read(content_length)
        # Send response status code and headers
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        # Respond with a JSON "Hello World" message
        response = {"message": "Hello World"}
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress default logging to keep the output clean.
        return

def run():
    server_address = ('', 9007)
    httpd = HTTPServer(server_address, HelloHandler)
    print("Hello World HTTP service is running on port 9007...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
EOF

# Make the service script executable.
chmod +x "${SERVICE_DIR}/hello_service.py"

# Start the service in the background.
# The output is redirected to a log file.
nohup "${SERVICE_DIR}/hello_service.py" > "${SERVICE_DIR}/hello_service.log" 2>&1 &

echo "Hello World HTTP service has been started on port 9007."
